"""User accounts, bearer tokens and role checks.

Passwords are scrypt-hashed (standard library), tokens are random and stored as SHA-256 hashes.
The shared GOLEK_API_TOKEN keeps working and acts as an admin, so scripts and older deployments
are unaffected.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Role, User, UserToken

ROLE_RANK = {Role.viewer: 0, Role.analyst: 1, Role.admin: 2}
SCRYPT = {"n": 2**14, "r": 8, "p": 1}
TOKEN_MAX_AGE = timedelta(days=30)
LOCKOUT_FAILURES = 10
LOCKOUT_WINDOW = timedelta(minutes=15)
# shortcut: failed-login memory lives in this process; fine for the single API container Compose
# runs, move it to the database if the API ever runs as several replicas
_failed_logins: dict[str, list[datetime]] = {}
# Verified when the user does not exist, so a login attempt takes the same time either way.
_DUMMY_HASH = None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), **SCRYPT)
        return hmac.compare_digest(candidate, bytes.fromhex(digest))
    except ValueError:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(db: Session, username: str, password: str, role: Role) -> User:
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    global _DUMMY_HASH
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        _DUMMY_HASH = _DUMMY_HASH or hash_password("dummy-password")
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


def locked_until(username: str) -> datetime | None:
    """When the username is locked after too many recent failed logins, else None."""
    now = datetime.now(UTC)
    recent = [t for t in _failed_logins.get(username, []) if now - t < LOCKOUT_WINDOW]
    if recent:
        _failed_logins[username] = recent
    else:
        _failed_logins.pop(username, None)
    if len(recent) >= LOCKOUT_FAILURES:
        return recent[-1] + LOCKOUT_WINDOW
    return None


def record_login_failure(username: str) -> None:
    if len(_failed_logins) > 10_000:  # a spray of made-up usernames must not grow memory forever
        for name in list(_failed_logins):
            locked_until(name)
    _failed_logins.setdefault(username, []).append(datetime.now(UTC))


def clear_login_failures(username: str) -> None:
    _failed_logins.pop(username, None)


def _as_utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes, PostgreSQL aware ones.
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def issue_token(db: Session, user: User) -> str:
    now = datetime.now(UTC)
    db.query(UserToken).filter(UserToken.created_at < now - TOKEN_MAX_AGE).delete()
    token = secrets.token_urlsafe(32)
    db.add(UserToken(user_id=user.id, token_hash=token_hash(token), created_at=now))
    db.commit()
    return token


def revoke_token(db: Session, digest: str) -> None:
    db.query(UserToken).filter(UserToken.token_hash == digest).delete()
    db.commit()


def bootstrap_admin(db: Session) -> User | None:
    """Create the first admin from GOLEK_ADMIN_PASSWORD when the users table is empty."""
    if not settings.golek_admin_password or db.query(User).first() is not None:
        return None
    return create_user(db, settings.golek_admin_username, settings.golek_admin_password, Role.admin)


@dataclass(frozen=True)
class Principal:
    username: str
    role: Role
    user_id: int | None = None
    token_hash: str | None = None


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Invalid or missing API token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db),
) -> Principal:
    if credentials is None:
        raise _unauthorized()
    token = credentials.credentials
    # Compare bytes: compare_digest raises TypeError on non-ASCII str.
    if secrets.compare_digest(token.encode(), settings.golek_api_token.encode()):
        return Principal(username="api-token", role=Role.admin)
    digest = token_hash(token)
    row = db.query(UserToken).filter(UserToken.token_hash == digest).first()
    if row is None:
        raise _unauthorized()
    if datetime.now(UTC) - _as_utc(row.created_at) > TOKEN_MAX_AGE:
        revoke_token(db, digest)
        raise _unauthorized()
    return Principal(
        username=row.user.username, role=row.user.role, user_id=row.user.id, token_hash=digest
    )


def require_role(minimum: Role):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if ROLE_RANK[principal.role] < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail=f"Requires the {minimum.value} role")
        return principal

    return dependency

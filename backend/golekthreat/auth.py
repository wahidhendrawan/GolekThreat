"""User accounts, bearer tokens and role checks.

Passwords are scrypt-hashed (standard library), tokens are random and stored as SHA-256 hashes.
The shared GOLEK_API_TOKEN keeps working and acts as an admin, so scripts and older deployments
are unaffected.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Role, User, UserToken

ROLE_RANK = {Role.viewer: 0, Role.analyst: 1, Role.admin: 2}
SCRYPT = {"n": 2**14, "r": 8, "p": 1}
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


def issue_token(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(UserToken(user_id=user.id, token_hash=token_hash(token), created_at=datetime.now(UTC)))
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
    return Principal(
        username=row.user.username, role=row.user.role, user_id=row.user.id, token_hash=digest
    )


def require_role(minimum: Role):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if ROLE_RANK[principal.role] < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail=f"Requires the {minimum.value} role")
        return principal

    return dependency

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Required: Settings() fails at import so the API never starts unauthenticated.
    golek_api_token: str = Field(min_length=16)
    # First admin account, created once when the users table is empty.
    golek_admin_username: str = Field(default="admin", min_length=3, max_length=80)
    golek_admin_password: str | None = Field(default=None, min_length=12)

    @field_validator("golek_admin_password", mode="before")
    @classmethod
    def _empty_password_means_unset(cls, value: object) -> object:
        # Compose passes the variable through even when .env leaves it blank.
        return None if value == "" else value

    database_url: str = "sqlite:///./golekthreat.db"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()

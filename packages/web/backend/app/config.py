"""Application settings with environment validation."""

from pydantic_settings import BaseSettings
from pydantic import model_validator


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://opentools:changeme@localhost:5432/opentools"
    secret_key: str = "change-me-in-development"
    environment: str = "development"
    allowed_origins: str = "http://localhost:5173"
    log_level: str = "info"

    @model_validator(mode="after")
    def validate_production_secret(self):
        if self.environment == "production" and "change" in self.secret_key.lower():
            raise ValueError("SECRET_KEY must be changed for production deployment")
        return self

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()

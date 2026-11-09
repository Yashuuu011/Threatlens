import os
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "ThreatLens"
    APP_ENV: str = "development"
    APP_PORT: int = 8000
    LOG_LEVEL: str = "INFO"

    # PostgreSQL configuration (primary database)
    POSTGRES_USER: str = "threatlens"
    POSTGRES_PASSWORD: str = "threatlens_secure_pwd"
    POSTGRES_DB: str = "threatlens_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    DATABASE_URL: str = (
        "postgresql+psycopg://threatlens:threatlens_secure_pwd@localhost:5432/threatlens_db"
    )
    ALLOW_SQLITE_FALLBACK: bool = True

    # JWT & Authentication
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # Initial Users
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_EMAIL: str = "admin@threatlens.local"
    INITIAL_ADMIN_PASSWORD: str = "ThreatLens!Admin2026"
    INITIAL_ANALYST_USERNAME: str = "analyst"
    INITIAL_ANALYST_EMAIL: str = "analyst@threatlens.local"
    INITIAL_ANALYST_PASSWORD: str = "ThreatLens!Analyst2026"

    # CORS & Rate Limiting
    CORS_ORIGINS: str = (
        "http://localhost:5173,http://localhost:3000,http://localhost:80,"
        "http://127.0.0.1:5173,http://127.0.0.1:3000"
    )
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 30
    RATE_LIMIT_INGEST_PER_MINUTE: int = 1200
    RATE_LIMIT_INTEL_PER_MINUTE: int = 120
    RATE_LIMIT_EXPORT_PER_MINUTE: int = 60
    RATE_LIMIT_API_PER_MINUTE: int = 1500

    # External Threat Intelligence Providers (optional)
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=(
            str(Path(__file__).resolve().parents[3] / ".env"),
            str(Path(__file__).resolve().parents[2] / ".env"),
            ".env",
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()


"""
PhishShield Backend Configuration
Reads settings from environment variables / .env file via pydantic-settings.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    APP_ENV: str = "development"
    JWT_SECRET_KEY: Optional[str] = None

    # Database
    DATABASE_URL: str = "sqlite:///./data/phishshield.db"

    # CORS
    FRONTEND_ORIGIN: str = "http://localhost:5173"

    # File upload limits
    MAX_APK_MB: int = 100
    MAX_IMAGE_MB: int = 10

    # Privacy / retention
    RETAIN_UPLOADS: bool = False
    STORE_FULL_SMS_TEXT: bool = False
    STORE_THUMBNAILS: bool = False

    # External reputation lookups
    ENABLE_EXTERNAL_LOOKUPS: bool = False
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    URLHAUS_AUTH_KEY: Optional[str] = None
    PHISHTANK_APP_KEY: Optional[str] = None
    OPENPHISH_FEED_URL: Optional[str] = None

    # Feed freshness
    FEED_MAX_AGE_HOURS: int = 24

    # Timeouts
    REPUTATION_TIMEOUT_SECONDS: int = 4

    # OCR
    TESSERACT_CMD: Optional[str] = None
    OCR_LANGS: str = "eng+hin"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 30

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/phishshield.log"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV.lower() == "development"

    @property
    def max_apk_bytes(self) -> int:
        return self.MAX_APK_MB * 1024 * 1024

    @property
    def max_image_bytes(self) -> int:
        return self.MAX_IMAGE_MB * 1024 * 1024

    @property
    def google_safebrowsing_configured(self) -> bool:
        return bool(
            self.ENABLE_EXTERNAL_LOOKUPS
            and self.GOOGLE_SAFE_BROWSING_API_KEY
        )

    @property
    def urlhaus_configured(self) -> bool:
        return bool(self.ENABLE_EXTERNAL_LOOKUPS)

    @property
    def phishtank_configured(self) -> bool:
        return bool(
            self.ENABLE_EXTERNAL_LOOKUPS
            and self.PHISHTANK_APP_KEY
        )

    @property
    def openphish_configured(self) -> bool:
        return bool(
            self.ENABLE_EXTERNAL_LOOKUPS
            and self.OPENPHISH_FEED_URL
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()

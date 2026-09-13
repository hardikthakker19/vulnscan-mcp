"""Configuration management using Pydantic Settings."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    # NVD API
    nvd_api_key: str = Field(default="", alias="NVD_API_KEY")
    nvd_api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # CISA KEV
    kev_catalog_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        alias="KEV_CATALOG_URL",
    )

    # EPSS
    epss_api_base_url: str = "https://api.first.org/data/v1/epss"

    # MCP Server
    mcp_transport: str = Field(default="sse", alias="MCP_TRANSPORT")
    mcp_host: str = Field(default="0.0.0.0", alias="MCP_HOST")
    mcp_port: int = Field(default=8001, alias="MCP_PORT")

    # Database
    data_dir: str = Field(default="./data", alias="DATA_DIR")
    db_name: str = Field(default="vulnscan.db", alias="DB_NAME")

    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Sync intervals (hours)
    nvd_sync_interval_hours: int = Field(default=2, alias="NVD_SYNC_INTERVAL_HOURS")
    kev_sync_interval_hours: int = Field(default=12, alias="KEV_SYNC_INTERVAL_HOURS")
    epss_sync_interval_hours: int = Field(default=24, alias="EPSS_SYNC_INTERVAL_HOURS")

    @property
    def db_path(self) -> Path:
        """Full path to the SQLite database file."""
        return Path(self.data_dir) / self.db_name

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached application settings singleton."""
    return Settings()

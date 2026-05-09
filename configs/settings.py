"""
Configuration management for 0xFluxHunter framework.

Handles all environment-based settings and configuration initialization.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Provides type-safe configuration management.
    """

    # Framework Configuration
    framework_name: str = "0xFluxHunter"
    framework_version: str = "1.0.0"
    framework_env: str = "production"
    debug_mode: bool = False

    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4
    api_reload: bool = False

    # Claude API Configuration
    anthropic_api_key: str = ""
    claude_model: str = "claude-3-5-sonnet-20241022"
    claude_max_tokens: int = 4096
    claude_temperature: float = 0.3

    # Database Configuration
    database_url: str = "sqlite:///./0xfluxhunter.db"
    database_echo: bool = False

    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "logs/0xfluxhunter.log"

    # Security Configuration
    allow_destructive_payloads: bool = False
    enforce_ethical_boundaries: bool = True
    max_payload_size: int = 1000000  # 1MB

    # Tool Configuration
    timeout_seconds: int = 300
    max_retries: int = 3
    retry_delay_seconds: int = 5

    # Memory Configuration
    max_memory_items: int = 10000
    memory_persistence: bool = True
    memory_file: str = "data/memory.json"

    # Agent Configuration
    agent_timeout: int = 60
    agent_max_iterations: int = 10

    # Scan Configuration
    max_concurrent_scans: int = 3
    scan_result_retention_days: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings.
    Cached for performance - settings are loaded once at startup.

    Returns:
        Settings: Application configuration object
    """
    return Settings()


if __name__ == "__main__":
    settings = get_settings()
    print(f"Framework: {settings.framework_name} v{settings.framework_version}")
    print(f"Environment: {settings.framework_env}")
    print(f"Debug Mode: {settings.debug_mode}")
    print(f"API: {settings.api_host}:{settings.api_port}")
    print(f"Claude Model: {settings.claude_model}")
    print(f"Database: {settings.database_url}")

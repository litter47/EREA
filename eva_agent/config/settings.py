"""Global application settings loaded from environment variables.

All settings use the ``EVA_`` prefix. Configuration can be overridden
at runtime via environment variables without modifying any files.
No API keys or secrets are hard-coded in this module.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-level configuration loaded from the environment.

    Attributes:
        host: The interface address the API server binds to.
        port: The TCP port the API server listens on.
        log_level: Logging verbosity (e.g. DEBUG, INFO, WARNING).
        task_timeout: Maximum wall-clock seconds for a single task.
        docker_image: Docker image tag used for sandboxed execution.
        upload_dir: Temporary directory where uploaded exploit files
            are stored before execution.
    """

    model_config = SettingsConfigDict(
        env_prefix="EVA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    task_timeout: int = 300
    docker_image: str = "eva-runtime:latest"
    upload_dir: str = "/tmp/eva_uploads"

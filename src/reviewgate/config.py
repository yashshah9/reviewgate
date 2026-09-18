"""Application settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REVIEWGATE_", env_file=".env", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8092
    api_keys: str = "dev-key:demo-tenant"
    admin_keys: str = "admin-key"
    auth_driver: str = "api_key"
    audit_driver: str = "memory"
    queue_driver: str = "memory"
    redis_url: str = "redis://localhost:6379/0"
    postgres_dsn: str = "postgresql://localhost:5432/reviewgate"
    eval_min_pass_rate: float = 1.0
    # gate fails (block) when risk_score >= block_threshold
    block_threshold: float = 0.7
    warn_threshold: float = 0.35

    def api_key_map(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in self.api_keys.split(","):
            part = part.strip()
            if not part or ":" not in part:
                continue
            key, tenant = part.split(":", 1)
            out[key.strip()] = tenant.strip()
        return out

    def admin_key_list(self) -> list[str]:
        return [k.strip() for k in self.admin_keys.split(",") if k.strip()]

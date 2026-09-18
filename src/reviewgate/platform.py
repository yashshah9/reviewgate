"""platformkit wiring."""

from __future__ import annotations

from typing import Any

from platformkit import PlatformKit

from reviewgate.config import Settings


def build_kit(settings: Settings) -> PlatformKit:
    auth: dict[str, Any] = {"driver": settings.auth_driver}
    if settings.auth_driver == "api_key":
        auth["keys"] = settings.api_key_map()
        auth["admin_keys"] = settings.admin_key_list()

    audit: dict[str, Any] = {"driver": settings.audit_driver}
    if settings.audit_driver == "postgres":
        audit["dsn"] = settings.postgres_dsn

    queue: dict[str, Any] = {"driver": settings.queue_driver}
    if settings.queue_driver == "redis":
        queue["url"] = settings.redis_url

    return PlatformKit.from_config({"auth": auth, "audit": audit, "queue": queue})

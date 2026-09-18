"""Build ReviewStore with optional durable backend."""

from __future__ import annotations

from reviewgate.config import Settings
from reviewgate.persist import build_backend
from reviewgate.store import ReviewStore


def build_store(settings: Settings) -> ReviewStore:
    backend = build_backend(settings.store_driver, postgres_dsn=settings.postgres_dsn)
    store = ReviewStore(
        block_threshold=settings.block_threshold,
        warn_threshold=settings.warn_threshold,
        backend=backend,
    )
    store.load()
    return store

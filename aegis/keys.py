"""Secrets that must live outside the run files (audit MAC key, session key)."""

import os
import secrets
from functools import lru_cache

from . import config


@lru_cache(maxsize=None)
def load(name: str, override: str | None = None) -> bytes:
    """Return `override` if set, else a key generated once in SECRETS_DIR/<name>.key."""
    if override:
        return override.encode()
    path = config.SECRETS_DIR / f"{name}.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:  # best effort on Windows
            pass
    return path.read_text(encoding="utf-8").strip().encode()


def audit_key() -> bytes:
    return load("audit", config.AUDIT_KEY)


def auth_secret() -> bytes:
    return load("auth", config.AUTH_SECRET)

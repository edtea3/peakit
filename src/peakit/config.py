from __future__ import annotations

import os

from dotenv import load_dotenv


def _env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


class Settings:
    def __init__(self) -> None:
        load_dotenv()
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.supabase_url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
        self.supabase_key = (
            os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
            or os.getenv("SUPABASE_SECRETS_KEY", "").strip()
            or os.getenv("SUPABASE_PUBLISHED_KEY", "").strip()
        )
        self.supabase_timeout_s = int(os.getenv("SUPABASE_TIMEOUT_S", "20").strip() or "20")
        self.supabase_ssl_verify = _env_bool("SUPABASE_SSL_VERIFY", True)
        self.supabase_ca_bundle = os.getenv("SUPABASE_CA_BUNDLE", "").strip() or None
        self.auto_monitor_enabled = _env_bool("AUTO_MONITOR_ENABLED", False)
        self.auto_monitor_interval_min = int(os.getenv("AUTO_MONITOR_INTERVAL_MIN", "15").strip() or "15")

    def validate(self) -> None:
        if not self.telegram_bot_token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is empty in .env")
        if not self.supabase_url:
            raise RuntimeError("SUPABASE_URL is empty in .env")
        if not self.supabase_key:
            raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY (or fallback key) is empty in .env")

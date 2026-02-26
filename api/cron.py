from __future__ import annotations

import asyncio
import os

from flask import Flask, Response, jsonify, request

from src.peakit.config import Settings
from src.peakit.handlers import _refresh_and_detect_for_channel
from src.peakit.storage import StorageError, SupabaseStorage

app = Flask(__name__)


def _storage_from_settings(settings: Settings) -> SupabaseStorage:
    return SupabaseStorage(
        url=settings.supabase_url,
        key=settings.supabase_key,
        timeout_s=settings.supabase_timeout_s,
        ssl_verify=settings.supabase_ssl_verify,
        ca_bundle=settings.supabase_ca_bundle,
    )


def _is_cron_authorized() -> bool:
    expected = os.getenv("CRON_SECRET", "").strip()
    if not expected:
        return True
    auth = request.headers.get("Authorization", "").strip()
    return auth == f"Bearer {expected}"


async def _run_refresh(storage: SupabaseStorage) -> dict:
    channels = [c for c in storage.list_channels() if bool(c.get("is_active", True))]
    ok_count = 0
    fail_count = 0
    errors: list[str] = []

    for ch in channels:
        handle = str(ch.get("handle") or "")
        channel_id = int(ch.get("id"))
        ok, err = await _refresh_and_detect_for_channel(
            storage=storage,
            handle=handle,
            channel_id=channel_id,
        )
        if ok:
            ok_count += 1
        else:
            fail_count += 1
            if err:
                errors.append(err)

    return {
        "channels_total": len(channels),
        "ok": ok_count,
        "failed": fail_count,
        "errors": errors[:10],
    }


@app.route("/api/cron", methods=["GET"])
@app.route("/", methods=["GET"])
def cron_refresh() -> Response:
    if not _is_cron_authorized():
        return jsonify({"ok": False, "error": "forbidden"}), 403

    settings = Settings()
    settings.validate()
    storage = _storage_from_settings(settings)

    try:
        result = asyncio.run(_run_refresh(storage))
    except StorageError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    except Exception as exc:
        return jsonify({"ok": False, "error": f"unexpected: {exc}"}), 500

    return jsonify({"ok": True, **result}), 200

from __future__ import annotations

import asyncio
import os

from flask import Flask, Response, jsonify, request
from telegram import Update

from src.peakit.app import build_application
from src.peakit.config import Settings
from src.peakit.storage import SupabaseStorage

app = Flask(__name__)


def _storage_from_settings(settings: Settings) -> SupabaseStorage:
    return SupabaseStorage(
        url=settings.supabase_url,
        key=settings.supabase_key,
        timeout_s=settings.supabase_timeout_s,
        ssl_verify=settings.supabase_ssl_verify,
        ca_bundle=settings.supabase_ca_bundle,
    )


def _is_secret_valid() -> bool:
    expected = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
    if not expected:
        return True
    actual = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "").strip()
    return actual == expected


async def _process(payload: dict) -> None:
    settings = Settings()
    settings.validate()
    storage = _storage_from_settings(settings)
    application = build_application(settings=settings, storage=storage)
    await application.initialize()
    try:
        update = Update.de_json(payload, application.bot)
        if update is not None:
            await application.process_update(update)
    finally:
        await application.shutdown()


@app.route("/api/telegram", methods=["POST"])
@app.route("/", methods=["POST"])
def telegram_webhook() -> Response:
    if not _is_secret_valid():
        return jsonify({"ok": False, "error": "forbidden"}), 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "bad payload"}), 400

    asyncio.run(_process(payload))
    return jsonify({"ok": True}), 200

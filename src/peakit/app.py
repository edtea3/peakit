from __future__ import annotations

import logging

from telegram.error import TimedOut
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

from .config import Settings
from .handlers import (
    WAIT_ALERT_ACTION,
    WAIT_ALERT_CHANNELS,
    WAIT_ALERT_INTERVAL,
    WAIT_ALERT_SCORE,
    WAIT_ALERT_TARGET,
    WAIT_ALERT_TYPES,
    WAIT_ANALYTICS_PERIOD,
    WAIT_CHANNEL,
    WAIT_EXPORT_CHANNELS,
    WAIT_EXPORT_PERIOD,
    WAIT_EXPORT_TYPES,
    on_add_channel_click,
    on_alerts_action,
    on_alerts_channels,
    on_alerts_click,
    on_alerts_score,
    on_alerts_target,
    on_alerts_types,
    on_analytics_click,
    on_analytics_period,
    on_export_threats_channels_file,
    on_export_threats_channels_text,
    on_export_threats_click,
    on_export_threats_period,
    on_export_threats_types,
    on_channel_file,
    on_channel_input,
    on_list_channels,
    on_alerts_interval,
    register_auto_monitor_job,
    start,
)
from .storage import SupabaseStorage
from .ui import BTN_ADD_CHANNEL, BTN_ALERTS, BTN_ANALYTICS, BTN_EXPORT_THREATS, BTN_LIST_CHANNELS

logger = logging.getLogger(__name__)


async def _on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    if isinstance(context.error, TimedOut):
        logger.warning("Telegram timeout ignored: %s", context.error)
        return
    logger.exception("Unhandled bot error", exc_info=context.error)


def build_application(settings: Settings, storage: SupabaseStorage) -> Application:
    app = Application.builder().token(settings.telegram_bot_token).build()
    app.bot_data["storage"] = storage

    conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex(f"^{BTN_ADD_CHANNEL}$"), on_add_channel_click)],
        states={
            WAIT_CHANNEL: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_channel_input),
                MessageHandler(filters.Document.ALL, on_channel_file),
            ],
        },
        fallbacks=[CommandHandler("start", start)],
        per_chat=True,
        per_user=True,
    )

    export_conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex(f"^{BTN_EXPORT_THREATS}$"), on_export_threats_click)],
        states={
            WAIT_EXPORT_CHANNELS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_export_threats_channels_text),
                MessageHandler(filters.Document.ALL, on_export_threats_channels_file),
            ],
            WAIT_EXPORT_PERIOD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_export_threats_period),
            ],
            WAIT_EXPORT_TYPES: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_export_threats_types),
            ],
        },
        fallbacks=[CommandHandler("start", start)],
        per_chat=True,
        per_user=True,
    )

    analytics_conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex(f"^{BTN_ANALYTICS}$"), on_analytics_click)],
        states={
            WAIT_ANALYTICS_PERIOD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_analytics_period),
            ],
        },
        fallbacks=[CommandHandler("start", start)],
        per_chat=True,
        per_user=True,
    )

    alerts_conv = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex(f"^{BTN_ALERTS}$"), on_alerts_click)],
        states={
            WAIT_ALERT_ACTION: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_alerts_action),
            ],
            WAIT_ALERT_SCORE: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_alerts_score),
            ],
            WAIT_ALERT_TYPES: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_alerts_types),
            ],
            WAIT_ALERT_CHANNELS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_alerts_channels),
            ],
            WAIT_ALERT_TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_alerts_target),
            ],
            WAIT_ALERT_INTERVAL: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_alerts_interval),
            ],
        },
        fallbacks=[CommandHandler("start", start)],
        per_chat=True,
        per_user=True,
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Regex(f"^{BTN_LIST_CHANNELS}$"), on_list_channels))
    app.add_handler(conv)
    app.add_handler(export_conv)
    app.add_handler(analytics_conv)
    app.add_handler(alerts_conv)
    app.add_error_handler(_on_error)
    app.bot_data["auto_monitor_interval_min"] = settings.auto_monitor_interval_min
    return app


def _build_storage(settings: Settings) -> SupabaseStorage:
    return SupabaseStorage(
        url=settings.supabase_url,
        key=settings.supabase_key,
        timeout_s=settings.supabase_timeout_s,
        ssl_verify=settings.supabase_ssl_verify,
        ca_bundle=settings.supabase_ca_bundle,
    )


def run() -> None:
    settings = Settings()
    settings.validate()
    storage = _build_storage(settings)
    storage.sync_threat_categories()
    startup_interval = settings.auto_monitor_interval_min
    try:
        persisted_interval = storage.get_latest_auto_monitor_interval()
        if persisted_interval is not None:
            startup_interval = persisted_interval
    except Exception:
        pass
    app = build_application(settings=settings, storage=storage)
    if settings.auto_monitor_enabled and app.job_queue is not None:
        interval = max(1, startup_interval)
        register_auto_monitor_job(app, interval)
        logger.info("Auto monitor enabled: interval=%s min", interval)
    app.run_polling()

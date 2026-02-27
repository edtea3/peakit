from __future__ import annotations

from telegram import KeyboardButton, ReplyKeyboardMarkup

BTN_ADD_CHANNEL = "Добавить канал"
BTN_LIST_CHANNELS = "Выгрузить каналы мониторинга"
BTN_EXPORT_THREATS = "Выгрузить угрозы"
BTN_ANALYTICS = "Аналитика"
BTN_ALERTS = "Алерты"


def main_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton(BTN_ADD_CHANNEL)],
            [KeyboardButton(BTN_LIST_CHANNELS)],
            [KeyboardButton(BTN_EXPORT_THREATS)],
            [KeyboardButton(BTN_ANALYTICS)],
            [KeyboardButton(BTN_ALERTS)],
        ],
        resize_keyboard=True,
    )

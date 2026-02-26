from __future__ import annotations

from telegram import KeyboardButton, ReplyKeyboardMarkup

BTN_ADD_CHANNEL = "Добавить канал"
BTN_LIST_CHANNELS = "Выгрузить каналы мониторинга"
BTN_EXPORT_THREATS = "Выгрузить угрозы"
BTN_REFRESH_DATA = "Обновить данные"
BTN_ANALYTICS = "Аналитика"


def main_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton(BTN_ADD_CHANNEL)],
            [KeyboardButton(BTN_REFRESH_DATA)],
            [KeyboardButton(BTN_LIST_CHANNELS)],
            [KeyboardButton(BTN_EXPORT_THREATS)],
            [KeyboardButton(BTN_ANALYTICS)],
        ],
        resize_keyboard=True,
    )

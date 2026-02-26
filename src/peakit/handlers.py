from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from io import StringIO
import os
import re
from typing import Any

from telegram import InputFile, KeyboardButton, ReplyKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes, ConversationHandler

from .parser import ParseError, parse_channel_last_days
from .storage import StorageError, SupabaseStorage
from .threat_categories import CATEGORY_RU_TO_EN, CANONICAL_CATEGORY_LABELS_RU, THREAT_TYPE_RU_OPTIONS
from .threat_detector import ThreatDetectorError, detect_threat_rows
from .ui import main_keyboard

WAIT_CHANNEL = 1
WAIT_EXPORT_CHANNELS = 10
WAIT_EXPORT_PERIOD = 11
WAIT_EXPORT_TYPES = 12
WAIT_ANALYTICS_PERIOD = 20


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


SYNC_PARSE_ON_ADD = _env_bool("SYNC_PARSE_ON_ADD", True)
SYNC_REFRESH_BEFORE_THREATS_EXPORT = _env_bool("SYNC_REFRESH_BEFORE_THREATS_EXPORT", True)



def _progress_bar(done: int, total: int, width: int = 12) -> str:
    if total <= 0:
        return "░" * width
    filled = int((done / total) * width)
    if filled > width:
        filled = width
    if filled < 0:
        filled = 0
    return ("█" * filled) + ("░" * (width - filled))


async def _safe_progress_edit(message_obj: Any, text: str) -> None:
    try:
        await message_obj.edit_text(text)
    except TelegramError:
        # Non-fatal: network timeouts on progress updates should not break workflow.
        return


def _extract_handle(text: str) -> str | None:
    value = text.strip()
    if value.startswith("https://t.me/"):
        value = value.replace("https://t.me/", "", 1)
    value = value.lstrip("@").split("/")[0].strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{5,64}", value):
        return None
    return value.lower()


def _extract_handles_batch(raw: str) -> tuple[list[str], list[str]]:
    tokens = re.split(r"[\s,;]+", raw)
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if not token.strip():
            continue
        handle = _extract_handle(token)
        if handle is None:
            invalid.append(token.strip())
            continue
        if handle in seen:
            continue
        seen.add(handle)
        valid.append(handle)
    return valid, invalid


def _normalize_period_input(raw: str) -> tuple[str | None, str | None]:
    text = raw.strip().lower()
    if text in {"all", "все", "весь", "весь период", "*"}:
        return None, None

    if re.fullmatch(r"\d{1,4}", text):
        days = int(text)
        start = datetime.now(UTC) - timedelta(days=days)
        return start.isoformat(), datetime.now(UTC).isoformat()

    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})\s*(?:\.\.|-|\s)\s*(\d{4}-\d{2}-\d{2})", text)
    if m:
        date_from = datetime.fromisoformat(m.group(1)).replace(tzinfo=UTC)
        date_to = datetime.fromisoformat(m.group(2)).replace(tzinfo=UTC) + timedelta(days=1) - timedelta(seconds=1)
        return date_from.isoformat(), date_to.isoformat()

    raise ValueError("bad period format")


def _normalize_threat_types(raw: str) -> list[str] | None:
    text = raw.strip().lower()
    if text in {"all", "все", "все типы", "*"}:
        return None
    tokens = [t.strip() for t in re.split(r"[,;|\n]+", text) if t.strip()]
    out: list[str] = []
    for token in tokens:
        mapped = CATEGORY_RU_TO_EN.get(token, token)
        if mapped not in out:
            out.append(mapped)
    return out or None


def _threat_types_keyboard() -> ReplyKeyboardMarkup:
    rows = [[KeyboardButton("Все типы")]]
    row: list[KeyboardButton] = []
    for label in THREAT_TYPE_RU_OPTIONS:
        row.append(KeyboardButton(label))
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return ReplyKeyboardMarkup(rows, resize_keyboard=True, one_time_keyboard=True)


def _to_date_iso(value: str | None) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return str(value)
    return dt.astimezone(UTC).date().isoformat()


def _build_csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k) for k in fieldnames})
    return buf.getvalue().encode("utf-8")


def _build_svg_bar_chart(
    title: str,
    labels: list[str],
    values: list[int | float],
    width: int = 1100,
    height: int = 700,
) -> bytes:
    if not labels:
        labels = ["нет данных"]
        values = [0]

    left = 80
    right = 30
    top = 70
    bottom = 140
    plot_w = width - left - right
    plot_h = height - top - bottom
    max_val = max(float(v) for v in values) if values else 1.0
    if max_val <= 0:
        max_val = 1.0
    gap = max(8, int(plot_w / max(1, len(labels) * 8)))
    bar_w = max(10, int((plot_w - gap * (len(labels) + 1)) / max(1, len(labels))))

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{left}" y="36" font-size="24" font-family="Arial, sans-serif" fill="#111111">{title}</text>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#333333" stroke-width="2"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#333333" stroke-width="2"/>',
    ]

    for i, (label, value) in enumerate(zip(labels, values)):
        v = float(value)
        h = int((v / max_val) * plot_h)
        x = left + gap + i * (bar_w + gap)
        y = top + plot_h - h
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="#f2b705"/>')
        parts.append(f'<text x="{x + bar_w / 2}" y="{y - 8}" text-anchor="middle" font-size="12" font-family="Arial, sans-serif">{int(v)}</text>')
        short = label if len(label) <= 22 else label[:19] + "..."
        parts.append(
            f'<text x="{x + bar_w / 2}" y="{top + plot_h + 18}" text-anchor="end" transform="rotate(-35 {x + bar_w / 2} {top + plot_h + 18})" font-size="12" font-family="Arial, sans-serif">{short}</text>'
        )

    parts.append("</svg>")
    return "".join(parts).encode("utf-8")


def _build_svg_line_chart(
    title: str,
    labels: list[str],
    values: list[int | float],
    width: int = 1100,
    height: int = 700,
) -> bytes:
    if not labels:
        labels = ["нет данных"]
        values = [0]

    left = 80
    right = 30
    top = 70
    bottom = 120
    plot_w = width - left - right
    plot_h = height - top - bottom
    max_val = max(float(v) for v in values) if values else 1.0
    if max_val <= 0:
        max_val = 1.0
    n = max(1, len(values) - 1)

    points: list[tuple[float, float]] = []
    for i, v in enumerate(values):
        x = left + (plot_w * i / n)
        y = top + plot_h - (plot_h * (float(v) / max_val))
        points.append((x, y))

    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{left}" y="36" font-size="24" font-family="Arial, sans-serif" fill="#111111">{title}</text>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#333333" stroke-width="2"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#333333" stroke-width="2"/>',
        f'<polyline fill="none" stroke="#2b7de9" stroke-width="3" points="{polyline}"/>',
    ]

    for i, ((x, y), label, value) in enumerate(zip(points, labels, values)):
        if len(points) > 14 and i % 2 == 1:
            continue
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#2b7de9"/>')
        parts.append(f'<text x="{x:.1f}" y="{y - 10:.1f}" text-anchor="middle" font-size="11" font-family="Arial, sans-serif">{int(float(value))}</text>')
        parts.append(f'<text x="{x:.1f}" y="{top + plot_h + 18}" text-anchor="middle" font-size="11" font-family="Arial, sans-serif">{label}</text>')

    parts.append("</svg>")
    return "".join(parts).encode("utf-8")


async def _refresh_and_detect_for_channel(
    storage: SupabaseStorage,
    handle: str,
    channel_id: int,
) -> tuple[bool, str | None]:
    try:
        last_post_date = storage.get_last_post_date(channel_id=channel_id)
    except StorageError as exc:
        return False, f"{handle}: last post read error: {exc}"

    parse_days = 7
    if last_post_date:
        try:
            dt = datetime.fromisoformat(str(last_post_date).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            gap = max(1, (datetime.now(UTC) - dt.astimezone(UTC)).days + 1)
            parse_days = min(gap, 365)
        except Exception:
            parse_days = 7

    try:
        parsed = parse_channel_last_days(handle=handle, days=parse_days)
    except ParseError as exc:
        return False, f"{handle}: parse error: {exc}"

    try:
        storage.upsert_posts(
            channel_id=channel_id,
            source_handle=handle,
            posts=[
                {
                    "external_post_id": post.external_post_id,
                    "post_url": post.post_url,
                    "content": post.content,
                    "post_date": post.post_date,
                    "raw_payload": post.raw_payload,
                }
                for post in parsed
            ],
        )
    except StorageError as exc:
        return False, f"{handle}: post save error: {exc}"

    try:
        unchecked_posts = storage.list_unchecked_posts(channel_id=channel_id, limit=10000)
    except StorageError as exc:
        return False, f"{handle}: unchecked posts error: {exc}"

    all_threats: list[dict] = []
    checked_post_ids: list[int] = []
    for post in unchecked_posts:
        post_id = int(post.get("id"))
        checked_post_ids.append(post_id)
        try:
            rows = detect_threat_rows(
                post_id=post_id,
                content=post.get("content"),
                post_meta={
                    "post_url": post.get("post_url"),
                    "post_date": post.get("post_date"),
                    "source_handle": post.get("source_handle"),
                },
            )
        except ThreatDetectorError:
            continue
        except Exception:
            continue
        all_threats.extend(rows)

    try:
        storage.upsert_threats(all_threats)
    except StorageError as exc:
        return False, f"{handle}: threat save error: {exc}"

    try:
        storage.mark_posts_risk_checked(checked_post_ids)
    except StorageError as exc:
        return False, f"{handle}: mark checked error: {exc}"

    return True, None


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text("Выберите действие:", reply_markup=main_keyboard())


async def on_add_channel_click(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if update.message:
        await update.message.reply_text(
            "Отправьте канал/список каналов текстом, или .txt/.csv файл со списком."
        )
    return WAIT_CHANNEL


async def on_refresh_data(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    storage = context.bot_data.get("storage")
    if not isinstance(storage, SupabaseStorage):
        await update.message.reply_text("Ошибка: хранилище не инициализировано")
        return

    try:
        channels = [c for c in storage.list_channels() if bool(c.get("is_active", True))]
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения каналов: {exc}", reply_markup=main_keyboard())
        return

    if not channels:
        await update.message.reply_text("Нет активных каналов для обновления.", reply_markup=main_keyboard())
        return

    progress = await update.message.reply_text(f"{_progress_bar(0, len(channels))} 0/{len(channels)}")
    ok_count = 0
    fail_count = 0
    errors: list[str] = []

    for i, ch in enumerate(channels, start=1):
        handle = str(ch.get("handle") or "")
        channel_id = int(ch.get("id"))
        ok, err = await _refresh_and_detect_for_channel(storage=storage, handle=handle, channel_id=channel_id)
        if ok:
            ok_count += 1
        else:
            fail_count += 1
            if err:
                errors.append(err)
        await _safe_progress_edit(progress, f"{_progress_bar(i, len(channels))} {i}/{len(channels)}")

    lines = [
        "Обновление завершено.",
        f"Успешно: {ok_count}",
        f"С ошибками: {fail_count}",
    ]
    if errors:
        lines.append(f"Ошибки (первые 5): {' | '.join(errors[:5])}")
    await update.message.reply_text("\n".join(lines), reply_markup=main_keyboard())


async def _save_handles(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    handles: list[str],
    invalid: list[str],
) -> int:
    storage = context.bot_data.get("storage")
    if not isinstance(storage, SupabaseStorage):
        await update.message.reply_text("Ошибка: хранилище не инициализировано")
        return WAIT_CHANNEL

    created_by = str(update.effective_user.id) if update.effective_user else None
    success_count = 0
    failed_count = len(invalid)
    errors: list[str] = []

    progress_msg = await update.message.reply_text(f"{_progress_bar(0, len(handles))} 0/{len(handles)}")

    total = len(handles)

    for index, handle in enumerate(handles, start=1):
        channel_ok = True
        try:
            channel_row = storage.upsert_channel(handle=handle, created_by=created_by)
        except StorageError as exc:
            errors.append(f"{handle}: {exc}")
            channel_ok = False
            channel_row = None

        if channel_ok and SYNC_PARSE_ON_ADD:
            try:
                parsed = parse_channel_last_days(handle=handle, days=7)
            except ParseError as exc:
                errors.append(f"{handle}: parse error: {exc}")
                channel_ok = False
                parsed = []
        else:
            parsed = []

        if channel_ok and channel_row is not None and SYNC_PARSE_ON_ADD:
            try:
                storage.upsert_posts(
                    channel_id=int(channel_row.get("id")),
                    source_handle=handle,
                    posts=[
                        {
                            "external_post_id": post.external_post_id,
                            "post_url": post.post_url,
                            "content": post.content,
                            "post_date": post.post_date,
                            "raw_payload": post.raw_payload,
                        }
                        for post in parsed
                    ],
                )
            except StorageError as exc:
                errors.append(f"{handle}: post save error: {exc}")
                channel_ok = False

        if channel_ok and channel_row is not None and SYNC_PARSE_ON_ADD:
            try:
                unchecked_posts = storage.list_unchecked_posts(channel_id=int(channel_row.get("id")), limit=10000)
            except StorageError as exc:
                errors.append(f"{handle}: unchecked posts error: {exc}")
                channel_ok = False
                unchecked_posts = []

            if channel_ok:
                all_threats: list[dict] = []
                checked_post_ids: list[int] = []
                for post in unchecked_posts:
                    post_id = int(post.get("id"))
                    checked_post_ids.append(post_id)
                    try:
                        threat_rows = detect_threat_rows(
                            post_id=post_id,
                            content=post.get("content"),
                            post_meta={
                                "post_url": post.get("post_url"),
                                "post_date": post.get("post_date"),
                                "source_handle": post.get("source_handle"),
                            },
                        )
                    except ThreatDetectorError as exc:
                        errors.append(f"{handle}: detector error on post {post_id}: {exc}")
                        continue
                    except Exception as exc:
                        errors.append(f"{handle}: detector unexpected error on post {post_id}: {exc}")
                        continue
                    all_threats.extend(threat_rows)

                try:
                    storage.upsert_threats(all_threats)
                except StorageError as exc:
                    errors.append(f"{handle}: threat save error: {exc}")
                    channel_ok = False

                if channel_ok:
                    try:
                        storage.mark_posts_risk_checked(checked_post_ids)
                    except StorageError as exc:
                        errors.append(f"{handle}: mark checked error: {exc}")
                        channel_ok = False

        if channel_ok:
            success_count += 1
        else:
            failed_count += 1

        await _safe_progress_edit(progress_msg, f"{_progress_bar(index, total)} {index}/{total}")

    lines = [
        "Готово.",
        f"Успешно добавлено каналов: {success_count}",
        f"Неуспешно: {failed_count}",
    ]
    if not SYNC_PARSE_ON_ADD:
        lines.append("Парсинг и детект выполняются отдельно: кнопкой 'Обновить данные' или по cron.")
    if errors:
        lines.append(f"ошибки (первые 3): {' | '.join(errors[:3])}")

    await update.message.reply_text("\n".join(lines), reply_markup=main_keyboard())
    return ConversationHandler.END


async def on_channel_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message:
        return WAIT_CHANNEL

    handles, invalid = _extract_handles_batch(update.message.text or "")
    if not handles:
        await update.message.reply_text("Не нашел валидных каналов. Пример: @channel или https://t.me/channel")
        return WAIT_CHANNEL
    return await _save_handles(update, context, handles, invalid)


async def on_channel_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message or not update.message.document:
        return WAIT_CHANNEL

    try:
        tg_file = await update.message.document.get_file()
        data = await tg_file.download_as_bytearray()
        text = bytes(data).decode("utf-8", errors="replace")
    except Exception as exc:
        await update.message.reply_text(f"Не удалось прочитать файл: {exc}")
        return WAIT_CHANNEL

    handles, invalid = _extract_handles_batch(text)
    if not handles:
        await update.message.reply_text("В файле не найдено валидных каналов.")
        return WAIT_CHANNEL
    return await _save_handles(update, context, handles, invalid)


async def on_list_channels(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    storage = context.bot_data.get("storage")
    if not isinstance(storage, SupabaseStorage):
        await update.message.reply_text("Ошибка: хранилище не инициализировано")
        return

    progress = await update.message.reply_text(f"{_progress_bar(0, 3)} 0/3")

    try:
        rows = storage.list_channels()
    except StorageError as exc:
        await _safe_progress_edit(progress, "Ошибка выгрузки.")
        await update.message.reply_text(f"Ошибка чтения из БД: {exc}", reply_markup=main_keyboard())
        return

    await _safe_progress_edit(progress, f"{_progress_bar(1, 3)} 1/3")

    total = len(rows)
    if total == 0:
        await _safe_progress_edit(progress, "Готово. Каналов нет.")
        return

    buf = StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["id", "platform", "handle", "url", "is_active", "created_by", "created_at", "updated_at"],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k) for k in writer.fieldnames})

    await _safe_progress_edit(progress, f"{_progress_bar(2, 3)} 2/3")
    data = buf.getvalue().encode("utf-8")
    await _safe_progress_edit(progress, f"{_progress_bar(3, 3)} 3/3")
    await update.message.reply_document(
        document=InputFile(data, filename="monitoring_channels_full.csv"),
        caption=f"Полный список каналов: {total}",
    )


async def on_export_threats_click(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if update.message:
        await update.message.reply_text(
            "Выберите каналы: all / список / файл (.txt/.csv)."
        )
    return WAIT_EXPORT_CHANNELS


async def on_export_threats_channels_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message:
        return WAIT_EXPORT_CHANNELS
    raw = update.message.text or ""
    text = raw.strip().lower()
    if text in {"all", "все", "*"}:
        context.user_data["export_channels_mode"] = "all"
        context.user_data["export_handles"] = []
    else:
        handles, invalid = _extract_handles_batch(raw)
        if not handles:
            await update.message.reply_text("Не нашел валидных каналов. Повтори ввод или отправь файл.")
            return WAIT_EXPORT_CHANNELS
        context.user_data["export_channels_mode"] = "list"
        context.user_data["export_handles"] = handles
        context.user_data["export_invalid_handles"] = invalid
    await update.message.reply_text(
        "Период: число дней назад (например 7), диапазон YYYY-MM-DD..YYYY-MM-DD, или all."
    )
    return WAIT_EXPORT_PERIOD


async def on_export_threats_channels_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message or not update.message.document:
        return WAIT_EXPORT_CHANNELS
    try:
        tg_file = await update.message.document.get_file()
        data = await tg_file.download_as_bytearray()
        text = bytes(data).decode("utf-8", errors="replace")
    except Exception as exc:
        await update.message.reply_text(f"Не удалось прочитать файл: {exc}")
        return WAIT_EXPORT_CHANNELS
    handles, invalid = _extract_handles_batch(text)
    if not handles:
        await update.message.reply_text("В файле не найдено валидных каналов.")
        return WAIT_EXPORT_CHANNELS
    context.user_data["export_channels_mode"] = "list"
    context.user_data["export_handles"] = handles
    context.user_data["export_invalid_handles"] = invalid
    await update.message.reply_text(
        "Период: число дней назад (например 7), диапазон YYYY-MM-DD..YYYY-MM-DD, или all."
    )
    return WAIT_EXPORT_PERIOD


async def on_export_threats_period(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message:
        return WAIT_EXPORT_PERIOD
    try:
        date_from, date_to = _normalize_period_input(update.message.text or "")
    except ValueError:
        await update.message.reply_text("Формат периода неверный. Пример: 7 или 2026-02-01..2026-02-27 или all.")
        return WAIT_EXPORT_PERIOD
    context.user_data["export_date_from"] = date_from
    context.user_data["export_date_to"] = date_to
    await update.message.reply_text(
        "Выберите тип угрозы кнопкой (или напишите список через запятую). Кнопка 'Все типы' — без фильтра.",
        reply_markup=_threat_types_keyboard(),
    )
    return WAIT_EXPORT_TYPES


async def on_export_threats_types(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message:
        return WAIT_EXPORT_TYPES
    threat_types = _normalize_threat_types(update.message.text or "")

    storage = context.bot_data.get("storage")
    if not isinstance(storage, SupabaseStorage):
        await update.message.reply_text("Ошибка: хранилище не инициализировано")
        return ConversationHandler.END

    mode = context.user_data.get("export_channels_mode", "all")
    selected_handles: list[str] = list(context.user_data.get("export_handles", []))
    date_from = context.user_data.get("export_date_from")
    date_to = context.user_data.get("export_date_to")

    try:
        if mode == "all":
            channels = storage.list_channels()
        else:
            channels = storage.list_channels_by_handles(selected_handles)
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения каналов: {exc}", reply_markup=main_keyboard())
        return ConversationHandler.END

    if not channels:
        await update.message.reply_text("Каналы не найдены по выбранному фильтру.", reply_markup=main_keyboard())
        return ConversationHandler.END

    progress = await update.message.reply_text(f"{_progress_bar(0, 4)} 0/4")

    errors: list[str] = []
    if SYNC_REFRESH_BEFORE_THREATS_EXPORT:
        for ch in channels:
            ok, err = await _refresh_and_detect_for_channel(
                storage=storage,
                handle=str(ch.get("handle")),
                channel_id=int(ch.get("id")),
            )
            if not ok and err:
                errors.append(err)
    await _safe_progress_edit(progress, f"{_progress_bar(1, 4)} 1/4")

    channel_ids = [int(ch.get("id")) for ch in channels]
    try:
        posts = storage.list_posts_for_export(channel_ids=channel_ids, date_from_iso=date_from, date_to_iso=date_to)
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения постов: {exc}", reply_markup=main_keyboard())
        return ConversationHandler.END
    post_by_id = {int(p["id"]): p for p in posts if p.get("id") is not None}
    await _safe_progress_edit(progress, f"{_progress_bar(2, 4)} 2/4")

    try:
        threats = storage.list_threats_by_post_ids(
            post_ids=list(post_by_id.keys()),
            threat_types=threat_types,
        )
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения угроз: {exc}", reply_markup=main_keyboard())
        return ConversationHandler.END
    await _safe_progress_edit(progress, f"{_progress_bar(3, 4)} 3/4")

    buf = StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "threat_id",
            "threat_type",
            "threat_type_ru",
            "severity",
            "score",
            "reason",
            "detector_name",
            "detector_version",
            "threat_created_at",
            "post_id",
            "post_date",
            "post_url",
            "source_handle",
            "content",
        ],
    )
    writer.writeheader()
    for row in threats:
        post = post_by_id.get(int(row.get("post_id")))
        if not post:
            continue
        tt = str(row.get("threat_type") or "")
        writer.writerow(
            {
                "threat_id": row.get("id"),
                "threat_type": tt,
                "threat_type_ru": CANONICAL_CATEGORY_LABELS_RU.get(tt, tt),
                "severity": row.get("severity"),
                "score": row.get("score"),
                "reason": row.get("reason"),
                "detector_name": row.get("detector_name"),
                "detector_version": row.get("detector_version"),
                "threat_created_at": row.get("created_at"),
                "post_id": post.get("id"),
                "post_date": post.get("post_date"),
                "post_url": post.get("post_url"),
                "source_handle": post.get("source_handle"),
                "content": post.get("content"),
            }
        )

    data = buf.getvalue().encode("utf-8")
    await _safe_progress_edit(progress, f"{_progress_bar(4, 4)} 4/4")
    await update.message.reply_document(
        document=InputFile(data, filename="threats_export.csv"),
        caption=f"Выгрузка угроз: {len(threats)} записей",
        reply_markup=main_keyboard(),
    )
    if errors:
        await update.message.reply_text(f"Ошибки обновления (первые 5): {' | '.join(errors[:5])}")
    return ConversationHandler.END


async def on_analytics_click(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if update.message:
        await update.message.reply_text(
            "Период аналитики: число дней назад (например 7), диапазон YYYY-MM-DD..YYYY-MM-DD, или all."
        )
    return WAIT_ANALYTICS_PERIOD


async def on_analytics_period(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message:
        return WAIT_ANALYTICS_PERIOD

    try:
        date_from, date_to = _normalize_period_input(update.message.text or "")
    except ValueError:
        await update.message.reply_text("Формат периода неверный. Пример: 7 или 2026-02-01..2026-02-27 или all.")
        return WAIT_ANALYTICS_PERIOD

    storage = context.bot_data.get("storage")
    if not isinstance(storage, SupabaseStorage):
        await update.message.reply_text("Ошибка: хранилище не инициализировано")
        return ConversationHandler.END

    progress = await update.message.reply_text(f"{_progress_bar(0, 5)} 0/5")

    try:
        channels = [c for c in storage.list_channels() if bool(c.get("is_active", True))]
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения каналов: {exc}", reply_markup=main_keyboard())
        return ConversationHandler.END
    await _safe_progress_edit(progress, f"{_progress_bar(1, 5)} 1/5")

    channel_ids = [int(c.get("id")) for c in channels]
    try:
        posts = storage.list_posts_for_export(
            channel_ids=channel_ids,
            date_from_iso=date_from,
            date_to_iso=date_to,
        )
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения постов: {exc}", reply_markup=main_keyboard())
        return ConversationHandler.END
    await _safe_progress_edit(progress, f"{_progress_bar(2, 5)} 2/5")

    post_by_id = {int(p["id"]): p for p in posts if p.get("id") is not None}
    try:
        threats = storage.list_threats_by_post_ids(post_ids=list(post_by_id.keys()), threat_types=None)
    except StorageError as exc:
        await update.message.reply_text(f"Ошибка чтения угроз: {exc}", reply_markup=main_keyboard())
        return ConversationHandler.END
    await _safe_progress_edit(progress, f"{_progress_bar(3, 5)} 3/5")

    channel_map = {int(c["id"]): c for c in channels if c.get("id") is not None}
    channel_handle_by_post_id: dict[int, str] = {}
    for pid, post in post_by_id.items():
        cid = int(post.get("channel_id") or 0)
        channel_handle_by_post_id[pid] = str(post.get("source_handle") or channel_map.get(cid, {}).get("handle") or "")

    threats_by_type: dict[str, int] = {}
    threats_by_channel: dict[str, int] = {}
    threats_by_day: dict[str, int] = {}

    for t in threats:
        cat = str(t.get("threat_type") or "unknown")
        threats_by_type[cat] = threats_by_type.get(cat, 0) + 1

        pid = int(t.get("post_id") or 0)
        handle = channel_handle_by_post_id.get(pid, "")
        threats_by_channel[handle] = threats_by_channel.get(handle, 0) + 1

        post = post_by_id.get(pid)
        day = _to_date_iso(post.get("post_date") if post else None) or "unknown"
        threats_by_day[day] = threats_by_day.get(day, 0) + 1

    total_channels = len(channels)
    total_posts = len(posts)
    total_threats = len(threats)
    affected_posts = len({int(t.get("post_id")) for t in threats if t.get("post_id") is not None})
    affected_ratio = round((affected_posts / total_posts), 4) if total_posts else 0.0

    summary_rows = [
        {"metric": "period_from", "value": date_from or "all"},
        {"metric": "period_to", "value": date_to or "all"},
        {"metric": "total_channels", "value": total_channels},
        {"metric": "total_posts", "value": total_posts},
        {"metric": "total_threats", "value": total_threats},
        {"metric": "affected_posts", "value": affected_posts},
        {"metric": "affected_posts_ratio", "value": affected_ratio},
    ]

    by_channel_rows: list[dict[str, Any]] = []
    for handle, cnt in sorted(threats_by_channel.items(), key=lambda x: x[1], reverse=True):
        by_channel_rows.append({"source_handle": handle, "threats_count": cnt})

    by_type_rows: list[dict[str, Any]] = []
    for key, cnt in sorted(threats_by_type.items(), key=lambda x: x[1], reverse=True):
        by_type_rows.append(
            {
                "threat_type": key,
                "threat_type_ru": CANONICAL_CATEGORY_LABELS_RU.get(key, key),
                "threats_count": cnt,
            }
        )

    by_day_rows: list[dict[str, Any]] = []
    for day, cnt in sorted(threats_by_day.items(), key=lambda x: x[0]):
        by_day_rows.append({"date": day, "threats_count": cnt})

    summary_csv = _build_csv_bytes(["metric", "value"], summary_rows)
    by_channel_csv = _build_csv_bytes(["source_handle", "threats_count"], by_channel_rows)
    by_type_csv = _build_csv_bytes(["threat_type", "threat_type_ru", "threats_count"], by_type_rows)
    by_day_csv = _build_csv_bytes(["date", "threats_count"], by_day_rows)

    top_types = by_type_rows[:12]
    type_svg = _build_svg_bar_chart(
        title="Угрозы по типам",
        labels=[str(r["threat_type_ru"]) for r in top_types],
        values=[int(r["threats_count"]) for r in top_types],
    )

    top_channels = by_channel_rows[:12]
    channel_svg = _build_svg_bar_chart(
        title="Угрозы по каналам",
        labels=[str(r["source_handle"]) for r in top_channels],
        values=[int(r["threats_count"]) for r in top_channels],
    )

    trend_rows = by_day_rows[-31:]
    trend_svg = _build_svg_line_chart(
        title="Динамика угроз по дням",
        labels=[str(r["date"])[5:] for r in trend_rows],
        values=[int(r["threats_count"]) for r in trend_rows],
    )
    await _safe_progress_edit(progress, f"{_progress_bar(4, 5)} 4/5")

    await update.message.reply_document(
        document=InputFile(summary_csv, filename="analytics_summary.csv"),
        caption=(
            f"Аналитика: каналов={total_channels}, постов={total_posts}, угроз={total_threats}, "
            f"доля постов с угрозами={affected_ratio:.2%}"
        ),
    )
    await update.message.reply_document(document=InputFile(by_channel_csv, filename="analytics_by_channel.csv"))
    await update.message.reply_document(document=InputFile(by_type_csv, filename="analytics_by_type.csv"))
    await update.message.reply_document(document=InputFile(by_day_csv, filename="analytics_by_day.csv"))
    await update.message.reply_document(document=InputFile(type_svg, filename="chart_threats_by_type.svg"))
    await update.message.reply_document(document=InputFile(channel_svg, filename="chart_threats_by_channel.svg"))
    await update.message.reply_document(document=InputFile(trend_svg, filename="chart_threats_trend.svg"), reply_markup=main_keyboard())
    await _safe_progress_edit(progress, f"{_progress_bar(5, 5)} 5/5")
    return ConversationHandler.END

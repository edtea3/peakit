from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import requests
from bs4 import BeautifulSoup


class ParseError(Exception):
    pass


@dataclass
class ParsedPost:
    external_post_id: str
    post_url: str
    content: str | None
    post_date: str
    raw_payload: dict


def parse_channel_last_days(
    handle: str,
    days: int = 7,
    max_posts: int | None = None,
    timeout_s: int = 20,
) -> list[ParsedPost]:
    """Parse telegram channel public mirror (/s/) and return posts within last N days."""
    normalized = handle.lower().lstrip("@")
    cutoff = datetime.now(UTC) - timedelta(days=days)

    all_posts: list[ParsedPost] = []
    before_id: str | None = None

    while True:
        base_url = f"https://t.me/s/{normalized}"
        url = f"{base_url}?before={before_id}" if before_id else base_url

        try:
            response = requests.get(url, timeout=timeout_s)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ParseError(f"network error while parsing {normalized}: {exc}") from exc

        soup = BeautifulSoup(response.text, "html.parser")
        cards = soup.select("div.tgme_widget_message")
        if not cards:
            break

        oldest_seen_on_page: datetime | None = None
        last_post_id_on_page: str | None = None

        for card in cards:
            data_post = (card.get("data-post") or "").strip()
            if "/" not in data_post:
                continue
            _, post_id = data_post.split("/", 1)
            last_post_id_on_page = post_id

            date_node = card.select_one("time")
            date_raw = date_node.get("datetime") if date_node else None
            if not date_raw:
                continue

            try:
                dt = datetime.fromisoformat(date_raw.replace("Z", "+00:00"))
            except ValueError:
                continue

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            else:
                dt = dt.astimezone(UTC)

            if oldest_seen_on_page is None or dt < oldest_seen_on_page:
                oldest_seen_on_page = dt

            if dt < cutoff:
                continue

            text_node = card.select_one("div.tgme_widget_message_text")
            content = text_node.get_text("\n", strip=True) if text_node else None

            link_node = card.select_one("a.tgme_widget_message_date")
            post_url = link_node.get("href") if link_node else f"https://t.me/s/{normalized}/{post_id}"

            raw_payload = {
                "platform": "telegram",
                "source_handle": normalized,
                "external_post_id": post_id,
                "post_url": post_url,
                "post_date": dt.isoformat(),
                "content": content,
            }

            all_posts.append(
                ParsedPost(
                    external_post_id=post_id,
                    post_url=post_url,
                    content=content,
                    post_date=dt.isoformat(),
                    raw_payload=raw_payload,
                )
            )

            if max_posts is not None and len(all_posts) >= max_posts:
                break

        if not last_post_id_on_page:
            break

        before_id = last_post_id_on_page

        if oldest_seen_on_page is not None and oldest_seen_on_page < cutoff:
            break

        if max_posts is not None and len(all_posts) >= max_posts:
            break

    # Deduplicate by external_post_id preserving first occurrence
    dedup: dict[str, ParsedPost] = {}
    for post in all_posts:
        dedup.setdefault(post.external_post_id, post)
    return list(dedup.values())

from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .threat_categories import CANONICAL_CATEGORY_LABELS_RU


class StorageError(Exception):
    pass


@dataclass
class SupabaseStorage:
    url: str
    key: str
    timeout_s: int = 20
    ssl_verify: bool = True
    ca_bundle: str | None = None

    def _ssl_context(self) -> ssl.SSLContext:
        if not self.ssl_verify:
            return ssl._create_unverified_context()  # noqa: SLF001
        if self.ca_bundle:
            return ssl.create_default_context(cafile=self.ca_bundle)
        return ssl.create_default_context()

    def sync_threat_categories(self) -> int:
        payload = [
            {
                "category_key": key,
                "display_name_ru": label,
                "description": None,
                "is_active": True,
            }
            for key, label in CANONICAL_CATEGORY_LABELS_RU.items()
        ]
        query = urlencode({"on_conflict": "category_key"})
        endpoint = f"{self.url}/rest/v1/threat_categories?{query}"
        req = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=representation",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc
        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected threat categories response: {rows}")
        return len(rows)

    def upsert_channel(self, handle: str, created_by: str | None) -> dict:
        payload = {
            "platform": "telegram",
            "handle": handle,
            "url": f"https://t.me/{handle}",
            "is_active": True,
            "created_by": created_by,
        }
        query = urlencode({"on_conflict": "platform,handle"})
        endpoint = f"{self.url}/rest/v1/monitoring_channels?{query}"

        req = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=representation",
            },
        )

        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc

        if not isinstance(rows, list) or not rows:
            raise StorageError(f"Supabase empty response: {rows}")
        return dict(rows[0])

    def upsert_posts(self, channel_id: int, source_handle: str, posts: list[dict]) -> int:
        if not posts:
            return 0

        payload: list[dict] = []
        for post in posts:
            payload.append(
                {
                    "channel_id": channel_id,
                    "platform": "telegram",
                    "source_handle": source_handle,
                    "external_post_id": str(post.get("external_post_id", "")),
                    "post_url": post.get("post_url"),
                    "content": post.get("content"),
                    "post_date": post.get("post_date"),
                    "raw_payload": post.get("raw_payload") or {},
                }
            )

        query = urlencode({"on_conflict": "platform,source_handle,external_post_id"})
        endpoint = f"{self.url}/rest/v1/posts?{query}"

        req = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=representation",
            },
        )

        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc

        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected posts response: {rows}")
        return len(rows)

    def list_channels(self) -> list[dict]:
        query = urlencode(
            {
                "select": "id,platform,handle,url,is_active,created_by,created_at,updated_at",
                "order": "created_at.desc",
            }
        )
        endpoint = f"{self.url}/rest/v1/monitoring_channels?{query}"
        req = Request(
            endpoint,
            method="GET",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Accept": "application/json",
            },
        )

        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc

        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected channels response: {rows}")
        return [dict(row) for row in rows]

    def list_unchecked_posts(self, channel_id: int, limit: int = 1000) -> list[dict]:
        query = urlencode(
            {
                "select": "id,content,post_url,post_date,source_handle,raw_payload",
                "channel_id": f"eq.{channel_id}",
                "risk_checked_at": "is.null",
                "order": "post_date.desc",
                "limit": str(limit),
            }
        )
        endpoint = f"{self.url}/rest/v1/posts?{query}"
        req = Request(
            endpoint,
            method="GET",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc

        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected unchecked posts response: {rows}")
        return [dict(row) for row in rows]

    def upsert_threats(self, threats: list[dict]) -> int:
        if not threats:
            return 0
        # Supabase/Postgres cannot upsert two rows with same conflict key in one statement.
        deduped: dict[tuple[str, str, str, str], dict] = {}
        for row in threats:
            key = (
                str(row.get("post_id")),
                str(row.get("threat_type")),
                str(row.get("detector_name")),
                str(row.get("detector_version")),
            )
            deduped[key] = row
        payload = list(deduped.values())

        query = urlencode({"on_conflict": "post_id,threat_type,detector_name,detector_version"})
        endpoint = f"{self.url}/rest/v1/post_threats?{query}"
        req = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=representation",
            },
        )

        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc

        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected threats response: {rows}")
        return len(rows)

    def mark_posts_risk_checked(self, post_ids: list[int]) -> int:
        if not post_ids:
            return 0

        unique_ids = sorted(set(int(x) for x in post_ids))
        ids_expr = ",".join(str(x) for x in unique_ids)
        endpoint = f"{self.url}/rest/v1/posts?id=in.({ids_expr})"
        payload = {"risk_checked_at": datetime.now(UTC).isoformat()}
        req = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            method="PATCH",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            },
        )

        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc

        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc

        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected posts patch response: {rows}")
        return len(rows)

    def list_channels_by_handles(self, handles: list[str]) -> list[dict]:
        if not handles:
            return []
        uniq = sorted({h.lower().lstrip("@") for h in handles if h.strip()})
        handles_expr = ",".join(uniq)
        query = urlencode(
            {
                "select": "id,platform,handle,url,is_active,created_by,created_at,updated_at",
                "handle": f"in.({handles_expr})",
                "order": "created_at.desc",
            }
        )
        endpoint = f"{self.url}/rest/v1/monitoring_channels?{query}"
        req = Request(
            endpoint,
            method="GET",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc
        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected channels-by-handles response: {rows}")
        return [dict(row) for row in rows]

    def get_last_post_date(self, channel_id: int) -> str | None:
        query = urlencode(
            {
                "select": "post_date",
                "channel_id": f"eq.{channel_id}",
                "order": "post_date.desc",
                "limit": "1",
            }
        )
        endpoint = f"{self.url}/rest/v1/posts?{query}"
        req = Request(
            endpoint,
            method="GET",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc
        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected last-post response: {rows}")
        if not rows:
            return None
        return rows[0].get("post_date")

    def list_posts_for_export(
        self,
        channel_ids: list[int],
        date_from_iso: str | None,
        date_to_iso: str | None,
    ) -> list[dict]:
        if not channel_ids:
            return []
        ids_expr = ",".join(str(int(x)) for x in sorted(set(channel_ids)))
        params: dict[str, str] = {
            "select": "id,channel_id,source_handle,post_url,post_date,content",
            "channel_id": f"in.({ids_expr})",
            "order": "post_date.desc",
            "limit": "20000",
        }
        if date_from_iso and date_to_iso:
            params["and"] = f"(post_date.gte.{date_from_iso},post_date.lte.{date_to_iso})"
        elif date_from_iso:
            params["post_date"] = f"gte.{date_from_iso}"
        elif date_to_iso:
            params["post_date"] = f"lte.{date_to_iso}"
        query = urlencode(params)
        endpoint = f"{self.url}/rest/v1/posts?{query}"
        req = Request(
            endpoint,
            method="GET",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8")
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
        except URLError as exc:
            raise StorageError(f"Supabase network error: {exc}") from exc
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StorageError(f"Supabase bad JSON response: {raw}") from exc
        if not isinstance(rows, list):
            raise StorageError(f"Supabase unexpected posts-for-export response: {rows}")
        return [dict(row) for row in rows]

    def list_threats_by_post_ids(self, post_ids: list[int], threat_types: list[str] | None) -> list[dict]:
        if not post_ids:
            return []
        uniq_ids = sorted(set(int(x) for x in post_ids))
        out: list[dict] = []
        chunk_size = 200
        for i in range(0, len(uniq_ids), chunk_size):
            chunk = uniq_ids[i : i + chunk_size]
            ids_expr = ",".join(str(x) for x in chunk)
            params: dict[str, str] = {
                "select": "id,post_id,threat_type,severity,score,reason,detector_name,detector_version,created_at",
                "post_id": f"in.({ids_expr})",
                "order": "created_at.desc",
                "limit": "20000",
            }
            if threat_types:
                tt_expr = ",".join(sorted(set(threat_types)))
                params["threat_type"] = f"in.({tt_expr})"
            query = urlencode(params)
            endpoint = f"{self.url}/rest/v1/post_threats?{query}"
            req = Request(
                endpoint,
                method="GET",
                headers={
                    "apikey": self.key,
                    "Authorization": f"Bearer {self.key}",
                    "Accept": "application/json",
                },
            )
            try:
                with urlopen(req, timeout=self.timeout_s, context=self._ssl_context()) as resp:
                    raw = resp.read().decode("utf-8")
            except HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                raise StorageError(f"Supabase HTTP {exc.code}: {body}") from exc
            except URLError as exc:
                raise StorageError(f"Supabase network error: {exc}") from exc
            try:
                rows = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise StorageError(f"Supabase bad JSON response: {raw}") from exc
            if not isinstance(rows, list):
                raise StorageError(f"Supabase unexpected threats-by-posts response: {rows}")
            out.extend(dict(row) for row in rows)
        return out

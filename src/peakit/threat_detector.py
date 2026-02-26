from __future__ import annotations

import os
from typing import Any

from openai import OpenAI

from .threat_categories import normalize_category_key

DETECTOR_NAME = "aitunnel_moderation"
DETECTOR_VERSION = "1.0"
DEFAULT_MODEL = "omni-moderation-latest"
DEFAULT_BASE_URL = "https://api.aitunnel.ru/v1/"


class ThreatDetectorError(Exception):
    pass


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _severity(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _client() -> OpenAI:
    api_key = (
        os.getenv("AITUNNEL_API_KEY", "").strip()
        or os.getenv("OPENAI_API_KEY", "").strip()
    )
    if not api_key:
        raise ThreatDetectorError("Set AITUNNEL_API_KEY (or OPENAI_API_KEY) in environment")

    base_url = os.getenv("AITUNNEL_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
    return OpenAI(api_key=api_key, base_url=base_url)


def score_text(text: str, model: str = DEFAULT_MODEL) -> dict[str, Any]:
    try:
        response = _client().moderations.create(model=model, input=text)
    except Exception as exc:
        raise ThreatDetectorError(f"Moderation request failed: {exc}") from exc

    if not response.results:
        raise ThreatDetectorError("Moderation returned empty results")

    result = response.results[0]

    categories = getattr(result, "categories", None)
    category_scores = getattr(result, "category_scores", None)
    flagged = bool(getattr(result, "flagged", False))

    categories_map: dict[str, bool] = {}
    scores_map: dict[str, float] = {}

    if categories is not None:
        if hasattr(categories, "model_dump"):
            categories_map = {k: bool(v) for k, v in categories.model_dump().items()}
        elif isinstance(categories, dict):
            categories_map = {k: bool(v) for k, v in categories.items()}

    if category_scores is not None:
        if hasattr(category_scores, "model_dump"):
            scores_map = {k: _to_float(v) for k, v in category_scores.model_dump().items()}
        elif isinstance(category_scores, dict):
            scores_map = {k: _to_float(v) for k, v in category_scores.items()}

    final_score = max(scores_map.values()) if scores_map else 0.0

    return {
        "threat_found": flagged,
        "final_score": final_score,
        "categories": categories_map,
        "category_scores": scores_map,
    }


def detect_threat_rows(post_id: int, content: str | None, post_meta: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not content or len(content.strip()) < 2:
        return []

    model = os.getenv("THREAT_DETECTOR_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    min_score = _to_float(os.getenv("THREAT_MIN_SCORE", "0.40"), 0.40)

    result = score_text(text=content, model=model)
    categories = result.get("categories") or {}
    scores = result.get("category_scores") or {}
    threat_found = bool(result.get("threat_found"))
    final_score = _to_float(result.get("final_score"), 0.0)

    rows: list[dict[str, Any]] = []
    for cat, is_flagged in categories.items():
        cat_key = normalize_category_key(str(cat))
        score = _to_float(scores.get(cat), 0.0)
        if not is_flagged and score < min_score:
            continue
        rows.append(
            {
                "post_id": post_id,
                "threat_type": cat_key,
                "severity": _severity(score),
                "score": round(score, 4),
                "is_confirmed": False,
                "reason": f"moderation:{cat_key}",
                "evidence": {
                    "model_result": result,
                    "post_meta": post_meta or {},
                },
                "detector_name": DETECTOR_NAME,
                "detector_version": DETECTOR_VERSION,
            }
        )

    if rows:
        return rows

    if threat_found and final_score >= min_score:
        return [
            {
                "post_id": post_id,
                "threat_type": "flagged",
                "severity": _severity(final_score),
                "score": round(final_score, 4),
                "is_confirmed": False,
                "reason": "moderation:flagged",
                "evidence": {
                    "model_result": result,
                    "post_meta": post_meta or {},
                },
                "detector_name": DETECTOR_NAME,
                "detector_version": DETECTOR_VERSION,
            }
        ]

    return []

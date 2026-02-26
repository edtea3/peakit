from __future__ import annotations

CANONICAL_CATEGORY_LABELS_RU: dict[str, str] = {
    "harassment": "Домогательства",
    "harassment/threatening": "Домогательства с угрозами",
    "hate": "Ненависть",
    "hate/threatening": "Ненависть с угрозами",
    "illicit": "Противоправные действия",
    "illicit/violent": "Противоправные с насилием",
    "self-harm": "Самоповреждение",
    "self-harm/intent": "Намерение самоповреждения",
    "self-harm/instructions": "Инструкции по самоповреждению",
    "sexual": "Сексуальный контент",
    "sexual/minors": "Сексуальный контент с несовершеннолетними",
    "violence": "Насилие",
    "violence/graphic": "Графическое насилие",
    "flagged": "Флаг модели",
}

CATEGORY_RU_TO_EN: dict[str, str] = {
    value.lower(): key for key, value in CANONICAL_CATEGORY_LABELS_RU.items()
}

THREAT_TYPE_RU_OPTIONS: list[str] = list(CANONICAL_CATEGORY_LABELS_RU.values())

ALIASES_TO_CANONICAL: dict[str, str] = {
    "harassment": "harassment",
    "harassment/threatening": "harassment/threatening",
    "harassment_threatening": "harassment/threatening",
    "hate": "hate",
    "hate/threatening": "hate/threatening",
    "hate_threatening": "hate/threatening",
    "illicit": "illicit",
    "illicit/violent": "illicit/violent",
    "illicit_violent": "illicit/violent",
    "self-harm": "self-harm",
    "self_harm": "self-harm",
    "self-harm/intent": "self-harm/intent",
    "self_harm/intent": "self-harm/intent",
    "self-harm_intent": "self-harm/intent",
    "self-harm/instructions": "self-harm/instructions",
    "self_harm/instructions": "self-harm/instructions",
    "self-harm_instructions": "self-harm/instructions",
    "sexual": "sexual",
    "sexual/minors": "sexual/minors",
    "sexual_minors": "sexual/minors",
    "violence": "violence",
    "violence/graphic": "violence/graphic",
    "violence_graphic": "violence/graphic",
    "flagged": "flagged",
}


def normalize_category_key(key: str) -> str:
    raw = key.strip().lower()
    raw = raw.replace(" ", "_")
    return ALIASES_TO_CANONICAL.get(raw, raw)

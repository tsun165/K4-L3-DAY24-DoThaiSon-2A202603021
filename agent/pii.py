"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Interface bắt buộc:
    detect(text: str) -> list[dict]
        Entity: {"type": str, "start": int, "end": int}
        Type: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
    redact(text: str) -> str
        Thay entity bằng "[REDACTED_<TYPE>]"
"""
from __future__ import annotations

import re


def detect(text: str) -> list[dict]:
    """Phát hiện PII gồm CCCD, Phone, Bank Account và Email."""
    entities: list[dict] = []

    # 1. EMAIL
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    for m in email_pattern.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (thường đi sau tiền tố STK hoặc số tài khoản)
    bank_pattern = re.compile(r"(?i)(?:\bSTK\b|số\s+tài\s+khoản)\s*[:.]?\s*(\d{8,16})\b")
    for m in bank_pattern.finditer(text):
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})

    # Tránh các span đã được nhận diện làm bank account hoặc email
    occupied = [(e["start"], e["end"]) for e in entities]

    def _is_occupied(start: int, end: int) -> bool:
        return any(max(start, occ_s) < min(end, occ_e) for occ_s, occ_e in occupied)

    # 3. VN_CCCD: 12 chữ số liên tiếp
    cccd_pattern = re.compile(r"\b\d{12}\b")
    for m in cccd_pattern.finditer(text):
        s, e = m.start(), m.end()
        if not _is_occupied(s, e):
            entities.append({"type": "VN_CCCD", "start": s, "end": e})
            occupied.append((s, e))

    # 4. VN_PHONE: 10 chữ số bắt đầu bằng 0
    phone_pattern = re.compile(r"\b0\d{9}\b")
    for m in phone_pattern.finditer(text):
        s, e = m.start(), m.end()
        if not _is_occupied(s, e):
            entities.append({"type": "VN_PHONE", "start": s, "end": e})
            occupied.append((s, e))

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi entity phát hiện được bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay thế ngược từ cuối về đầu để không làm lệch offset
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        placeholder = f"[REDACTED_{ent['type']}]"
        text = text[: ent["start"]] + placeholder + text[ent["end"] :]
    return text

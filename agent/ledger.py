"""BƯỚC 3e — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3e).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(data: dict) -> str:
    """Tính SHA-256 từ dict không chứa field 'hash' với sort_keys=True."""
    to_hash = {k: v for k, v in data.items() if k != "hash"}
    encoded = json.dumps(to_hash, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Thêm một entry vào ledger kèm prev_hash và sha256 hash chain."""
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        content = path.read_text(encoding="utf-8").strip()
        if content:
            last_line = content.splitlines()[-1]
            try:
                last_record = json.loads(last_line)
                prev_hash = last_record.get("hash", "0" * 64)
            except Exception:
                prev_hash = "0" * 64

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác thực tính toàn vẹn của audit ledger hash chain."""
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        reason = record.get("reason")
        if not reason or not str(reason).strip():
            return False

        if record.get("prev_hash") != expected_prev:
            return False

        stored_hash = record.get("hash")
        if not stored_hash:
            return False

        recomputed = _compute_hash(record)
        if recomputed != stored_hash:
            return False

        expected_prev = stored_hash

    return True

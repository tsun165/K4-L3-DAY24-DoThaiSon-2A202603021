"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b, §3c).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if not PRINCIPALS_PATH.exists():
        return {}
    try:
        return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật trước khi cho phép gọi tool.
    
    Luôn trả về (allow, reason) với reason không bao giờ rỗng.
    """
    # 1. Rule tối thiểu: data restricted đi kèm egress=True bắt buộc phải DENY
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "DENY: restricted data cannot be accessed when egress is enabled"

    # 2. Kiểm tra TTL / expires_at
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > exp:
                return False, f"DENY: delegation context expired at {context.expires_at}"
        except Exception:
            return False, "DENY: invalid expires_at timestamp format"

    # 3. Kiểm tra Principal và OBO permissions
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"DENY: unknown principal_id '{context.principal_id}'"

        principal = principals[context.principal_id]
        allowed_tools = set(principal.get("allowed_tools", []))
        allowed_purposes = set(principal.get("purposes", []))

        # Kiểm tra purpose nếu có
        if context.request_purpose and allowed_purposes and context.request_purpose not in allowed_purposes:
            return False, f"DENY: purpose '{context.request_purpose}' is not allowed for principal '{context.principal_id}'"

        # Quyền hiệu lực là giao của: principal.allowed_tools ∩ agent_scopes (nếu có)
        effective_tools = allowed_tools
        if context.agent_scopes:
            effective_tools = effective_tools.intersection(set(context.agent_scopes))

        # Khi delegation_depth > 0, agent con không được vượt quyền cha (giao với parent_scopes)
        if context.delegation_depth > 0 and context.parent_scopes:
            effective_tools = effective_tools.intersection(set(context.parent_scopes))

        if context.requested_tool and context.requested_tool not in effective_tools:
            return (
                False,
                f"DENY: tool '{context.requested_tool}' is not in effective scopes for principal '{context.principal_id}'",
            )

    # 4. Kiểm tra delegation scopes khi không có principal_id
    if context.delegation_depth > 0 and context.requested_tool and context.parent_scopes:
        if context.requested_tool not in context.parent_scopes:
            return False, f"DENY: delegation tool '{context.requested_tool}' exceeds parent scopes"

    return True, "ALLOW: request satisfied all policy and OBO constraints"

"""BƯỚC 3c & 3d — Trifecta Split + OBO Tool Boundary + Audit Logging.

Kiến trúc Trifecta Split:
- Run A: Gọi search_docs (untrusted content). KHÔNG gọi read_customer, KHÔNG gọi http_post.
         Chỉ truyền ticket IDs dạng số nguyên trích từ TÊN FILE sang Run B.
- Run B: Gọi read_customer (private data) dựa trên `related_tickets` trong data/customers.json.
         KHÔNG BAO GIỜ nhận customer_id từ free text của attacker.
- Mọi tool call (search_docs, read_customer, http_post) đều phải:
  1. Qua `agent.policy.check()` TRƯỚC KHI thực thi.
  2. Ghi nhận vào ledger qua `agent.ledger.append()` (kể cả khi allow hay deny).
  3. Chỉ thực thi tool nếu policy cho phép.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _get_customers() -> list[dict]:
    if not CUSTOMERS_FILE.exists():
        return []
    try:
        return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    agent_scopes = ("search_docs", "read_customer", "http_post")

    # =========================================================================
    # RUN A: Untrusted Content (search_docs)
    # Không đọc customer, không egress
    # =========================================================================
    run_a_id = "run-a"
    ctx_search = policy.PolicyContext(
        data_classification="internal",
        request_purpose="support-reply",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    search_args_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": run_a_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "search_docs",
            "args_hash": search_args_hash,
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu tìm kiếm tài liệu bị từ chối bởi chính sách."

    docs = tools.search_docs(message)

    # Trích xuất ticket IDs từ TÊN FILE (sanitized data boundary)
    # Ví dụ: "ticket-014.md" -> 14, "ticket-901.md" -> 901
    ticket_ids: set[int] = set()
    for d in docs:
        m = re.search(r"ticket-(\d+)", d.get("id", ""))
        if m:
            ticket_ids.add(int(m.group(1)))

    # Phân tích injection trong Run A (chỉ để phát hiện ý định tấn công, KHÔNG dùng customer_id)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # RUN B: Private Data Store (read_customer)
    # Suy customer_id từ NGUỒN TIN CẬY (data/customers.json: related_tickets),
    # tuyệt đối không lấy từ free text của attacker.
    # =========================================================================
    run_b_id = "run-b"
    all_customers = _get_customers()
    matched_customer_ids: list[str] = []
    for c in all_customers:
        rel = set(c.get("related_tickets", []))
        if rel.intersection(ticket_ids):
            matched_customer_ids.append(c["customer_id"])

    # Đảm bảo thứ tự xác định
    matched_customer_ids = sorted(set(matched_customer_ids))

    collected_records: list[dict] = []
    for cust_id in matched_customer_ids:
        ctx_customer = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_cust, reason_cust = policy.check(ctx_customer)
        cust_args_hash = hashlib.sha256(cust_id.encode("utf-8")).hexdigest()
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": run_b_id,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "read_customer",
                "args_hash": cust_args_hash,
                "classification": "restricted",
                "decision": "allow" if allow_cust else "deny",
                "reason": reason_cust,
            },
            ledger_path,
        )

        if allow_cust:
            try:
                rec = tools.read_customer(cust_id)
                collected_records.append(rec)
            except tools.ToolError:
                pass

    # =========================================================================
    # EGRESS VECTOR (http_post): Nếu có chỉ thị injection đòi gửi dữ liệu ra sink
    # =========================================================================
    if injected is not None:
        target_url = injected.target_url
        ctx_post = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        post_args_hash = hashlib.sha256(target_url.encode("utf-8")).hexdigest()
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": run_b_id,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "http_post",
                "args_hash": post_args_hash,
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
            },
            ledger_path,
        )

        if allow_post:
            tools.http_post(target_url, {"records": collected_records})

    return llm.summarize(docs)

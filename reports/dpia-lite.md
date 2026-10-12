# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - Dữ liệu nội bộ (`internal`): Nội dung ticket yêu cầu hỗ trợ trong `corpus/`.
   - Dữ liệu cá nhân nhạy cảm (`restricted` / PII): Hồ sơ khách hàng trong `data/customers.json` gồm Họ tên, Số CCCD (12 chữ số), Số điện thoại (10 chữ số), Số tài khoản ngân hàng (8–16 chữ số), Email cá nhân.
2. Mục đích xử lý và principal:
   - Mục đích xử lý: Tổng hợp thông tin vé hỗ trợ (`summarize-tickets`) và phản hồi hỗ trợ khách hàng (`support-reply`).
   - Principal thực thi:
     - `support_l1`: Nhân viên hỗ trợ tầng 1, chỉ được dùng `search_docs`, bị cấm truy cập PII (`read_customer`).
     - `dpo`: Cán bộ bảo vệ dữ liệu, được phép truy cập `read_customer` cho mục đích kiểm soát hợp lệ.
3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - Run A: Thực thi tool `search_docs` đọc untrusted content từ `corpus/`. Dữ liệu chuyển giao sang Run B được làm sạch hoàn toàn: chỉ truyền mảng số nguyên `ticket_id` trích từ tên file. Free text của kẻ tấn công không đi qua boundary này.
   - Run B: Dùng `ticket_id` đối chiếu trường `related_tickets` trong `data/customers.json` để xác định khách hàng. Gọi `read_customer` lấy dữ liệu (chỉ thành công dưới quyền `dpo`).
   - Endpoint: Kẻ tấn công tìm cách gọi `http_post` gửi PII tới `http://127.0.0.1:10024/reconcile`.
4. Bằng chứng deny/allow và giới hạn của mock:
   - Bằng chứng Allow: `reports/ledger.jsonl` ghi nhận `search_docs` (allow) và `read_customer` (allow dưới quyền `dpo`).
   - Bằng chứng Deny: `reports/ledger.jsonl` ghi nhận dòng `tool="http_post", decision="deny"` với lý do `DENY: restricted data cannot be accessed when egress is enabled`. Dưới quyền `support_l1`, các yêu cầu `read_customer` đều bị deny.
   - Kết quả exfiltration: `reports/attack-after.log` rỗng (0 bytes).
   - Giới hạn của mock:
     - Mock LLM dựa trên heuristic marker để tái lập kết quả chấm điểm, chưa phản ánh toàn diện các kỹ thuật jailbreak nâng cao trên LLM sinh mã thật.
     - Tham số `--as` chỉ mô phỏng kiểm soát truy cập (ABAC/RBAC) trong lab, không thay thế xác thực danh tính production (OAuth2/OIDC, mTLS).
     - Audit ledger dạng hash chain cục bộ chưa có neo tin cậy bên ngoài (external timestamping authority) để bảo vệ chống việc cắt đuôi file nhật ký.

# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | PII Detection & Redaction gate (CCCD, SĐT, STK, Email); Phân quyền kiểm soát truy cập dữ liệu nhạy cảm OBO (support_l1 bị từ chối đọc hồ sơ khách hàng, chỉ dpo được đọc) | `agent/pii.py:13-60`<br>`agent/policy.py:53-78`<br>`agent/runner.py:91-140` | Điều khoản cụ thể: *chưa xác minh*. Hệ thống dùng dữ liệu tổng hợp (synthetic data) và mock; chưa thay thế quy trình pháp lý thực tế. |
| NĐ 356/2025/NĐ-CP | Ràng buộc mục đích xử lý dữ liệu (Purpose specification); Audit trail minh bạch, lưu vết toàn bộ tool call với hash chain chống chối bỏ | `agent/policy.py:64-70`<br>`agent/ledger.py:20-84`<br>`reports/ledger.jsonl:1-23` | Điều khoản cụ thể: *chưa xác minh*. File log cục bộ chưa có mốc thời gian ngoài (RFC 3161 TSA) để chống cắt đuôi file. |
| Luật AI 134/2025/QH15 | Kiến trúc kiểm soát an toàn AI (Trifecta Split); Ngăn mô hình tự ý thực hiện hành động nguy hiểm hoặc kết nối mạng trái phép khi xử lý dữ liệu mật | `agent/runner.py:38-175`<br>`agent/policy.py:43-45` | Điều khoản cụ thể: *chưa xác minh*. Thử nghiệm dựa trên deterministic mock LLM; production cần đánh giá trên LLM thật. |
| OWASP ASI01, ASI03, ASI04 | **ASI01 (Prompt Injection):** Trifecta Split cô lập text attacker ở Run A, Run B chỉ nhận sanitized ticket ID.<br>**ASI03 (Insecure Tool Execution):** PEP thẩm định quyền trước khi gọi tool.<br>**ASI04 (Uncontrolled Egress):** Chặn đứng http_post khi dữ liệu là restricted. | `agent/runner.py:73-100`<br>`agent/policy.py:38-92`<br>`agent/runner.py:145-175` | Lab chạy trên môi trường giả lập localhost; chưa bao gồm proxy firewall và container sandboxing ở cấp độ hạ tầng. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.

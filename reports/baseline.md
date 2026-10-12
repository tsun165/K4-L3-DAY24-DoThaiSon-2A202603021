# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm: Chưa. Trong `agent/loop.py` hàm `_naive_loop()`, agent thực thi mà không có `agent_id`, `run_id` hay identity/principal nào được khởi tạo hoặc quản lý theo từng run.
2. Ai cho phép `http_post`? Dẫn file/hàm: Không có ai cấp phép (thiếu Policy Enforcement Point). Hàm `_naive_loop()` trong `agent/loop.py` tự động gọi `tools.http_post()` theo chỉ thị trích xuất trực tiếp từ payload injection (`injected.target_url`) mà không thông qua bất kỳ cơ chế kiểm soát chính sách nào.
3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm: Bằng chứng chỉ nằm ở phía đích nhận (sink) tại file `reports/sink.log` do hàm `make_handler()` trong `sink/sink.py` ghi lại khi nhận HTTP POST request; phía agent hoàn toàn không có audit ledger lưu lại lịch sử tool execution.

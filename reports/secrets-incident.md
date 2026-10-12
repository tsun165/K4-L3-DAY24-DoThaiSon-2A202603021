# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1 (sử dụng hook `gitleaks-system` pin v8.30.1)
- Commit chứa token giả: `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c` — chore: seed student lab with synthetic secret exercise)
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`
  - Rule: `lab24-synthetic-token` (cấu hình trong `.gitleaks.toml`, regex `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`)
  - Kết quả quét lịch sử (`gitleaks git --config .gitleaks.toml .`): Phát hiện 1 finding token giả `LAB24_FAKE_TOKEN=LAB24-DEMO-...` tại commit `1bdd849`.
- Kết quả quét file hiện tại:
  - Kết quả quét file hiện tại (`gitleaks dir --config .gitleaks.toml .`): Sạch (0 leaks), file giả lập đã được xóa khỏi HEAD.
- Nếu đây là credential thật, cần xử lý thế nào:
  - Phải lập tức **thu hồi (revoke) và rotate** credential trên hệ thống dịch vụ/nhà cung cấp. Kiểm tra audit log xem credential đã bị truy cập trái phép chưa.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xóa file khỏi HEAD không xóa được dữ liệu trong lịch sử Git: commit `1bdd849` và blob object của file vẫn nằm trong git history/packfile, bất kỳ ai clone repo đều đọc được.
  - Pin dependency (hash lock) và pre-commit hook chỉ ngăn ngừa tấn công supply chain từ package ngoài hoặc chặn commit secret mới trong tương lai, chứ không thể vô hiệu hóa một credential đã bị lộ trong quá khứ. Biện pháp duy nhất giải quyết triệt để rủi ro là **rotate / thu hồi** khóa bí mật trên server.

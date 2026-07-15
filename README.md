# Secure Note Sharing

## Giới thiệu

Secure Note Sharing là ứng dụng console viết bằng ngôn ngữ C++ cho phép người dùng:

- Đăng ký và đăng nhập tài khoản
- Tạo và lưu ghi chú an toàn
- Tải ghi chú từ file
- Chia sẻ ghi chú bằng URL hoặc cơ chế End-to-End

Dữ liệu ghi chú được mã hóa ở phía client trước khi gửi lên server mô phỏng chạy cục bộ

## Tính năng chính

- Đăng ký và đăng nhập người dùng
- Tạo ghi chú dạng text
- Tải lên, đọc và lưu ghi chú từ file
- Xóa ghi chú
- Chia sẻ ghi chú bằng URL có thời hạn
- Hỗ trợ mã PIN để bảo vệ URL được chia sẻ
- Chia sẻ khóa giải mã theo cơ chế End-to-End
- Kiểm tra "hộp thư" để nhận gói chia sẻ
- Thu hồi link chia sẻ khi hết hạn

## Công nghệ sử dụng

- `C++17`: Ngôn ngữ chính của Project
- `Crypto++`: Dùng cho AES-GCM, SHA-256, PBKDF2, HKDF, Diffie-Hellman va random an toàn
- `nlohmann/json`: Đọc, ghi và chia sẻ dữ liệu JSON
- `Windows API`: dùng `SetConsoleOutputCP` để hiển thị console tốt hơn trên Windows
- `g++ / MinGW`: Môi trường biên dịch
- `PowerShell`: Dùng để buil nhanh thông qua script `build.ps1`
- `VS Code Tasks`: Build nhanh từ `.vscode/tasks.json`

## Cấu trúc source

- `src/main.cpp`: Project
- `src/app.cpp`, `src/app.hpp`: Điều phối menu và vòng lặp chính
- `src/client.cpp`, `src/client.hpp`: logic phía client, keystore, chia sẻ va truy cập ghi chú
- `src/server.cpp`, `src/server.hpp`: logic phía server, user, ghi chú, share token và mailbox
- `src/crypto_utils.cpp`, `src/crypto_utils.hpp`: hàm tiện ích cho crypto, JSON và file
- `src/console_ui.cpp`: hiển thị giao diện console
- `deps/cryptopp`: mã nguồn Crypto++ được dùng trực tiếp khi build
- `deps/json`: thư viện `nlohmann/json`
- `build.ps1`: script build tự động cho cấu trúc project hiện tại

## Dữ liệu sinh ra khi chạy Project

Project có thể tạo các file sau trong thư mục gốc:

- `users.json`
- `notes.json`
- `tokens.json`
- `pubkeys.json`
- `dh_params.json`
- `keystore_<username>.enc`
- `inbox_<username>.json`

## Yâu cầu môi trường

- Windows
- `g++` hỗ trợ `C++17`
- PowerShell
- Có sẵn các thư mục dependency:
  - `deps/cryptopp`
  - `deps/json`

## Cách build

Cách đơn giản nhất:

```powershell
.\build.ps1
```
## Cách chạy

Sau khi build xong:

```powershell
.\project2.exe
```

## Luồng sử dụng cơ bản

1. Đăng ký tài khoản mới
2. Đăng nhập
3. Tạo ghi chú text hoặc tải ghi chú từ file
4. Liệt kê và đọc ghi chú của mình
5. Chia sẻ ghi chú bằng URL hoặc End-to-End
6. Nhấn vào hộp thư hoặc mở link để đọc nội dung

## Ghi chú bảo mật

- Ghi chú được mã hóa trước khi lưu
- Khóa ghi chú được giữ ở phias client
- Keystore cục bộ được mã hóa bằng khóa dẫn xuất từ mật khẩu
- Link chia sẻ có thể có hạn dùng, giới hạn số lần truy cập và PIN
- Phiên đăng nhập hiện tại dùng token ngẫu nhiên lưu trong bộ nhớ server thay vì JWT
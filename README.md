# 🎭 GhostProfile PRO MAX — Trình Quản Lý Đa Tài Khoản & Chống Vân Tay Trình Duyệt (Anti-Detect Browser Manager)

Công cụ tạo và vận hành **hàng chục Profile trình duyệt Chrome/Edge cô lập 100%** ngay trên máy tính (tương tự **Hidemyacc / GoLogin / Multilogin** chạy Local), tích hợp **12 lớp giả lập vân tay phần cứng qua giao thức CDP**, **Bộ tạo mã 2FA TOTP trực tiếp**, **Cookie Robot nuôi nick tự động** và **Phòng thí nghiệm kiểm chứng chống trùng lặp vân tay (`/lab/fingerprint`)**.

---

## 🚀 Cách khởi động nhanh (1-Click)

Nháy đúp vào file **[start.bat](file:///d:/AI_App/anti-detect-browser/start.bat)** hoặc chạy lệnh:

```powershell
cd d:\AI_App\anti-detect-browser
node server.js
```

- **Giao diện Quản lý**: `http://localhost:4120`
- **Phòng Lab Kiểm Chứng Vân Tay**: `http://localhost:4120/lab/fingerprint`

---

## 🔥 8 Vũ Khí Trọng Tâm (Bản PRO MAX)

### 1. 🛡️ Động Cơ Giả Lập 12 Lớp Vân Tay Phần Cứng (`12-Layer Hardware Anti-Detect`)
Mỗi Profile sở hữu một bộ hạt giống nhiễu phần cứng (`Seeds`) cố định và duy nhất:
1. **Ẩn danh Chống Bot (`navigator.webdriver = false`)**: Xóa sạch dấu vết điều khiển tự động của Chromium.
2. **Nhiễu Độc Nhất Canvas 2D (`Canvas Noise Seed`)**: Can thiệp vi sai mức pixel vào `getImageData` & `toDataURL`. Hình ảnh hiển thị trên màn hình giữ nguyên 100% nhưng mã băm `SHA-256` của mỗi Profile khác nhau hoàn toàn và không bao giờ thay đổi qua các lần mở lại.
3. **Giả Lập Card Đồ Họa WebGL (`UNMASKED_VENDOR_WEBGL` & `UNMASKED_RENDERER_WEBGL`)**: Đồng bộ chặt chẽ theo Hệ điều hành (*Apple Metal M1/M2/M3 Max* cho macOS, *NVIDIA RTX 4080 / 4070 / AMD RX 7800 XT Direct3D11* cho Windows).
4. **Nhiễu Sóng Âm `AudioContext`**: Tạo mã băm `OfflineAudioContext` riêng biệt cho từng Profile.
5. **Nhiễu Khung DOM `ClientRects`**: Dịch chuyển vi điểm `getBoundingClientRect` (`10^-5 px`) chống định danh bố cục font chữ.
6. **Khóa Chặn Rò Rỉ IP Thật Qua `WebRTC`**: Kết hợp cờ nhân Chromium `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` và khóa `RTCPeerConnection`.
7. **Đồng Bộ Địa Lý (`Timezone`, `Locale`, `Languages`, `GPS Geolocation`)**: Ép múi giờ hệ thống (`Emulation.setTimezoneOverride`) và tọa độ GPS khớp với quốc gia của Proxy (`VN`, `US`, `UK`, `SG`, `JP`).
8. **Giả Lập `Navigator`, `Sec-CH-UA Client Hints`, `Screen Resolution`, `MediaDevices ID` và `Battery API`**.

### 2. 🔐 Kho Tài Khoản & Bộ Sinh Mã 2FA TOTP Trực Tiếp (RFC 6238) + 1-Click Auto-Fill
- Lưu trữ `Username/Email`, `Password` và khóa bí mật `2FA Secret (Base32)` ngay trong từng Profile.
- Tự động tính toán và hiển thị **mã 2FA 6 số thời gian thực** (cập nhật mỗi 30 giây) ngay trên thẻ Profile.
- Bấm **`🔑 Auto-Fill 2FA`** để tự động điền Username, Password và mã 2FA mới nhất vào trang đăng nhập trong trình duyệt đang mở.

### 3. 🤖 Cookie Robot & Account Warmer (Trình Nuôi Nick Tự Động)
- Bấm **`🤖 Nuôi Cookie`** trên bất kỳ Profile nào để khởi chạy kịch bản duyệt web tự động qua chuỗi trang (`Search Engine` ➔ `News Portal` ➔ `E-Commerce Marketplace`), tự động cuộn trang giống người thật, tích lũy Cookie độ tin cậy cao (`Trust Score A+`), tự động điền 2FA và chụp ảnh nghiệm thu.

### 4. 🌐 Kiểm Tra Proxy & Tự Động Đồng Bộ Địa Lý (`Check Proxy & Geo-Sync`)
- Bấm **`🌐 Check Proxy`** để đo độ trễ kết nối (`ms`) và tự động đồng bộ Múi giờ, Ngôn ngữ, Tọa độ GPS theo quốc gia của Proxy.

### 5. 🖥️ Mở Cửa Sổ Trình Duyệt Cô Lập Thực Tế & Lưu Phiên Vĩnh Viễn
- Bấm **`🚀 Mở Trình Duyệt`** trên bất kỳ Profile nào để mở cửa sổ Chrome/Edge thật với thư mục dữ liệu riêng tại `data/profiles/<id>/`.
- Mọi Cookie, LocalStorage, IndexedDB đều được giữ nguyên cho lần mở sau và **không bao giờ rò rỉ sang Profile khác**.

### 6. 🔬 Phòng Thí Nghiệm Kiểm Chứng Vân Tay & ⚖️ Ma Trận Đối Chiếu Đa Profile
- Bấm **`🔬 Quét Vân Tay`** trên từng Profile hoặc chuyển sang tab **`⚖️ Ma Trận Đối Chiếu Chống Trùng Vân Tay`** để chạy kiểm chứng tự động nhiều Profile cùng lúc và đối chiếu bảng so sánh `Canvas Hash`, `Audio Hash`, `WebGL GPU`, `ClientRects Hash`, `MediaDevices Hash` kèm ảnh chụp màn hình thực tế.

### 7. 🏭 Xưởng Tạo Profile Hàng Loạt (`Bulk Profile Factory`)
- Tạo nhanh từ **1 đến 30 Profile** chỉ với 1 cú nhấp chuột, tự động phân bổ hệ điều hành (`Windows 11` / `macOS Sonoma`), quốc gia, tài khoản + khóa 2FA và tự động gắn danh sách Proxy (`host:port:user:pass`) vào từng Profile.

### 8. 🍪 Kho Quản Lý Cookie & Đồng Bộ 1-Click Sang NetPulse (`4080`)
- Xem, nạp (`Import JSON`), xóa Cookie trực tiếp trong từng Profile và bấm **`🔗 Đồng Bộ Sang NetPulse (4080)`** để đẩy Cookie + User-Agent của Profile sang công cụ kiểm thử API.

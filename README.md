Dưới đây là bài báo cáo hoàn chỉnh để bạn nộp.

# Báo cáo phân tích rủi ro và chiến lược bảo vệ Refresh Token

## 1. Mở đầu

Trong hệ thống xác thực hiện đại, đặc biệt là các ứng dụng tài chính ngân hàng, Access Token và Refresh Token thường được sử dụng để quản lý phiên đăng nhập của người dùng. Access Token thường có thời gian sống ngắn và được dùng để truy cập tài nguyên. Refresh Token có thời gian sống dài hơn, dùng để cấp lại Access Token mới khi Access Token hết hạn.

Refresh Token giúp cải thiện trải nghiệm người dùng vì người dùng không cần đăng nhập lại liên tục. Tuy nhiên, chính vì có thời gian sống dài nên Refresh Token trở thành mục tiêu nguy hiểm nếu bị đánh cắp. Khi kẻ tấn công sở hữu Refresh Token hợp lệ, họ có thể liên tục yêu cầu hệ thống cấp Access Token mới và duy trì quyền truy cập trái phép trong thời gian dài.

Theo OAuth 2.0 Security Best Current Practice, Refresh Token cho public client cần được bảo vệ bằng cơ chế sender-constrained token hoặc refresh token rotation. Điều này cho thấy Refresh Token là thành phần có rủi ro cao và cần có chiến lược bảo vệ nghiêm ngặt. ([IETF Datatracker][1])

---

## 2. Phần 1 - Phân tích logic

## 2.1. Các kịch bản Refresh Token bị đánh cắp hoặc lạm dụng

### Kịch bản 1: Tấn công Cross-Site Scripting, XSS

XSS xảy ra khi ứng dụng web có lỗ hổng cho phép kẻ tấn công chèn mã JavaScript độc hại vào trang web. Nếu Refresh Token được lưu trong LocalStorage hoặc SessionStorage, JavaScript độc hại có thể đọc token và gửi về máy chủ của kẻ tấn công.

Ví dụ:

Người dùng đăng nhập vào ứng dụng ngân hàng. Refresh Token được lưu trong LocalStorage. Một chức năng bình luận, tìm kiếm hoặc hiển thị thông tin người dùng không xử lý dữ liệu đầu vào đúng cách. Kẻ tấn công chèn đoạn mã JavaScript độc hại. Khi người dùng truy cập trang, đoạn mã này chạy trong trình duyệt và đọc Refresh Token từ LocalStorage.

Hậu quả là kẻ tấn công có Refresh Token và có thể gửi request đến endpoint `/auth/refresh-token` để lấy Access Token mới.

OWASP khuyến nghị không nên lưu thông tin nhạy cảm trong LocalStorage vì dữ liệu trong đó có thể bị truy cập nếu môi trường trình duyệt hoặc mã JavaScript bị xâm phạm. ([OWASP Cheat Sheet Series][2])

---

### Kịch bản 2: Lưu trữ Refresh Token không an toàn trên client

Một lỗi phổ biến là lưu Refresh Token trực tiếp ở LocalStorage, SessionStorage hoặc cookie không cấu hình bảo mật.

So sánh rủi ro:

| Cách lưu trữ                    | Rủi ro chính                                                                 |
| ------------------------------- | ---------------------------------------------------------------------------- |
| LocalStorage                    | JavaScript có thể đọc được, dễ bị đánh cắp khi có XSS                        |
| SessionStorage                  | Ít tồn tại lâu hơn LocalStorage nhưng vẫn bị JavaScript đọc được             |
| Cookie thường                   | Có thể bị gửi tự động trong request, dễ gặp CSRF nếu không cấu hình SameSite |
| HttpOnly Secure SameSite Cookie | An toàn hơn vì JavaScript không đọc được trực tiếp                           |

Nếu Refresh Token được lưu ở LocalStorage, chỉ cần một lỗ hổng XSS nhỏ cũng có thể khiến token bị lộ. Nếu cookie không có `HttpOnly`, JavaScript vẫn có thể đọc được. Nếu cookie không có `Secure`, token có thể bị gửi qua kết nối không an toàn. MDN khuyến nghị cookie nhạy cảm nên có các thuộc tính như `Secure`, `HttpOnly`, `SameSite` và có thể dùng prefix như `__Host-` để giảm rủi ro cấu hình sai. ([MDN Web Docs][3])

---

### Kịch bản 3: Tấn công Man-in-the-Middle, MITM

MITM xảy ra khi kẻ tấn công đứng giữa người dùng và máy chủ để nghe lén hoặc thay đổi dữ liệu truyền tải. Nếu hệ thống không bắt buộc HTTPS, cấu hình TLS yếu, hoặc người dùng bị chuyển hướng đến kết nối không an toàn, Refresh Token có thể bị lộ trong quá trình truyền.

Ví dụ:

Người dùng sử dụng Wi-Fi công cộng. Ứng dụng gọi API refresh token qua HTTP hoặc HTTPS cấu hình yếu. Kẻ tấn công chặn gói tin và lấy Refresh Token trong request. Sau đó, kẻ tấn công sử dụng token này để lấy Access Token mới.

Đối với ứng dụng tài chính ngân hàng, đây là rủi ro nghiêm trọng vì kẻ tấn công có thể truy cập thông tin tài khoản, lịch sử giao dịch hoặc thực hiện các hành động trái phép nếu không có lớp bảo vệ bổ sung.

---

### Kịch bản 4: Refresh Token bị lộ qua log, lỗi hệ thống hoặc công cụ debug

Refresh Token cũng có thể bị lộ do lập trình viên vô tình ghi token vào log server, log client, công cụ monitoring, console trình duyệt hoặc message lỗi.

Ví dụ:

Backend ghi log toàn bộ request body khi người dùng gọi API `/auth/refresh-token`. Trong request body có Refresh Token. Nếu log bị truy cập trái phép hoặc gửi lên hệ thống logging bên thứ ba không an toàn, token có thể bị lộ.

Đây là lỗi thường gặp trong môi trường phát triển và kiểm thử, nhưng nếu không kiểm soát tốt, nó có thể xuất hiện cả trong môi trường production.

---

### Kịch bản 5: Thiết bị người dùng bị nhiễm mã độc hoặc extension độc hại

Nếu máy tính hoặc trình duyệt của người dùng bị nhiễm mã độc, hoặc người dùng cài extension độc hại, Refresh Token có thể bị đánh cắp từ bộ nhớ trình duyệt, cookie hoặc request gửi đi.

Kịch bản này khó kiểm soát hoàn toàn từ phía hệ thống, nhưng hệ thống vẫn có thể giảm thiểu rủi ro bằng cách phát hiện hành vi bất thường, ràng buộc thiết bị, giới hạn phiên đăng nhập và yêu cầu xác thực lại khi phát hiện nguy cơ.

---

## 2.2. Hậu quả khi Refresh Token bị lộ

### 1. Kẻ tấn công duy trì phiên đăng nhập lâu dài

Access Token thường có thời gian sống ngắn, ví dụ 5 đến 15 phút. Tuy nhiên, nếu kẻ tấn công có Refresh Token, họ có thể liên tục xin Access Token mới. Điều này khiến việc Access Token hết hạn gần như không còn ý nghĩa bảo vệ.

Kẻ tấn công không cần biết mật khẩu của người dùng. Chỉ cần Refresh Token còn hiệu lực, họ vẫn có thể duy trì quyền truy cập.

---

### 2. Chiếm quyền tài khoản người dùng

Trong ứng dụng tài chính ngân hàng, việc chiếm quyền tài khoản có thể dẫn đến các hậu quả nghiêm trọng:

- Xem thông tin cá nhân.
- Xem số dư tài khoản.
- Xem lịch sử giao dịch.
- Thay đổi thông tin tài khoản.
- Thực hiện hành động trái phép nếu hệ thống không có xác thực bổ sung.
- Đăng xuất người dùng thật hoặc thay đổi thiết bị đăng nhập.

---

### 3. Vượt qua cơ chế hết hạn của Access Token

Access Token ngắn hạn chỉ hiệu quả khi Refresh Token được bảo vệ tốt. Nếu Refresh Token bị lộ, kẻ tấn công có thể tạo Access Token mới mà không cần đăng nhập lại.

Điều này làm suy yếu toàn bộ kiến trúc xác thực. Hệ thống tưởng rằng Access Token hết hạn sẽ giảm rủi ro, nhưng thực tế kẻ tấn công vẫn có thể tiếp tục truy cập thông qua Refresh Token.

---

### 4. Khó phát hiện tấn công

Nếu kẻ tấn công sử dụng Refresh Token giống như người dùng thật, hệ thống có thể khó phát hiện. Đặc biệt nếu hệ thống không lưu thông tin thiết bị, IP, vị trí địa lý, User-Agent hoặc lịch sử sử dụng token.

Ví dụ:

Người dùng thật ở Việt Nam, nhưng Refresh Token lại được sử dụng từ một quốc gia khác chỉ sau vài phút. Nếu hệ thống không kiểm tra bất thường, request này vẫn có thể được chấp nhận.

---

### 5. Gây thiệt hại tài chính và mất uy tín

Với ứng dụng ngân hàng, hậu quả không chỉ là mất dữ liệu mà còn có thể gây thiệt hại tài chính. Người dùng mất niềm tin vào hệ thống. Doanh nghiệp có thể bị ảnh hưởng uy tín, phải xử lý khiếu nại, điều tra sự cố và nâng cấp hệ thống khẩn cấp.

---

## 2.3. Đánh giá cơ chế Revoke Token hiện tại

Cơ chế Revoke Token là việc thu hồi token để token đó không còn được sử dụng nữa. Ví dụ, khi người dùng đăng xuất, hệ thống xóa hoặc đánh dấu Refresh Token là đã bị thu hồi trong database.

### Ưu điểm của Revoke Token

Revoke Token có một số lợi ích:

- Cho phép người dùng đăng xuất khỏi hệ thống.
- Có thể thu hồi phiên đăng nhập khi phát hiện rủi ro.
- Hạn chế việc Refresh Token tiếp tục được sử dụng sau khi người dùng đổi mật khẩu.
- Hỗ trợ quản lý nhiều thiết bị đăng nhập.
- Cho phép admin khóa phiên đăng nhập khi tài khoản có dấu hiệu bị xâm phạm.

### Hạn chế của Revoke Token

Tuy nhiên, Revoke Token chưa đủ mạnh nếu sử dụng đơn lẻ.

#### Hạn chế 1: Phản ứng bị động

Revoke Token thường chỉ hoạt động sau khi hệ thống hoặc người dùng biết có sự cố. Nếu Refresh Token bị đánh cắp nhưng chưa bị phát hiện, kẻ tấn công vẫn có thể sử dụng nó bình thường.

#### Hạn chế 2: Kẻ tấn công có thể đổi token trước khi token cũ bị thu hồi

Một tình huống nguy hiểm là kẻ tấn công đánh cắp Refresh Token và nhanh chóng gọi API refresh. Nếu hệ thống cấp Refresh Token mới nhưng không kiểm soát chuỗi token, kẻ tấn công có thể sở hữu Refresh Token mới trước khi token ban đầu bị revoke.

Ví dụ:

1. Người dùng có Refresh Token A.
2. Kẻ tấn công đánh cắp Refresh Token A.
3. Kẻ tấn công dùng Refresh Token A để lấy Access Token mới và Refresh Token B.
4. Hệ thống hoặc người dùng revoke Refresh Token A.
5. Nhưng kẻ tấn công vẫn có Refresh Token B.

Trong trường hợp này, revoke token cũ không giải quyết triệt để vấn đề.

#### Hạn chế 3: Không phát hiện được reuse token

Nếu hệ thống không dùng Refresh Token Rotation, việc một Refresh Token được dùng nhiều lần có thể không bị coi là bất thường. Điều này tạo cơ hội cho cả người dùng thật và kẻ tấn công cùng sử dụng một token.

#### Hạn chế 4: Không tự động đánh giá ngữ cảnh

Revoke Token chỉ là hành động thu hồi. Nó không tự động phân tích:

- IP có bất thường không.
- Thiết bị có thay đổi không.
- Vị trí đăng nhập có hợp lý không.
- Tần suất refresh token có bất thường không.
- Token có bị dùng lại sau khi đã rotate không.

Do đó, nếu không kết hợp với logging, monitoring và phát hiện bất thường, revoke token chỉ là lớp bảo vệ cơ bản.

---

## 2.4. Đề xuất chiến lược bảo vệ Refresh Token nâng cao

## Chiến lược 1: Lưu Refresh Token bằng HttpOnly Secure SameSite Cookie

Refresh Token không nên lưu trong LocalStorage vì LocalStorage có thể bị JavaScript đọc nếu ứng dụng bị XSS. Thay vào đó, nên lưu Refresh Token trong cookie có cấu hình bảo mật:

```text
HttpOnly
Secure
SameSite=Strict hoặc SameSite=Lax
Path=/auth/refresh-token
__Host- prefix nếu phù hợp
```

Ý nghĩa:

- `HttpOnly`: JavaScript không thể đọc cookie, giảm rủi ro bị đánh cắp qua XSS.
- `Secure`: cookie chỉ được gửi qua HTTPS.
- `SameSite=Strict` hoặc `Lax`: giảm rủi ro CSRF.
- `Path=/auth/refresh-token`: chỉ gửi cookie đến endpoint cần dùng.
- `__Host-`: giúp cookie bị ràng buộc chặt hơn với host hiện tại.

MDN khuyến nghị cookie nhạy cảm nên bật `Secure` và `HttpOnly`, đồng thời cấu hình `SameSite` phù hợp để giảm rủi ro bảo mật. ([MDN Web Docs][3])

Tuy nhiên, khi dùng cookie, hệ thống cần chú ý chống CSRF. Có thể kết hợp thêm CSRF token hoặc chỉ cho phép request refresh token qua endpoint cụ thể với kiểm tra Origin/Referer.

---

## Chiến lược 2: Refresh Token Rotation

Refresh Token Rotation là cơ chế mỗi lần client dùng Refresh Token để lấy Access Token mới, server sẽ cấp luôn một Refresh Token mới và vô hiệu hóa Refresh Token cũ.

Luồng xử lý:

1. Người dùng đăng nhập, server cấp Access Token A và Refresh Token R1.
2. Access Token A hết hạn.
3. Client gửi Refresh Token R1 để xin token mới.
4. Server kiểm tra R1 hợp lệ.
5. Server cấp Access Token B và Refresh Token R2.
6. Server đánh dấu R1 đã sử dụng hoặc đã bị thay thế.
7. Nếu R1 bị dùng lại lần nữa, hệ thống coi đây là dấu hiệu token bị lộ.

Auth0 mô tả Refresh Token Rotation là kỹ thuật cấp token mới bằng Refresh Token theo cách an toàn hơn so với cơ chế refresh truyền thống. ([Auth0][4])

Cơ chế này giúp phát hiện trường hợp token bị đánh cắp. Nếu người dùng thật đã đổi R1 sang R2, nhưng kẻ tấn công sau đó dùng lại R1, hệ thống có thể phát hiện token reuse và thu hồi toàn bộ token trong cùng một token family.

Đề xuất xử lý khi phát hiện reuse:

- Thu hồi toàn bộ Refresh Token thuộc cùng phiên đăng nhập.
- Đăng xuất người dùng khỏi thiết bị nghi ngờ.
- Gửi cảnh báo bảo mật cho người dùng.
- Yêu cầu đăng nhập lại.
- Nếu là tài khoản ngân hàng, yêu cầu xác thực đa yếu tố.

---

## Chiến lược 3: Bảo vệ truyền tải bằng HTTPS, TLS và HSTS

Refresh Token chỉ được truyền qua kết nối HTTPS. Hệ thống cần:

- Bắt buộc HTTPS trên toàn bộ website và API.
- Bật HSTS để trình duyệt luôn dùng HTTPS.
- Không gửi token qua URL query string.
- Không ghi token vào log.
- Không cho phép mixed content.
- Cấu hình TLS phiên bản an toàn.
- Chặn request đến từ Origin không hợp lệ.

Không nên gửi Refresh Token trong URL như:

```text
/auth/refresh?token=abcxyz
```

Vì URL có thể bị lưu trong browser history, log server, proxy log hoặc analytics tool.

Cách tốt hơn là gửi Refresh Token thông qua HttpOnly Cookie hoặc request body trong kết nối HTTPS, tùy kiến trúc hệ thống.

---

## Chiến lược 4: Ràng buộc Refresh Token với thiết bị, IP hoặc User-Agent

Server nên lưu thêm metadata khi phát hành Refresh Token:

- User ID.
- Device ID.
- User-Agent.
- IP đăng nhập.
- Thời gian cấp.
- Thời gian hết hạn.
- Thời gian sử dụng gần nhất.
- Token family ID.
- Trạng thái token: active, used, revoked, expired.

Khi client dùng Refresh Token, server kiểm tra ngữ cảnh:

- IP có thay đổi bất thường không.
- Thiết bị có giống lần đăng nhập trước không.
- User-Agent có thay đổi đột ngột không.
- Vị trí địa lý có bất thường không.
- Token có bị dùng quá nhiều lần trong thời gian ngắn không.

Ví dụ:

Nếu người dùng thường đăng nhập từ Việt Nam, nhưng Refresh Token được dùng từ quốc gia khác chỉ sau 5 phút, hệ thống nên yêu cầu xác thực lại hoặc khóa phiên tạm thời.

Không nên dùng IP whitelisting quá cứng nhắc cho người dùng phổ thông vì IP có thể thay đổi khi dùng 4G, Wi-Fi công cộng hoặc VPN. Với hệ thống nội bộ hoặc admin banking, IP whitelist có thể áp dụng nghiêm ngặt hơn.

---

## Chiến lược 5: Phát hiện hành vi bất thường và cảnh báo bảo mật

Hệ thống cần có cơ chế giám sát Refresh Token:

- Một Refresh Token bị dùng lại sau khi đã rotate.
- Một tài khoản refresh token từ nhiều IP khác nhau trong thời gian ngắn.
- Một thiết bị lạ liên tục xin Access Token.
- Refresh Token được dùng vào thời điểm bất thường.
- Nhiều lần refresh thất bại.
- Một token đã revoke nhưng vẫn tiếp tục được gửi lên.

Khi phát hiện bất thường, hệ thống có thể:

- Thu hồi phiên hiện tại.
- Thu hồi toàn bộ phiên của tài khoản.
- Yêu cầu đăng nhập lại.
- Yêu cầu xác thực MFA.
- Gửi email hoặc thông báo trong ứng dụng.
- Tạm khóa chức năng nhạy cảm như chuyển tiền, đổi mật khẩu, đổi số điện thoại.

---

## Chiến lược 6: Giới hạn thời gian sống và phạm vi sử dụng của Refresh Token

Refresh Token không nên có thời gian sống quá dài. Có thể áp dụng hai loại thời hạn:

### Thời hạn tuyệt đối

Ví dụ: Refresh Token hết hạn hoàn toàn sau 7 ngày, 15 ngày hoặc 30 ngày, dù người dùng vẫn hoạt động.

### Thời hạn trượt

Ví dụ: Nếu người dùng còn hoạt động, token có thể được gia hạn, nhưng không vượt quá thời hạn tuyệt đối.

Đối với ứng dụng tài chính ngân hàng, nên yêu cầu đăng nhập lại hoặc xác thực lại định kỳ, đặc biệt trước các thao tác nhạy cảm.

---

## Chiến lược 7: Mã hóa hoặc băm Refresh Token trong database

Server không nên lưu Refresh Token dạng plain text trong database. Thay vào đó, nên lưu giá trị đã hash của Refresh Token.

Luồng xử lý:

1. Server tạo Refresh Token ngẫu nhiên đủ mạnh.
2. Server gửi token gốc cho client.
3. Server hash token và lưu vào database.
4. Khi client gửi Refresh Token, server hash lại token nhận được.
5. So sánh hash với dữ liệu trong database.

Lợi ích:

Nếu database bị lộ, kẻ tấn công không lấy được Refresh Token gốc để sử dụng ngay.

---

## Chiến lược 8: Kết hợp MFA cho hành động nhạy cảm

Ngay cả khi kẻ tấn công có Refresh Token và lấy được Access Token, hệ thống vẫn nên yêu cầu xác thực bổ sung cho các hành động quan trọng:

- Chuyển tiền.
- Đổi mật khẩu.
- Thay đổi email.
- Thay đổi số điện thoại.
- Thêm tài khoản nhận tiền.
- Xem thông tin nhạy cảm.

Điều này giúp giảm thiệt hại nếu token bị đánh cắp.

---

# 3. Kiến trúc đề xuất cho hệ thống thực tế

## 3.1. Luồng đăng nhập

1. Người dùng gửi email và mật khẩu.
2. Server xác thực thông tin.
3. Nếu hợp lệ, server cấp:
   - Access Token thời gian sống ngắn, ví dụ 5–15 phút.
   - Refresh Token thời gian sống dài hơn, ví dụ 7–30 ngày.

4. Refresh Token được lưu trong HttpOnly Secure SameSite Cookie.
5. Server lưu hash Refresh Token trong database cùng metadata thiết bị.

---

## 3.2. Luồng refresh token an toàn

1. Client gọi API `/auth/refresh-token`.
2. Browser tự gửi Refresh Token qua HttpOnly Cookie.
3. Server kiểm tra:
   - Token có tồn tại không.
   - Token có hết hạn không.
   - Token có bị revoke không.
   - Token có bị dùng lại không.
   - Thiết bị, IP, User-Agent có bất thường không.

4. Nếu hợp lệ:
   - Cấp Access Token mới.
   - Cấp Refresh Token mới.
   - Vô hiệu hóa Refresh Token cũ.

5. Nếu phát hiện reuse:
   - Thu hồi toàn bộ token family.
   - Gửi cảnh báo.
   - Yêu cầu đăng nhập lại.

---

## 3.3. Luồng đăng xuất

1. Người dùng bấm đăng xuất.
2. Server revoke Refresh Token hiện tại.
3. Server xóa cookie Refresh Token.
4. Access Token phía client bị xóa khỏi bộ nhớ.
5. Nếu người dùng chọn “đăng xuất khỏi tất cả thiết bị”, server revoke toàn bộ Refresh Token của user.

---

# 4. Bảng tổng hợp rủi ro và biện pháp bảo vệ

| Rủi ro                 | Hậu quả                                       | Biện pháp bảo vệ                                                              |
| ---------------------- | --------------------------------------------- | ----------------------------------------------------------------------------- |
| XSS đánh cắp token     | Kẻ tấn công lấy Refresh Token từ LocalStorage | Không lưu token trong LocalStorage, dùng HttpOnly Cookie, CSP, validate input |
| MITM                   | Token bị nghe lén khi truyền tải              | Bắt buộc HTTPS, TLS mạnh, HSTS                                                |
| Token bị dùng lại      | Kẻ tấn công duy trì phiên trái phép           | Refresh Token Rotation, phát hiện reuse                                       |
| Token bị lộ trong log  | Người có quyền xem log lấy được token         | Không log token, mask dữ liệu nhạy cảm                                        |
| Database bị lộ         | Token bị lấy trực tiếp từ DB                  | Lưu hash Refresh Token                                                        |
| Thiết bị lạ dùng token | Chiếm quyền tài khoản                         | Theo dõi IP, User-Agent, Device ID, cảnh báo bất thường                       |
| CSRF khi dùng cookie   | Request refresh bị lợi dụng                   | SameSite, CSRF token, kiểm tra Origin/Referer                                 |

---

# 5. Kết luận

Refresh Token là thành phần quan trọng trong hệ thống xác thực vì nó giúp người dùng duy trì phiên đăng nhập thuận tiện. Tuy nhiên, trong ứng dụng tài chính ngân hàng, Refresh Token cũng là mục tiêu tấn công rất nguy hiểm do có thời gian sống dài và có khả năng cấp lại Access Token.

Cơ chế Revoke Token là cần thiết nhưng chưa đủ. Nếu chỉ dựa vào revoke token, hệ thống sẽ phản ứng chậm và có thể không xử lý được trường hợp kẻ tấn công đã đổi Refresh Token cũ lấy Refresh Token mới. Vì vậy, hệ thống cần kết hợp nhiều lớp bảo vệ như HttpOnly Secure SameSite Cookie, HTTPS, Refresh Token Rotation, phát hiện reuse token, lưu hash token trong database, kiểm tra hành vi bất thường và yêu cầu MFA cho thao tác nhạy cảm.

Đối với môi trường sản phẩm thực tế, đặc biệt là ứng dụng ngân hàng, chiến lược phù hợp nhất là áp dụng bảo mật nhiều lớp. Không có một biện pháp đơn lẻ nào có thể bảo vệ tuyệt đối Refresh Token, nhưng khi kết hợp đúng cách, hệ thống có thể giảm mạnh nguy cơ bị chiếm quyền tài khoản và phản ứng nhanh khi có sự cố bảo mật.

[1]: https://datatracker.ietf.org/doc/rfc9700/?utm_source=chatgpt.com "RFC 9700 - Best Current Practice for OAuth 2.0 Security"
[2]: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html?utm_source=chatgpt.com "HTML5 Security - OWASP Cheat Sheet Series"
[3]: https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies?utm_source=chatgpt.com "Secure cookie configuration - MDN Web Docs"
[4]: https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation?utm_source=chatgpt.com "Refresh Token Rotation - Auth0 Docs"

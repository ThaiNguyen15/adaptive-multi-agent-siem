# Login Processing Mindset

File này ghi lại mindset xử lý dataset `login` theo hướng thầy yêu cầu:

- bắt đầu từ mục tiêu nghiệp vụ
- hiểu semantics từng trường
- xử lý riêng từng nhóm đặc trưng
- chống noise, scale lệch, và leakage trước khi nghĩ tới model

## 1. Goal First

Goal chính của domain này không phải chỉ là `predict success/failure`.

Goal đúng hơn là:

- phát hiện `abnormal login behavior`
- nhận ra thay đổi hành vi theo user
- hỗ trợ risk scoring hoặc anomaly detection

Điều này có nghĩa:

- `login_successful` không chỉ là label, mà còn là một phần của chuỗi hành vi
- giá trị của domain nằm ở pattern theo thời gian, không nằm ở từng record độc lập

## 2. Domain Semantics

Các trường hiện có trong [normalizer.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/login/normalizer.py#L1):

- `user_id`
- `ip`
- `country`
- `region`
- `city`
- `device`
- `login_timestamp`
- `login_successful`

Mindset cần giữ:

- `user_id` là trục chính để gom hành vi
- `ip`, `device`, `location` là dấu hiệu thay đổi ngữ cảnh
- `login_successful` là phản ứng của hệ thống sau hành vi
- giá trị nằm ở tương quan theo chuỗi, không nằm ở giá trị tuyệt đối từng field

## 3. Feature Groups Should Be Separated

Không nên coi tất cả field là một bảng flat rồi build feature đồng đều.

Nên tách thành các nhóm:

- `identity/history`: `user_id`
- `network context`: `ip`
- `geo context`: `country`, `region`, `city`
- `device context`: `device`
- `outcome`: `login_successful`
- `temporal behavior`: thời gian giữa lần login, mật độ, chu kỳ ngày/giờ

Giai đoạn preprocessing nên xử lý riêng từng nhóm rồi mới fusion.

## 4. What Matters More Than Current Code

Code hiện tại ở [feature_builder.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/login/feature_builder.py#L1) đã có:

- count
- success/failure rate
- unique IP/device/location
- entropy

Nhưng theo mindset của thầy, vẫn còn thiếu các lớp rất quan trọng:

- `delta time` giữa 2 login liên tiếp
- novelty feature: IP mới, device mới, location mới với từng user
- hierarchy location: country khác có ý nghĩa mạnh hơn city khác
- time-of-day / day-of-week behavior
- bins hoặc rank cho các count/rate lớn nhỏ khác nhau

## 5. Noise And Leakage Risks

Rủi ro chính của dataset login:

- ID-specific memorization: model nhớ user thay vì hiểu hành vi
- location granularity quá mịn: city có thể noisy
- class imbalance giữa success và failure
- split sai theo row thay vì theo thời gian

Mindset:

- time split là bắt buộc
- validation/test phải đủ failure cases
- feature mới nên ưu tiên loại ổn định qua user hơn là quá cụ thể

## 6. Numeric Handling

Count/rate feature có thể lệch range mạnh giữa user active và user ít hoạt động.

Nên bổ sung:

- `log1p` cho count lớn
- rank/bin cho login count
- `RobustScaler` hoặc `QuantileTransformer` ở downstream training
- feature theo nhiều resolution: ngắn hạn, trung hạn, dài hạn

## 7. Update Priorities For Code

Ưu tiên update code theo thứ tự:

1. Thêm novelty features theo user:
   - `is_new_ip`
   - `is_new_device`
   - `is_new_country`
   - `is_new_city`
2. Thêm temporal features:
   - `seconds_since_prev_login`
   - `hour_of_day`
   - `day_of_week`
   - `is_weekend`
3. Tách location thành nhiều resolution:
   - country
   - region
   - city
4. Thêm binned/ranked variants cho count features
5. Kiểm tra lại fill strategy cho rate features, tránh mặc định quá lạc quan

## 8. Prompt To Update This Domain

Use this prompt when updating the login domain:

```text
Refactor the login domain to follow an anomaly-detection mindset instead of a flat classification mindset.

Context:
- Dataset fields: user_id, ip, country, region, city, device, login_timestamp, login_successful
- Goal: detect abnormal login behavior per user, not just classify isolated rows
- Keep the existing normalize -> shard -> feature -> split architecture

Requirements:
- Preserve time-based splitting
- Keep user_id as the behavioral grouping key
- Add novelty features per user: new IP, new device, new country, new city
- Add temporal behavior features: seconds_since_prev_login, hour_of_day, day_of_week, weekend flag
- Separate location features by resolution instead of treating all location info as one flat field
- Add multi-resolution numeric handling where useful: raw count + log1p count + coarse bins
- Avoid features that simply memorize user identity without behavioral meaning
- Keep output training-friendly and deterministic

Deliverables:
- update config if needed
- update feature_builder.py
- keep normalizer.py simple and domain-correct
- explain leakage risks and any assumptions
```

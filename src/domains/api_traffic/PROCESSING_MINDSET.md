# API Traffic Processing Mindset

File này ghi lại mindset xử lý dataset `api_traffic` theo hướng thầy yêu cầu.

## 1. Goal First

Goal của domain này không phải đơn thuần là:

- học xem request nào có nhãn attack

Goal đúng hơn là:

- phát hiện `malicious request behavior`
- tách rõ attacker-controlled input khỏi system response
- kiểm tra leakage giữa request-side và response-side

Đây là domain mix data rõ nhất, nên mindset xử lý riêng từng nhóm là bắt buộc.

## 2. Domain Semantics

Code hiện tại đã đi đúng hướng khi tách:

- `request`
- `response`
- `combined`

trong [config.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/api_traffic/config.py#L1) và [feature_builder.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/api_traffic/feature_builder.py#L1).

Mindset nên giữ:

- request là nguồn tín hiệu chính cho security detection
- response là nguồn audit leakage
- combined chỉ là upper bound tham khảo, không nên mặc định xem là production-safe

## 3. Separate The Modalities

Theo note, data text và number không nên trộn thô.

Áp vào domain này, nên tách:

- `request lexical`
- `request token/stat`
- `response lexical`
- `response token/stat`
- `protocol/context metadata`

Sau đó mới fusion bằng lớp nhỏ hoặc downstream model.

## 4. Convert Random User-Controlled Text To More Stable Signals

Mindset của thầy rất hợp với security text:

- text do user định nghĩa chứa nhiều phần ngẫu nhiên
- cần mapping từ random sang static hơn

Áp vào request data:

- URL path segments nên có abstraction
- query values nên phân biệt key vs value
- body nên có pattern abstraction
- token nên tách:
  - syntax tokens
  - attack-pattern tokens
  - random literal tokens

Không nên chỉ giữ raw text dài rồi mong model tự hiểu hết.

## 5. Main Risk: Response Leakage

Domain này có nguy cơ leakage mạnh:

- status code
- error message
- body phản hồi

Nếu model thắng nhờ response thì nó đang học backend reaction, không hẳn học malicious intent.

Mindset:

- `request_only` là baseline chính
- `response_only` là leakage audit
- `combined` là upper bound tham khảo

## 6. Numeric And Text Need Different Handling

Các numeric/text feature không nên xử lý chung một kiểu.

Nên:

- request length, token count, special char count: có raw + log + bin
- status code: dùng semantic buckets
- token/value fields: chuẩn hóa trước khi vector hóa
- user-controlled literals: thay bằng abstract markers nếu có thể

## 7. What Current Domain Should Evolve Toward

Code hiện tại đã có:

- request-centric lexical features
- response leakage audit features
- token stats

Nhưng để đúng hơn theo mindset của thầy, nên bổ sung:

1. token abstraction tốt hơn cho path/query/body
2. tách key/value semantics rõ hơn
3. biến random literals thành stable categories
4. binned numeric features cho text-length stats
5. stricter controls để response features không vô tình đi vào main production baseline

## 8. Prompt To Update This Domain

```text
Refactor the api_traffic domain to follow a modality-aware security mindset instead of a flat text classification mindset.

Context:
- Goal: detect malicious request behavior while auditing response leakage
- Existing modes: request_only, response_only, combined
- Keep the existing normalize -> shard -> feature -> split architecture

Requirements:
- Preserve request-only as the primary production-oriented modeling view
- Keep response-only as a leakage-audit path, not the default production signal
- Improve request preprocessing by separating stable syntax from random user-controlled literals
- Add stronger abstraction for URL path segments, query values, and request body fragments where possible
- Add multi-resolution handling for numeric text stats: raw, log1p, and coarse bins
- Keep request/response modalities explicitly separated before any combined fusion
- Document which features are attacker-controlled, backend-controlled, or leakage-prone

Deliverables:
- update feature_builder.py with better abstraction-aware request features
- update config if additional feature modes or toggles are needed
- preserve current compatibility for request_only / response_only / combined experiments
```

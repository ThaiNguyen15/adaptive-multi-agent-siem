## API Traffic Preprocessing Review Note

Mục đích file này là để thầy review nhanh xem hướng preprocess domain `api_traffic` đã đúng chưa.

## 1. Goal

- phát hiện `malicious request behavior`
- ưu tiên học từ `request`, không để model phụ thuộc vào `response`
- giảm noise từ raw HTTP text trước khi đưa vào NLP/model
- gom request theo `endpoint` để so sánh đúng ngữ cảnh

## 2. Cách process đang đề xuất

Pipeline preprocess:

1. parse raw HTTP request thành:
   - `method`
   - `host`
   - `path`
   - `query`
   - `headers`
   - `body`
2. normalize:
   - URL decode
   - lowercase host + header names
   - decompress body nếu có `gzip/deflate/br`
   - trim / chuẩn hóa whitespace
3. filter headers theo whitelist:
   - chỉ giữ các header có ý nghĩa cho security/model
   - ví dụ: `host`, `content-type`, `user-agent`, `cookie`, `authorization`, `accept`
4. extract endpoint:
   - `endpoint = method + host + path`
   - nếu cần thì thêm bản template như `/users/{id}`
5. transform text thành model-ready representation:
   - query values -> token ổn định như `<int>`, `<uuid>`, `<url>`
   - body values -> abstraction token như `<email>`, `<script_pattern>`, `<sql_pattern>`
   - giữ keyword quan trọng của attack, không abstract mù

## 3. Vì sao cách này hợp lý

- `normalization` giúp các payload cùng nghĩa về cùng không gian token
  - ví dụ `select`, `SELECT`, `%53%45%4c%45%43%54` không nên thành 3 tín hiệu khác nhau
- `token abstraction` giúp model bớt học thuộc literal ngẫu nhiên
  - ví dụ id, uuid, email, timestamp nên map về type token
- `endpoint grouping` giúp anomaly detection đúng ngữ cảnh
  - request bình thường ở `/search` chưa chắc bình thường ở `/admin/import`
- `header whitelist` giúp giảm vocabulary noise từ infra headers

## 4. Output sau preprocess mong muốn

Một record sau preprocess nên có:

- `method`
- `host`
- `path`
- `query_string_normalized`
- `endpoint_key`
- `filtered_headers`
- `body_text_normalized`
- `request_text`
- `token_stream`

Ví dụ:

- raw:
  - `GET /search?q=%27%20UNION%20SELECT&page=1`
- sau preprocess:
  - `GET shop.example.com /search query:q=<sql_pattern> page=<int>`

## 5. Điểm em nghĩ là đúng

- request phải là nguồn tín hiệu chính
- response chỉ nên dùng để audit leakage hoặc làm upper-bound
- không nên nhét nguyên raw HTTP vào model
- path/query/body phải được tách riêng trước khi token hóa
- dynamic values nên được abstraction để tăng generalization

## 6. Điểm cần thầy confirm

Em muốn confirm 4 ý này:

1. preprocess nên lấy `endpoint = method + host + path` làm đơn vị gom nhóm, đúng không
2. query/body values có nên abstraction mạnh về type token như `<int>`, `<uuid>`, `<url>` không
3. header có nên đi theo whitelist-based filtering thay vì giữ toàn bộ không
4. response có nên tách hẳn khỏi baseline chính, chỉ dùng để audit leakage không

## 7. Kết luận ngắn

Hướng process hiện tại là:

- parse rõ từng phần của HTTP request
- normalize để giảm biến thể bề mặt
- filter bớt noise
- group theo endpoint
- abstract dynamic values trước khi NLP/model học

Nếu 4 điểm confirm phía trên là đúng, thì em sẽ bám hướng này để implement preprocess và feature extraction cho domain `api_traffic`.

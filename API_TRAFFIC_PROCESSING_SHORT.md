## 3.1 Goal

- phát hiện malicious request behavior
- tách rõ tín hiệu từ request và response
- kiểm tra leakage để tránh model học theo backend response

## 3.2 Gom nhóm dữ liệu

- `request lexical`: URL, path, query, method, body
- `request token/stat`: token count, special chars, signal score
- `response lexical`: status code, response body, content type
- `response token/stat`: response token count, response signal score
- `context`: host, event timestamp, modeling view

## 3.3 Cách process

Xử lý theo 4 nhóm chính:

- `request`: tín hiệu chính để detect hành vi tấn công
- `response`: chỉ dùng để audit leakage hoặc upper-bound
- `token/stat`: đo độ dài, độ phức tạp, mật độ pattern
- `context`: giữ metadata cần thiết nhưng không để lấn át request

## 3.4 Xử lý feature data

### 3.4.1 Number

Các cột number chính:

- `request_url_length`
- `request_body_length`
- `request_query_param_count`
- `request_signal_score`
- `response_signal_score`
- `request_token_count`
- `response_token_count`
- `combined_token_count`

Cách xử lý:

- `request-side number`: giữ raw + bin  
  Ví dụ trong [shard_000.parquet](/home/ad1/Project/adaptive-multi-agent-siem/data/processed/api_traffic/splits/train/shard_000.parquet), `request_url_length` nằm từ `22` đến `118`, còn `request_query_param_count` max chỉ `2`, nên đây là các feature nhỏ và tương đối ổn định.
- `response-side number`: phải xử lý cẩn thận vì rất dễ lệch  
  Cùng shard đó, `response_token_count` có median `14` nhưng max tới `26716`. Nếu dùng raw trực tiếp, model rất dễ học theo response size thay vì học malicious intent.
- `signal score`: giữ raw + coarse bins vì đây là score nhỏ, dễ diễn giải
- scaler downstream:
  - `RobustScaler` nếu response-side có outlier lớn
  - `QuantileTransformer` nếu muốn nén tail rất mạnh

### 3.4.2 Categorical

Các cột categorical chính:

- `method`
- `status_code`
- `host`
- `modeling_view`

Cách xử lý:

- `method`: category nhỏ, có thể encode trực tiếp
- `status_code`: không nên chỉ coi là number, mà nên gom theo semantic buckets như `2xx`, `3xx`, `4xx`, `5xx`
- `host`: thường ít giá trị, giữ như context metadata
- `modeling_view`: dùng để biết request_only/response_only/combined, không phải tín hiệu chính cho production model

### 3.4.3 Khi text và number đi cùng nhau

Prephase nên tách riêng:

- `request-text`
- `request-number`
- `response-text`
- `response-number`
- `context-categorical`

Sau đó mới xử lý:

- text -> abstraction / tokenization
- number -> log / bin / scale
- categorical -> semantic mapping
- cuối cùng mới nối các vector lại

Kết luận:

- `URL` không chỉ là text
- `status_code` không chỉ là số
- `response body` không phải lúc nào cũng là tín hiệu nên học

Mỗi trường phải được đổi về tín hiệu phù hợp với vai trò security của nó, và request phải luôn là nguồn tín hiệu chính.

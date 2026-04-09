# Data Processing Mindset For Security Domains

## 1. Mục tiêu của tài liệu

Tài liệu này chỉ tập trung vào `cách process data` cho 4 domain đã xử lý:

- login
- cicids2018
- brute_force_https
- api_traffic

Trọng tâm không phải là liệt kê thêm feature một cách chung chung, mà là:

- phải xác định mục tiêu nghiệp vụ trước
- phải gom nhóm đặc trưng theo đúng bản chất dữ liệu
- phải xử lý riêng từng nhóm trước khi trộn
- phải xử lý bài toán text, number, categorical theo các cách khác nhau
- phải xử lý scale, noise, imbalance, validation, leakage ngay từ bước preprocess

## 2. Triết lý tiếp cận chung

### 2.1 Goal first, không bắt đầu từ model

Quy trình đúng là:

`goal -> collect data -> process data -> embedding/vector -> model AI -> decision`

Nếu goal là phát hiện DDoS, brute-force hay abnormal login thì phần data cần giữ và phần data cần bỏ là khác nhau. Dataset có sẵn không có nghĩa là dùng nguyên xi; phải lọc lại phần nào thực sự có ích cho đúng domain goal.

### 2.2 Mutual resolution

Nhiều trường numeric có range rất rộng. Nếu chỉ giữ một dạng raw value thì:

- giá trị lớn sẽ lấn át giá trị nhỏ
- pattern nhỏ nhưng quan trọng sẽ bị chìm
- model chỉ học được phần nổi của phân phối

Vì vậy cần `multi-resolution`:

- raw value
- `log1p` value
- clipped value
- binned/ranked value

Ý tưởng là mỗi head hoặc mỗi nhánh downstream có thể nhìn dữ liệu ở một độ phân giải khác nhau.

### 2.3 Manifold processing

Không nên coi toàn bộ bảng dữ liệu là một khối đồng nhất rồi ném vào model.

Phải tách theo từng họ đặc trưng:

- temporal
- volume/count
- categorical/context
- text/sequence
- response/system output

Ở bước preprocess, mỗi nhóm cần được xử lý riêng. Sau đó mới trộn lại ở learning base bằng một lớp nhỏ hoặc một tầng fusion gọn.

### 2.4 Khi dữ liệu vừa có text vừa có number

Nếu trộn thô text và number ngay từ đầu, model sẽ học rất lệch.

Nên đi theo pipeline:

1. tách riêng từng trường
2. xử lý riêng từng loại dữ liệu
3. mapping thành token hoặc vector trung gian
4. trộn lại bằng small layer

Với `number`:

- scale
- bin
- rank
- log transform nếu lệch mạnh

Với `text`:

- tách phần ổn định và phần ngẫu nhiên
- mapping literal ngẫu nhiên về token ổn định hơn
- giữ syntax/pattern quan trọng

### 2.5 Nếu một cột số quá nhỏ hoặc quá lớn thì xử lý thế nào

Nếu range quá lớn hoặc quá mịn:

- model khó detect pattern nhỏ
- noise lớn làm tín hiệu nhỏ biến mất

Nên xử lý theo thứ tự:

1. kiểm tra phân phối
2. nếu lệch mạnh thì dùng `log1p`
3. nếu nhiều outlier thì dùng clipping theo quantile
4. nếu cần tính thứ bậc thì dùng `rank`
5. nếu cần đưa về dạng token thì dùng `binning`
6. downstream có thể dùng `RobustScaler` hoặc `QuantileTransformer`

Nguyên tắc:

- dữ liệu lệch mạnh: ưu tiên `RobustScaler`
- dữ liệu cần phân phối đều hơn: cân nhắc `QuantileTransformer`
- không mặc định scale 0-1 cho mọi trường, vì giá trị nhỏ có thể bị mất ý nghĩa

### 2.6 Validation, noise, imbalance

Nếu validation quá nhỏ:

- model không học được pattern đủ đa dạng

Nếu noise quá lớn:

- model chỉ detect được mẫu lớn, bỏ qua mẫu nhỏ nhưng quan trọng

Nếu split sai:

- test cao nhưng validation thấp
- hoặc model học shortcut thay vì học xu hướng chung

Vì vậy preprocess phải lo:

- split đủ đại diện
- chống leakage
- kiểm soát imbalance
- giảm noise trước khi chỉnh model

## 3. Khung process chung cho các domain

### 3.1 Prephase

Trước khi build feature, mỗi domain nên đi theo cùng một khung:

1. xác định `goal`
2. xác định `entity` chính để gom hành vi
3. chia trường dữ liệu thành các nhóm semantics
4. xử lý riêng từng nhóm
5. tạo representation trung gian cho từng nhóm
6. mới fusion lại cho training

### 3.2 Ba lớp biểu diễn nên có

Mỗi domain nên cố gắng có ba lớp biểu diễn:

- `raw/stable columns`
- `group-specific transformed features`
- `fusion-ready representation`

Điều này giúp:

- giải thích được
- audit được leakage
- thay model sau này mà không phải làm lại tư duy preprocess

## 4. Domain 1: Login

### 4.1 Goal

Goal không chỉ là đoán `login_successful`.

Goal đúng là:

- phát hiện abnormal login behavior
- đánh giá risk theo từng user
- theo dõi thay đổi ngữ cảnh đăng nhập

### 4.2 Nên gom nhóm dữ liệu như sau

- `identity/history`: `user_id`
- `network context`: `ip`
- `geo context`: `country`, `region`, `city`
- `device context`: `device`
- `outcome`: `login_successful`
- `temporal behavior`: `login_timestamp`

### 4.3 Cách process đúng

Không nên chỉ tính count rồi xong.

Nên xử lý theo nhóm:

- `temporal`
  - count theo cửa sổ thời gian
  - time since previous login
  - hour-of-day
  - day-of-week
- `novelty`
  - IP mới hay không
  - device mới hay không
  - country/city mới hay không
- `diversity`
  - unique IP
  - unique device
  - unique location
  - entropy
- `outcome dynamics`
  - success/failure ratio
  - chuỗi failure liên tiếp

### 4.4 Number và categorical xử lý thế nào

Với chính tập [shard_000.parquet](/home/ad1/Project/adaptive-multi-agent-siem/data/processed/login/splits/train/shard_000.parquet) trong `data/processed/login/splits/train`, có thể thấy rõ vì sao phải xử lý riêng miền dữ liệu:

d- `login_count_window1` có `min=1`, `median=1`, `max=29`
- `failure_count_window1` có `min=0`, `median=1`, `max=29`
- `unique_ips_window1` có `min=1`, `median=1`, `max=27`
- `entropy_ips_window1` có `min≈0`, `median≈0`, `max≈4.72`
- `country` tập trung mạnh vào `NO` với `51/75` records, sau đó mới tới `US` với `14/75`
- `device` chủ yếu là `mobile` và `desktop`

Nhìn từ ví dụ này:

- có nhiều cột số rất lệch
- có nhiều cột categorical bị mất cân bằng
- có cột phần lớn nằm sát 0 hoặc 1 nhưng vẫn có một số điểm rất lớn

Vì vậy login domain không nên xử lý tất cả theo một kiểu.

#### 4.4.1 Với nhóm number

Các cột number chính ở login domain hiện tại là:

- `login_count_window*`
- `success_count_window*`
- `failure_count_window*`
- `success_rate_window*`
- `failure_rate_window*`
- `unique_ips_window*`
- `unique_devices_window*`
- `unique_locations_window*`
- `entropy_ips_window*`
- `entropy_devices_window*`

Cách xử lý đúng:

1. `Count features`

Ví dụ `login_count_window1` trong train có median chỉ là `1`, nhưng max tới `29`.

Nếu đưa raw trực tiếp:

- các record rất lớn sẽ lấn phần lớn record còn lại
- model dễ chú ý vào vài spike lớn mà bỏ qua sự khác biệt tinh tế giữa `1`, `2`, `3`

Nên giữ đồng thời:

- `raw_count`
- `log1p_count`
- `count_bin`
- nếu cần, thêm `count_rank`

Ví dụ bin hợp lý:

- `1`
- `2-3`
- `4-7`
- `8-15`
- `>15`

2. `Rate features`

Ví dụ `success_rate_window1` hiện đang chỉ nằm trong `[0, 1]`.

Loại này không cần log transform, nhưng cần:

- giữ raw rate
- có thể thêm coarse bins:
  - `0`
  - `(0, 0.25]`
  - `(0.25, 0.5]`
  - `(0.5, 0.75]`
  - `(0.75, 1]`

Mục tiêu là giúp model nhìn được cả:

- mức chính xác liên tục
- và nhóm hành vi rõ ràng

3. `Entropy features`

Ví dụ `entropy_ips_window1` ở train có median gần `0`, nhưng max lên `4.72`.

Đây là cột rất dễ bị:

- đa số record dồn sát 0
- một số ít record có diversity rất cao

Nên xử lý:

- clip upper tail nếu cần
- giữ raw entropy
- thêm entropy bin:
  - `0`
  - `(0, 1]`
  - `(1, 2]`
  - `(2, 3.5]`
  - `>3.5`

4. `Scaler downstream`

Với nhóm number login, không nên mặc định chỉ dùng Min-Max scaling.

Ưu tiên:

- `RobustScaler` nếu phân phối lệch và có outlier
- `QuantileTransformer` nếu muốn nén tail và làm phân phối đều hơn

Vì ở shard train này:

- nhiều cột có median thấp
- nhưng đuôi trên rất dài

#### 4.4.2 Với nhóm categorical

Các cột categorical chính là:

- `country`
- `region`
- `city`
- `device`
- `ip`

Cách xử lý đúng không phải là one-hot toàn bộ ngay lập tức.

1. `Location`

Không nên gộp `country|region|city` thành một category phẳng duy nhất rồi encode.

Phải giữ nhiều resolution:

- country
- region
- city

Lý do:

- `country` đổi là tín hiệu mạnh hơn
- `city` đổi có thể chỉ là noise
- nhiều giá trị region/city rất thưa

Nên process:

- country-level feature
- region novelty feature
- city novelty feature
- location consistency feature

2. `Device`

Trong train hiện tại:

- `mobile = 40`
- `desktop = 33`
- `tablet = 2`

Điều này cho thấy:

- `tablet` quá hiếm
- one-hot trực tiếp có thể làm feature rất sparse và thiếu ổn định

Nên:

- giữ category gốc
- thêm `is_rare_device`
- hoặc gom nhóm hiếm thành `other_device`

3. `IP`

`IP` không nên xem như categorical bình thường để one-hot.

Nó nên được dùng cho:

- novelty: IP mới hay không
- diversity: số IP khác nhau
- consistency: user có đang dùng IP quen thuộc không

Tức là:

- `ip` nên được chuyển thành tín hiệu hành vi
- không nên để model học thuộc từng giá trị IP

#### 4.4.3 Khi number và categorical đi cùng nhau

Login domain là ví dụ điển hình cho việc number và categorical phải xử lý riêng trước khi fusion.

Prephase nên là:

1. nhóm `temporal-number`
2. nhóm `rate-number`
3. nhóm `diversity-number`
4. nhóm `location-categorical`
5. nhóm `device-categorical`
6. nhóm `ip-behavior`

Sau đó:

- number -> scale / log / bin
- categorical -> map category ổn định hoặc novelty flag
- cuối cùng mới nối các vector lại

Tức là triết lý đúng ở domain login là:

- `count` không chỉ là số
- `country` không chỉ là category
- `ip` không chỉ là string

Mỗi trường phải được đổi về dạng tín hiệu hành vi phù hợp với vai trò của nó.

### 4.5 Điều cần tránh

- model học thuộc user
- split ngẫu nhiên theo row
- coi city nhỏ lẻ là tín hiệu mạnh mà không kiểm soát noise

## 5. Domain 2: CICIDS2018

### 5.1 Goal

Goal là phát hiện hành vi mạng bất thường ở mức flow, không chỉ phân loại nhãn benchmark.

### 5.2 Nên gom nhóm dữ liệu như sau

- `volume`: bytes, packets
- `directionality`: forward/backward ratio
- `timing`: duration, active, idle, per-second rates
- `transport`: protocol, dst_port
- `flags`: SYN, ACK, RST, URG
- `label view`: binary, family, raw

### 5.3 Cách process đúng

Mỗi nhóm phải được transform riêng:

- `volume`
  - raw
  - `log1p`
  - clipped
  - bins
- `directionality`
  - ratio
  - clipped ratio
  - zero-safe transform
- `timing`
  - raw duration/rate
  - log transform
  - burstiness view
- `transport`
  - protocol flags
  - service-port grouping
- `flags`
  - presence flags
  - normalized ratios

### 5.4 Nếu số quá lớn hoặc quá mịn

Domain này đặc biệt dễ bị range issue vì bytes/rates rất rộng.

Nên:

- clip theo quantile
- dùng `log1p`
- tạo coarse bins cho rate lớn
- không để raw number là view duy nhất

### 5.5 Điều cần tránh

- model học shortcut từ port
- label artifact learning
- xem mọi flow metric là cùng một loại số

## 6. Domain 3: Brute Force HTTPS

### 6.1 Goal

Goal là detect `HTTPS brute-force attempt` đủ ổn định qua tool và app, không phải học thuộc `scenario`.

### 6.2 Nên gom nhóm dữ liệu như sau

- `volume`: `bytes`, `bytes_rev`, `packets`, `packets_rev`
- `timing`: `duration`, `roundtrips`, `bytes_per_sec`, `packets_per_sec`
- `service context`: `dst_port`, `protocol`, `tls_sni`, `tls_ja3`
- `scenario metadata`: `scenario`, `attack_tool`, `target_app`

### 6.3 Cách process đúng

Với dataset này, `aggregated_flows` là mức hợp lý nhất để process trong repo.

Các bước đúng:

- giữ `service_key` để gom theo service ổn định
- dùng `scenario/tool/app` chủ yếu cho split và evaluation
- numeric feature phải có nhiều resolution:
  - raw
  - `log1p`
  - clipped
  - bins
- hashed field chỉ nên dùng cẩn thận, không coi là semantic mạnh

### 6.4 Split phải như thế nào

Đây là domain rất dễ leakage.

Không nên chỉ time split.

Nên có thêm:

- scenario holdout
- tool holdout
- app holdout

Nếu không, model dễ đạt điểm đẹp nhưng thực ra chỉ nhớ pattern lab.

### 6.5 Điều cần tránh

- dùng `scenario` như production feature
- học thuộc app hoặc tool
- phụ thuộc vào hashed identifier

## 7. Domain 4: API Traffic

### 7.1 Goal

Goal là detect malicious request behavior, đồng thời audit leakage từ response.

### 7.2 Nên gom nhóm dữ liệu như sau

- `request lexical`
- `request token/stat`
- `response lexical`
- `response token/stat`
- `protocol/context metadata`

### 7.3 Cách process đúng khi vừa có text vừa có number

Đây là domain mix data rõ nhất nên phải xử lý rất tách bạch.

Với `request text`:

- tách syntax ổn định với literal ngẫu nhiên
- path, query, body nên được abstract dần
- key và value không nên xử lý như nhau

Với `response text`:

- xem như nguồn leakage audit
- không nên mặc định dùng làm production signal

Với `numeric text stats`:

- length
- token count
- special char count
- status-code buckets

phải có raw + log + bins.

### 7.4 Mapping text và number về token/vector

Nên đi theo hướng:

- text ngẫu nhiên -> abstract token
- numeric ranges -> bins
- mỗi trường xử lý riêng
- sau đó map về vector riêng
- cuối cùng mới fusion bằng lớp nhỏ

### 7.5 Điều cần tránh

- model thắng nhờ status code hoặc error body
- trộn request và response từ đầu
- giữ nguyên quá nhiều literal ngẫu nhiên

## 8. Kết luận

Điểm chung của cả 4 domain là:

- không được bắt đầu từ model
- phải bắt đầu từ goal và semantics của từng trường
- phải chia nhóm đặc trưng trước khi transform
- phải xử lý riêng text, number, categorical
- phải dùng multi-resolution cho numeric range rộng
- phải giảm noise và leakage ngay từ preprocess
- phần fusion chỉ nên đến sau khi từng nhóm đã được làm sạch và biểu diễn ổn định

Tóm lại, `processing` không phải là thêm nhiều feature hơn, mà là:

- chọn đúng tín hiệu
- gom đúng nhóm
- scale đúng cách
- token hóa đúng kiểu
- và chỉ fusion sau khi từng nhóm đã được xử lý đúng bản chất của nó

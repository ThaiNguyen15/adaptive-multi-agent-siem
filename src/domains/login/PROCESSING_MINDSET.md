# Login Processing Mindset

File này mô tả cách xử lý domain `login` theo objective trong [OVERVIEW.md](/home/ad1/Project/adaptive-multi-agent-siem/OVERVIEW.md#L26):

- đây là `Trigger Layer` cho authentication anomalies
- goal chính là phát hiện `abnormal login behavior` theo từng user
- trọng tâm là `risk scoring`, `anomaly detection`, và quyết định có cần escalate hay không
- giá trị nằm ở thay đổi hành vi theo thời gian, không nằm ở việc nhớ identity

## 1. Goal Đúng Của Domain Này

Không nên hiểu login domain là:

- predict `login_successful`
- nhớ `user_id` nào thường fail
- nhớ `ip` nào thường đi với user nào

Phải hiểu là:

- đo mức lệch của current login so với history trước đó
- tách tín hiệu thành nhiều `characteristics` nhỏ thay vì trộn thành một khối
- giảm noise từ raw categorical values trước khi đưa vào model

Nói ngắn gọn:

- `user_id` chỉ để gom history
- `current event` chỉ được mô tả bằng `strictly-past behavior`
- model nên học `pattern shift`, không học `identity memorization`

## 2. Character Của Raw Data: Benign vs Abuse/Malicious

Trong login domain, `malware / attacker / abuse` thường không xuất hiện như text payload rõ ràng. Nó lộ ra qua `behavior shape`.

### 2.1 Raw benign thường có shape như sau

- context ổn định:
  - IP quen
  - device quen
  - geo quen
- nhịp thời gian tương đối lặp lại:
  - login theo giờ làm việc
  - gap giữa các lần login không quá bất thường
- success/failure history cân bằng hoặc success-dominant
- diversity thấp:
  - ít IP
  - ít device
  - ít location đổi liên tục

### 2.2 Raw abuse / malicious / brute-like behavior thường có shape như sau

- novelty cao:
  - IP mới
  - device mới
  - country/region/city mới
- bursty hoặc lệch nhịp:
  - quá dày
  - quá thưa rồi đột ngột active
  - lệch mạnh so với lịch sử
- failure pressure cao:
  - failure streak tăng
  - failure rate trong cửa sổ ngắn tăng
- diversity tăng bất thường:
  - nhiều IP
  - nhiều geo
  - context đổi nhanh
- raw values có thể rất nhiễu:
  - IP string cardinality rất lớn
  - device string không đồng nhất
  - geo fields có missing hoặc spelling noise

Vì vậy, chiến lược xử lý không nên là học trực tiếp từ raw strings. Phải đổi raw data thành tín hiệu hành vi ổn định hơn.

## 3. Character Của Từng Nhóm Dữ Liệu

Schema chuẩn hiện tại ở [normalizer.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/login/normalizer.py):

- `user_id`: khóa gom history, không phải direct feature
- `ip`: network context raw, rất high-cardinality
- `country`, `region`, `city`: geo context nhiều resolution
- `device`: device context raw, có noise về text
- `login_timestamp`: trục thời gian
- `login_successful`: outcome của current event, không được leak vào feature hiện tại

Sau normalize, nên nhìn dữ liệu thành 5 nhóm:

- `identity key`
  - `user_id`
- `temporal manifold`
  - `login_timestamp`
- `context manifold`
  - `ip`, `device`, `country`, `region`, `city`
- `stable abstraction tokens`
  - `ip_token`
  - `device_token`
  - `geo_token`
  - `context_token`
- `outcome history`
  - các kết quả quá khứ của user

Ý chính:

- raw context giữ lại để audit
- token abstraction dùng để giảm cardinality và giảm noise
- features train chính nằm ở counts, rates, recency, novelty, diversity

## 4. Strategy: Split Thành Nhiều Phase

Không nên làm một bước duy nhất kiểu `raw row -> flat vector`.

Nên split thành nhiều phase:

### Phase 1: Normalize

Làm data theo các bước:

- rename raw columns về schema chuẩn:
  - `User ID -> user_id`
  - `IP Address -> ip`
  - `Country -> country`
  - `Region -> region`
  - `City -> city`
  - `Device Type -> device`
  - `Login Timestamp -> login_timestamp`
  - `Login Successful -> login_successful`
- chỉ giữ các cột thuộc schema login domain
- normalize text cho các cột category:
  - trim space
  - lowercase
  - map giá trị rỗng như `""`, `n/a`, `null`, `none` về `unknown`
  - collapse multiple spaces về một space
- parse `login_timestamp` sang datetime UTC
- map `login_successful` từ các dạng `true/false`, `yes/no`, `1/0` về integer `0/1`
- sort data theo `user_id`, `login_timestamp`

Kết quả của phase này là:

- data có schema ổn định
- text bớt noise format
- time cùng timezone
- outcome ở dạng nhị phân để build history sau đó

### Phase 2: Noise Reduction / Stable Mapping

Làm data theo các bước:

- giữ raw fields lại để audit, nhưng không xem raw string là feature train chính
- map từng raw categorical field cardinality lớn về token ổn định hơn
- mỗi nhóm context có token riêng, chưa fusion ngay vào một vector chung

Ví dụ:

- map `ip` thành `ip_token`:
  - `ipv4_public`
  - `ipv4_private`
  - `invalid_ip`
  - `unknown_ip`
- map `device` thành `device_token`:
  - `mobile`
  - `desktop`
  - `tablet`
  - `server`
  - `other_device`
- map `country/region/city` thành `geo_token` phản ánh level resolution:
  - `geo_country_region_city`
  - `geo_country_region`
  - `geo_country_only`
  - `geo_unknown`
- build `context_token` bằng cách ghép:
  - `ip_token|device_token|geo_token`

Đây chính là ý `if data mix number vs text, split to mapping to 1 token`:

- không đẩy text thô vào model ngay
- đổi text/cardinality lớn thành token ít giá trị hơn
- dùng token để build novelty/familiarity signal về sau

### Phase 3: Strictly-Past Behavioral Build

Làm data theo các bước:

- group data theo `user_id`
- với mỗi event tại thời điểm `t`, chỉ lấy history có `timestamp < t`
- tính toàn bộ behavioral features từ history đó, trước khi add current row vào state
- update state sau khi đã build xong features cho current row

Cụ thể khi đi qua từng event của một user:

- giữ các state như:
  - `seen_ips`, `seen_devices`, `seen_geo_tokens`, `seen_context_tokens`
  - counters cho IP/device/country/context
  - `prev_timestamp`, `prev_success_timestamp`, `prev_failure_timestamp`
  - `prior_success_streak`, `prior_failure_streak`
- từ state quá khứ đó build ra:
  - `is_new_*`
  - `prev_login_same_*`
  - `current_*_prior_count`
  - `current_*_prior_rate`
  - `seconds_since_prev_*`
  - `prior_success_streak`
  - `prior_failure_streak`
- với mỗi rolling window, chỉ query các record trong history window:
  - `window_start <= timestamp < current_timestamp`
- tuyệt đối không để current row góp vào `success_count`, `failure_rate`, `unique_*`, `entropy_*` của chính nó

### Phase 4: Multi-Resolution Feature Build

Làm data theo các bước:

- với mỗi numeric behavioral signal, không chỉ giữ một bản raw
- tạo thêm bản `log1p`
- tạo thêm bản bin/coarse ordinal
- làm việc này nhất quán cho count, recency, rate, diversity

Ví dụ:

- count:
  - `login_count_window*`
  - `log_login_count_window*`
  - `login_count_bin_window*`
- recency:
  - `seconds_since_prev_*`
  - `seconds_since_prev_*_log`
  - `seconds_since_prev_*_bin`
- rate:
  - `success_rate_window*`
  - `failure_rate_window*`
  - `success_rate_bin_window*`
  - `failure_rate_bin_window*`

Cách làm thực tế:

- count lớn lệch scale thì giữ:
  - raw count
  - `log1p(count)`
  - count bin
- gap thời gian thì giữ:
  - raw seconds
  - `log1p(seconds)`
  - gap bin
- rate thì giữ:
  - raw rate
  - rate bin

Mục đích thực dụng của cách làm này là để downstream model nhìn được:

- magnitude thật
- relative change ở tail dài
- regime thô như thấp/vừa/cao

### Phase 5: Head-Specific Scoring

Làm data theo các bước:

- chia feature matrix thành nhiều block thay vì quăng toàn bộ vào một head duy nhất
- mỗi block tương ứng một characteristic hành vi
- train model riêng cho từng block, hoặc feed từng block vào encoder riêng nếu dùng neural model

Ví dụ chia block:

- `temporal head`:
  - `seconds_since_prev_*`
  - `hour_of_day`
  - `day_of_week`
  - `is_weekend`
- `novelty head`:
  - `is_new_ip`
  - `is_new_device`
  - `is_new_geo_token`
  - `is_new_context_token`
- `familiarity head`:
  - `current_ip_prior_count`
  - `current_device_prior_count`
  - `current_context_prior_count`
  - các prior rate tương ứng
- `outcome-pressure head`:
  - `prior_success_streak`
  - `prior_failure_streak`
  - `success_rate_window*`
  - `failure_rate_window*`
- `diversity head`:
  - `unique_*`
  - `entropy_*`

Sau đó kết hợp outcome giữa các head bằng một tầng fusion như:

- weighted average
- logistic regression trên các head scores
- gradient boosting trên vector score của các head
- neural fusion MLP nếu dùng multi-encoder

### Phase 6: Multi-Resolution / Manifold Fusion

Làm data theo các bước:

- giữ riêng từng manifold trước khi fusion:
  - temporal manifold
  - context manifold
  - outcome manifold
- trong mỗi manifold, biểu diễn tín hiệu ở nhiều resolution nếu cần:
  - raw
  - log
  - bin
- chỉ fusion các manifold sau khi mỗi manifold đã tạo ra signal tương đối ổn định

Ví dụ practical:

- temporal manifold:
  - `seconds_since_prev_login`
  - `seconds_since_prev_login_log`
  - `seconds_since_prev_login_bin`
  - `hour_of_day`
- context manifold:
  - `ip_token`
  - `device_token`
  - `geo_token`
  - `context_token`
  - `is_new_context_token`
  - `current_context_prior_count`
- outcome manifold:
  - `prior_success_streak`
  - `prior_failure_streak`
  - `success_rate_window*`
  - `failure_rate_window*`

Thứ tự xử lý nên là:

- normalize raw data
- map raw categorical sang stable token
- build strictly-past behavioral features
- expand numeric signals ra raw/log/bin
- chia feature theo manifold/head
- train từng head hoặc encoder riêng
- fusion head outputs thành final risk

## 6. Multi-Resolution Và Manifold Mindset

Raw security data thường không nằm trên một scale duy nhất.

Ví dụ:

- `login_count_window1 = 1` và `login_count_window1 = 3` có thể quan trọng
- nhưng `login_count_window30 = 300` cũng phải được giữ lại
- nếu chỉ dùng raw count, signal nhỏ có thể bị chìm

Do đó nên dùng `multi-resolution`:

- raw giữ magnitude
- log giữ relative change ở tail dài
- bin giữ coarse regime

`manifold` ở đây nên hiểu thực dụng:

- thời gian là một manifold
- geo là một manifold nhiều level
- device/context là manifold category
- outcome dynamics là manifold hành vi

Không trộn thô tất cả modalities ngay từ đầu. Nên giữ chúng tách ra trước, rồi mới fusion ở downstream.

## 7. Leakage Control Rules

### Rule 1: strictly past only

Đúng:

- history window dùng `timestamp < current_timestamp`

Sai:

- history window dùng `timestamp <= current_timestamp`

Nếu sai, `success_count`, `failure_count`, `success_rate`, `failure_rate` sẽ leak current outcome.

### Rule 2: current outcome không mô tả current feature

Được phép:

- dùng outcome quá khứ
- dùng `seconds_since_prev_success`
- dùng `prior_failure_streak`

Không được phép:

- để current row góp vào history window hiện tại

### Rule 3: split phải theo thời gian

Không random row split vì sẽ leak tương lai và leak behavior của cùng user giữa train/test.

### Rule 4: không train trực tiếp bằng identity

Không dùng raw trực tiếp làm baseline feature:

- `user_id`
- raw `ip`
- raw `city`

Nếu cần embedding raw token, phải audit leakage riêng.

## 8. Rewrite Code Theo Mindset Này

Code hiện tại nên đi theo cấu trúc sau:

### 8.1 Normalizer

Trong [normalizer.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/login/normalizer.py):

- chuẩn hóa text raw
- tạo `ip_token`
- tạo `device_token`
- tạo `geo_token`
- tạo `context_token`

Mục tiêu:

- giữ raw fields để audit
- nhưng đồng thời tạo stable token fields để downstream dùng khi cần

### 8.2 Feature Builder

Trong [feature_builder.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/login/feature_builder.py):

- giữ strictly-past rolling windows
- thêm recency raw/log/bin
- thêm familiarity features:
  - `current_ip_prior_count`
  - `current_device_prior_count`
  - `current_context_prior_count`
  - các rate tương ứng
- thêm head cho outcome pressure:
  - `prior_success_streak`
  - `prior_failure_streak`
- thêm head cho context continuity:
  - `prev_login_same_ip`
  - `prev_login_same_device`
  - `prev_login_same_country`
  - `prev_login_same_region`
  - `prev_login_same_city`
- thêm diversity của `context_token`
- thêm bin cho rate và unique count

Các feature này gần với objective hơn là việc ingest raw strings.

## 9. Cách Chuẩn Bị Dữ Liệu Train

Khi đưa vào model, nên tách tối thiểu 3 khối:

- `numeric behavioral block`
  - counts
  - rates
  - recency
  - streaks
  - entropy
- `flag/block for novelty-continuity`
  - `is_new_*`
  - `prev_login_same_*`
  - `has_prior_login`
- `token block for optional embedding`
  - `ip_token`
  - `device_token`
  - `geo_token`
  - `context_token`

Nếu chỉ làm baseline model:

- ưu tiên numeric + flags
- token block chỉ nên là optional path

## 10. Kết Luận Thực Dụng

Mindset tốt cho login domain là:

- đừng học raw strings
- đừng train bằng identity
- đừng trộn số và text thô
- đừng dùng một flat head cho mọi signal

Thay vào đó:

- split thành nhiều phase
- giảm noise trước
- map categorical thô về stable token
- build strictly-past behavior
- dùng multi-resolution cho numeric
- tách nhiều head theo từng characteristic rồi mới fusion

Đó là cách xử lý data gần với anomaly/risk objective hơn, và cũng dễ generalize hơn khi đi từ benign sang abuse/malicious behavior.

## 4.1 Goal

- phát hiện abnormal login behavior
- đánh giá risk theo từng user
- theo dõi thay đổi ngữ cảnh đăng nhập

## 4.2 Gom nhóm dữ liệu

- `identity/history`: `user_id`
- `network context`: `ip`
- `geo context`: `country`, `region`, `city`
- `device context`: `device`
- `outcome`: `login_successful`
- `temporal behavior`: `login_timestamp`

## 4.3 Cách process

Xử lý theo 4 nhóm chính:

- `temporal`: count theo cửa sổ thời gian, time since previous login, hour-of-day, day-of-week
- `novelty`: IP mới, device mới, country/city mới
- `diversity`: số IP, device, location khác nhau, entropy
- `outcome dynamics`: success/failure ratio, chuỗi failure liên tiếp

## 4.4 Xử lý feature data

### 4.4.1 Number

Các cột number chính:

- `login_count_window*`
- `success_count_window*`
- `failure_count_window*`
- `success_rate_window*`
- `failure_rate_window*`
- `unique_*`
- `entropy_*`

Cách xử lý:

- `count`: giữ raw + bin  
  Ví dụ `login_count_window1` có median `1`, max `29`, nên cần chia bin để model thấy cả mức nhỏ và mức tăng mạnh.
- `rate`: giữ raw + coarse bins trong khoảng `[0,1]`
- `entropy`: giữ raw, có thể clip upper tail và chia bin vì đa số record gần `0`, một số ít rất cao
- scaler downstream:
  - `RobustScaler` nếu lệch phân phối, có outlier
  - `QuantileTransformer` nếu muốn nén tail và làm phân phối đều hơn

### 4.4.2 Categorical

Các cột categorical chính:

- `country`
- `region`
- `city`
- `device`
- `ip`

Cách xử lý:

- `location`: không gộp phẳng toàn bộ `country|region|city`, mà giữ nhiều resolution:
  - country
  - region
  - city
- `device`: category hiếm như `tablet` có thể gom thành `other_device`
- `ip`: không dùng như string thô, mà đổi thành tín hiệu hành vi:
  - IP mới hay không
  - số IP khác nhau
  - mức độ quen thuộc của IP với user

### 4.4.3 Khi number và categorical đi cùng nhau

Prephase nên tách riêng:

- `temporal-number`
- `rate-number`
- `diversity-number`
- `location-categorical`
- `device-categorical`
- `ip-behavior`

Sau đó mới xử lý:

- number -> scale / bin
- categorical -> stable category / novelty flag
- cuối cùng mới nối các vector lại

Kết luận:

- `count` không chỉ là số
- `country` không chỉ là category
- `ip` không chỉ là string

Mỗi trường phải được đổi về tín hiệu hành vi phù hợp với vai trò của nó.

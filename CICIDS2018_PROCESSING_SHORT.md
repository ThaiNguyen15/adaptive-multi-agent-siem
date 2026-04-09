## 2.1 Goal

- phát hiện bất thường mạng ở mức flow
- nhận ra pattern tấn công qua hành vi traffic
- tạo feature có thể dùng ngoài benchmark, không chỉ khớp nhãn dataset

## 2.2 Gom nhóm dữ liệu

- `volume`: `total_packets`, `total_bytes`, `bytes_per_packet`
- `directionality`: `fwd_bwd_packet_ratio`, `fwd_bwd_bytes_ratio`
- `timing`: `flow_bytes_per_second_log1p`, `flow_packets_per_second_log1p`, `active_idle_ratio`
- `transport`: `protocol`, `dst_port`
- `flags`: `syn_ack_flag_ratio`, `reset_flag_present`, `urgent_flag_present`
- `label view`: `label_binary`, `attack_family`

## 2.3 Cách process

Xử lý theo 4 nhóm chính:

- `volume`: số packet, số byte, byte mỗi packet
- `directionality`: tương quan chiều forward và backward
- `timing`: tốc độ flow, mức burst, active/idle
- `transport + flags`: protocol, port, TCP flag behavior

## 2.4 Xử lý feature data

### 2.4.1 Number

Các cột number chính:

- `total_packets`
- `total_bytes`
- `bytes_per_packet`
- `fwd_bwd_packet_ratio`
- `fwd_bwd_bytes_ratio`
- `flow_bytes_per_second_log1p`
- `flow_packets_per_second_log1p`
- `syn_ack_flag_ratio`

Cách xử lý:

- `volume`: giữ raw + log + bin  
  Ví dụ trong [shard_000.parquet](/home/ad1/Project/adaptive-multi-agent-siem/data/processed/cicids2018/splits/train/shard_000.parquet), `total_packets` có median `2`, max `48`; `total_bytes` có median `0`, max `4160`. Điều này cho thấy dữ liệu lệch mạnh, nên không thể chỉ dùng raw value.
- `ratio`: giữ raw ratio, nhưng phải zero-safe và có thể clip upper tail
- `rate`: nên giữ log-scale và có thể thêm coarse bins vì nhiều record dồn sát `0`, nhưng một số flow rất lớn
- scaler downstream:
  - `RobustScaler` nếu có outlier
  - `QuantileTransformer` nếu muốn nén tail mạnh hơn

### 2.4.2 Categorical

Các cột categorical chính:

- `protocol`
- `dst_port`
- `attack_family`

Cách xử lý:

- `protocol`: không nên coi chỉ là số, mà nên map thành semantic flags như TCP/UDP
- `dst_port`: không nên dùng raw port như category duy nhất, mà nên gom theo nhóm service hoặc well-known/high-port
- `attack_family`: dùng làm nhãn hoặc metadata đánh giá, không nên coi là feature input

### 2.4.3 Khi number và categorical đi cùng nhau

Prephase nên tách riêng:

- `volume-number`
- `direction-number`
- `timing-number`
- `transport-categorical`
- `flags-number`

Sau đó mới xử lý:

- number -> log / clip / bin / scale
- categorical -> semantic mapping hoặc service grouping
- cuối cùng mới nối các vector lại

Kết luận:

- `bytes` không chỉ là số lớn nhỏ
- `port` không chỉ là một category thô
- `protocol` không chỉ là integer

Mỗi trường phải được đổi về tín hiệu hành vi mạng phù hợp với vai trò của nó.

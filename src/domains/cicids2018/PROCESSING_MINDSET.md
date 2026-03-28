# CICIDS2018 Processing Mindset

File này ghi lại mindset xử lý dataset `cicids2018` theo hướng thầy yêu cầu.

## 1. Goal First

Goal của domain này không chỉ là `classify attack label`.

Goal đúng hơn là:

- phát hiện bất thường mạng ở mức flow
- nắm được pattern tấn công qua traffic behavior
- tạo representation dùng được ngoài dataset lab

Điều đó dẫn tới một nguyên tắc:

- feature nên mô tả hành vi của flow
- không nên phụ thuộc quá mạnh vào artifact riêng của dataset

## 2. Domain Semantics

Dataset hiện tại được xử lý như flow-level network data trong:

- [config.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/cicids2018/config.py#L1)
- [normalizer.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/cicids2018/normalizer.py#L1)
- [feature_builder.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/cicids2018/feature_builder.py#L1)

Mindset nên giữ:

- mỗi flow là một đơn vị hành vi mạng
- volume, direction, timing, flags là các nhóm tín hiệu khác nhau
- label attack chỉ là một cách nhìn downstream, không phải toàn bộ ý nghĩa của flow

## 3. Feature Groups Should Be Separated

Không nên trộn tất cả numeric flow metrics thành một khối đồng nhất.

Nên tách thành:

- `volume`: bytes, packets
- `directionality`: forward/backward ratio
- `timing`: duration, active, idle, rates
- `transport`: protocol, ports
- `flags`: SYN, ACK, RST, URG
- `label semantics`: binary, family, raw

Mỗi nhóm nên có preprocessing riêng trước khi fusion.

## 4. Key Mindset From The Note

Theo note:

- số có range rộng sẽ làm tín hiệu nhỏ bị chìm
- nên dùng multi-resolution
- nên gom nhóm rồi xử lý theo manifold

Áp vào dataset này:

- count, byte, rate metrics nên có bản raw, log-scale, và clipped/bin
- protocol/port nên đi theo dạng categorical flag, không chỉ numeric
- forward/backward relation nên được xem như semantic structure riêng

## 5. Noise And Leakage Risks

Rủi ro chính:

- label artifacts đặc trưng cho dataset lab
- port-specific memorization
- duplicate or near-duplicate flows
- split không phản ánh tương lai hoặc attack-family shift

Mindset:

- tránh để model thắng nhờ `dst_port` hoặc label shortcut
- cần đánh giá cả binary và family generalization
- cần audit performance theo nhóm attack

## 6. What Current Code Does Well And What Is Missing

Hiện tại code đã có:

- normalize schema
- build ratios/rates
- flag presence
- binary/family/raw target view

Nhưng còn thiếu:

- explicit clipped/bin views cho numeric features lớn
- attack-family holdout evaluation
- richer port semantics:
  - common service bins
  - suspicious uncommon-port behavior
- temporal burstiness ở mức flow neighborhood nếu có thể

## 7. Update Priorities For Code

Ưu tiên:

1. Tạo grouped numeric transforms:
   - raw
   - `log1p`
   - clipped
   - binned
2. Mở rộng transport semantics:
   - service-port groups
   - ephemeral-port indicators
3. Mở rộng direction/timing interaction features
4. Thêm evaluation metadata cho holdout theo attack family
5. Giảm phụ thuộc vào một số shortcut field quá đặc trưng dataset

## 8. Prompt To Update This Domain

```text
Refactor the CICIDS2018 domain to follow a security-behavior mindset instead of a flat tabular-label mindset.

Context:
- This is a flow-level network dataset
- Goal: represent network behavior patterns that generalize beyond this one benchmark
- Keep the existing normalize -> shard -> feature -> split architecture

Requirements:
- Organize features into groups: volume, directionality, timing, transport, flags
- For large-range numeric metrics, add multi-resolution handling: raw, log1p, clipped, and coarse bins where appropriate
- Improve port semantics beyond raw dst_port integers
- Preserve binary/family/raw target modes
- Avoid introducing obvious dataset shortcuts as dominant signals
- Keep the feature set training-friendly for both tree models and neural models
- Document leakage/generalization risks, especially attack-family and port memorization

Deliverables:
- update feature_builder.py with grouped, interpretable transforms
- update config if new options are needed
- preserve current pipeline compatibility
```

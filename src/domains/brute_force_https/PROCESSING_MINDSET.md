# Brute Force HTTPS Processing Mindset

File này ghi lại mindset xử lý dataset `Extended Network Flow Brute-force Dataset`.

## 1. Goal First

Goal đúng không phải là:

- học thuộc `scenario`
- đoán đúng tool lab

Goal đúng là:

- phát hiện `HTTPS brute-force attempt`
- nhận ra pattern đủ ổn định qua tool và app
- tạo feature có thể dùng cho production-like detection

## 2. Domain Semantics

Dataset này có 3 mức:

- `flows.csv`
- `aggregated_flows.csv`
- `samples.csv`

Mindset nên giữ:

- `flows` là raw nhất ở mức flow-prefix
- `aggregated_flows` là mức phù hợp nhất để tự làm feature trong repo
- `samples` là benchmark phụ, không phải ground truth preprocessing duy nhất

## 3. Treat Feature Families Separately

Nên chia feature thành:

- `volume`: `bytes`, `bytes_rev`, `packets`, `packets_rev`
- `timing`: `duration`, `roundtrips`, `bytes_per_sec`, `packets_per_sec`
- `service context`: `dst_port`, `protocol`, `tls_sni`, `tls_ja3`
- `scenario metadata`: `scenario`, `attack_tool`, `target_app`

Nguyên tắc:

- `scenario/tool/app` hữu ích cho split và analysis
- không nên là production feature chính

## 4. Main Risk: Dataset Shortcut Learning

Dataset này cực dễ bị shortcut learning qua:

- `scenario`
- app-specific service pattern
- tool-specific burst shape
- split sai làm cùng scenario rơi vào train và test

Mindset:

- report binary detection là chưa đủ
- phải test generalization theo `scenario`, `tool`, hoặc `app`

## 5. Numeric Handling

Đúng tinh thần note:

- rate/volume metrics có range rất lệch
- số lớn sẽ nuốt tín hiệu nhỏ nếu giữ raw duy nhất

Nên có:

- raw value
- `log1p`
- clipped value
- coarse bin hoặc rank

Đặc biệt với:

- `duration`
- `bytes`
- `bytes_rev`
- `packets`
- `packets_rev`
- `roundtrips_per_sec`

## 6. Hashed Fields Need Care

Các field như:

- `src_ip`
- `dst_ip`
- `src_port`
- `tls_sni`

đã bị hash hoặc bị trừu tượng hóa.

Mindset:

- đừng xem hashed value là semantic token mạnh
- ưu tiên feature có meaning hành vi hơn là raw identifier
- raw hash chỉ nên dùng để grouping hoặc service context ổn định

## 7. What Current Domain Should Evolve Toward

Hiện tại domain đã đi đúng hướng ở chỗ:

- tách riêng domain mới
- chọn `aggregated_flows` làm default
- shard theo `service_key`

Nhưng để đúng hơn theo mindset của thầy, nên bổ sung:

1. split kiểu `scenario holdout`
2. split kiểu `tool holdout` hoặc `app holdout`
3. binned/ranked variants cho numeric features
4. feature về novelty hoặc rarity theo service
5. phân tách rõ production features và evaluation metadata

## 8. Prompt To Update This Domain

```text
Refactor the brute_force_https domain to follow a robust detection mindset instead of a benchmark-shortcut mindset.

Context:
- Dataset views: flows.csv, aggregated_flows.csv, samples.csv
- Main goal: detect HTTPS brute-force attempts that generalize across attack tools and target applications
- Keep the existing normalize -> shard -> feature -> split architecture

Requirements:
- Keep aggregated_flows as the default repo-native processing path
- Treat scenario/tool/app as evaluation metadata first, not primary production features
- Add multi-resolution numeric handling for duration, bytes, packets, rates, and roundtrip-related metrics
- Preserve stable service grouping via service_key
- Add support for stronger evaluation modes such as scenario holdout, tool holdout, or app holdout
- Avoid over-reliance on hashed raw identifiers as semantic features
- Keep the feature set interpretable and suitable for downstream ML

Deliverables:
- update config/pipeline if new split modes are needed
- update feature_builder.py to add grouped transforms and binned variants
- clearly document which fields are production-safe signals vs metadata-only fields
```

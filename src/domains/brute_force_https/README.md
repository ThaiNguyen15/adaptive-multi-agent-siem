# Brute Force HTTPS Domain

Domain này dành cho dataset `Extended Network Flow Brute-force Dataset`.

## Recommended processing strategy

### 1. `samples.csv` for baseline

Use when:
- cần baseline nhanh để train model
- muốn giữ gần nhất với feature space gốc của tác giả dataset

Pros:
- nhỏ nhất
- đã có feature engineered
- phù hợp để benchmark nhanh

Cons:
- ít kiểm soát preprocessing
- khó audit leakage nếu giữ toàn bộ feature mà không review kỹ

### 2. `aggregated_flows.csv` for repo-native pipeline

Use when:
- muốn normalize/build feature trong repo
- muốn kiểm soát feature semantics
- muốn tái sử dụng chung architecture `normalize -> shard -> feature -> split`

This is the recommended default for this domain.

Why:
- already aggregated enough for efficient processing
- still close to the network-flow source
- avoids the 1.1GB `flows.csv` overhead for the first version

### 3. `flows.csv` for advanced experiments

Use when:
- muốn sequence-aware modeling
- muốn trích xuất packet-prefix timing/size features riêng
- chấp nhận cost parse lớn hơn

This should be phase 2, not the default path.

## Recommended labels

- `binary`: production-like brute-force detection baseline
- `scenario`: hold-out by exact scenario
- `tool`: generalization across `hydra`, `patator`, `ncrack`
- `app`: generalization across target applications

## Recommended split policy

Do not rely only on random row-level splitting if the goal is robustness.

Preferred evaluation:
- baseline time split for compatibility with existing pipeline
- add scenario-holdout experiments outside the default splitter
- report both binary accuracy and cross-scenario generalization

## Recommended shard key

This domain shards by `service_key`:

`coalesce(tls_sni, dst_ip) + ":" + dst_port + ":" + protocol`

Reason:
- `dst_port` alone would skew heavily to `443`
- service-level grouping keeps related HTTPS traffic together

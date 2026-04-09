# Raw Domain Processing Mindset

File này mô tả cách hiểu và xử lý dữ liệu ở mức `raw source` trước khi đưa vào domain model cụ thể.

Case hiện tại được neo theo dataset ở [readme.md](/home/ad1/Project/adaptive-multi-agent-siem/data/raw/brute-force-dataset/readme.md), và phải khớp với vai trò trong [OVERVIEW.md](/home/ad1/Project/adaptive-multi-agent-siem/OVERVIEW.md#L43):

- đây là dữ liệu cho `Network Layer`
- goal không phải là đọc raw file cho đủ
- goal là chọn đúng raw view nào gần nhất với bài toán model cần học

## 1. Goal Đúng Của Raw Domain

`raw` không phải một model domain độc lập để train trực tiếp.

Nó là lớp hiểu nguồn dữ liệu:

- raw file nào chứa signal gần với production nhất
- raw file nào chỉ là benchmark convenience
- raw file nào quá thấp level, tốn cost parse nhưng chưa cần ở phase đầu

Nói ngắn gọn:

- `raw domain` dùng để quyết định `representation level`
- không dùng để học thuộc tên file hay schema lab
- phải chọn input view sao cho khớp với objective của model phía sau

## 2. Phải Gắn Với Picture Trong OVERVIEW Như Thế Nào

Theo [OVERVIEW.md](/home/ad1/Project/adaptive-multi-agent-siem/OVERVIEW.md#L43), brute-force HTTPS nằm ở:

- `Network Layer (O4)`
- nhiệm vụ là phát hiện `HTTPS brute-force attempt`
- trọng tâm là flow behavior, timing, service context

Vì vậy khi đứng ở `raw` level, câu hỏi đúng không phải là:

- file nào nhiều cột nhất
- file nào tác giả dataset đã feature-engineer sẵn nhiều nhất

Mà phải là:

- file nào gần với `network behavior model` nhất
- file nào cho phép normalize và build feature theo architecture của repo
- file nào giảm rủi ro leakage hoặc shortcut learning

## 3. Hiểu 3 Mức Dữ Liệu Trong readme.md

Theo [readme.md](/home/ad1/Project/adaptive-multi-agent-siem/data/raw/brute-force-dataset/readme.md), dataset publish 3 file:

- `flows.csv`
- `aggregated_flows.csv`
- `samples.csv`

Không nên xem 3 file này là 3 bản giống nhau khác kích thước. Chúng là 3 mức representation khác nhau.

### 3.1 `flows.csv`

Đây là raw nhất.

Ý nghĩa:

- gần với extended network flow source nhất
- còn nhiều chi tiết ở mức prefix packets, direction, timing
- phù hợp khi muốn sequence-aware modeling hoặc tự thiết kế feature sâu hơn

Tradeoff:

- parse cost lớn
- schema phức tạp hơn
- chưa phải điểm bắt đầu tốt nhất cho pipeline đầu tiên

Mindset:

- dùng cho `phase 2` hoặc advanced experiment
- không nên là default raw view nếu mục tiêu hiện tại là build pipeline ổn định nhanh

### 3.2 `aggregated_flows.csv`

Đây là mức cân bằng nhất giữa raw fidelity và processing practicality.

Ý nghĩa:

- vẫn còn gần network-flow behavior
- đã aggregate đủ để xử lý hiệu quả
- vẫn cho phép repo tự normalize, shard, build feature

Mindset:

- đây là raw view nên gần model nhất trong phase đầu
- phù hợp nhất để map sang `network behavior model` trong overview
- nên là default input cho domain `brute_force_https`

### 3.3 `samples.csv`

Đây là bản convenience cho benchmark nhanh.

Ý nghĩa:

- đã có extracted features
- train baseline rất nhanh
- tiện cho kiểm tra label path hoặc benchmark ban đầu

Tradeoff:

- ít kiểm soát preprocessing semantics
- dễ giữ lại feature mà mình chưa audit
- có nguy cơ học shortcut từ feature space sẵn có thay vì signal mình thật sự muốn

Mindset:

- dùng để baseline
- không nên là nguồn chân lý duy nhất cho production-minded pipeline

## 4. File Nào Gần Model Nhất

Nếu bám đúng picture trong `OVERVIEW.md`, model ở đây cần học:

- volume pattern
- timing pattern
- service-level behavior
- dấu hiệu brute-force lặp lại qua tools và apps

Vì vậy mức dữ liệu gần model nhất là:

- `aggregated_flows.csv` cho pipeline chính

Lý do:

- đủ gần traffic thật để giữ behavioral signal
- chưa bị đóng khung hoàn toàn bởi feature engineering của tác giả dataset
- khớp với kiến trúc repo hiện tại: `normalize -> shard -> feature -> split`

Thứ tự ưu tiên hợp lý:

1. `aggregated_flows.csv` cho repo-native model path
2. `samples.csv` cho benchmark nhanh
3. `flows.csv` cho phase sau nếu cần modeling sâu hơn

## 5. Raw Signals Nào Nên Được Giữ

Từ `readme.md`, dataset chứa các nhóm tín hiệu quan trọng:

- network volume:
  - bytes
  - reverse bytes
  - packets
  - reverse packets
- timing:
  - time first
  - time last
  - duration
  - inter-packet or roundtrip related information
- service context:
  - destination IP
  - destination port
  - protocol
  - TLS SNI nếu có
- scenario metadata:
  - benign backbone capture
  - brute-force tool/app combinations

Mindset:

- volume, timing, service context là production-signal chính
- scenario/tool/app là evaluation metadata rất hữu ích
- hashed identifiers không nên được xem là semantic feature mạnh

## 6. Raw Signals Nào Không Nên Tin Quá Mức

Trong `readme.md`, các field như IP, source port, TLS SNI đã bị hash.

Điều đó có nghĩa:

- hash có thể dùng để grouping ổn định
- nhưng hash không mang semantic network meaning giống giá trị gốc
- nếu model học quá mạnh từ hash thì sẽ thành shortcut theo dataset identity

Vì vậy:

- không treat raw hash như token nội dung quan trọng
- ưu tiên behavior features hơn là identifier memorization
- dùng raw hash chủ yếu cho grouping, join, service anchoring

## 7. Raw Domain Phải Hỗ Trợ Model Downstream Ra Sao

`raw domain` nên chuẩn bị cho model downstream theo 4 việc:

### 7.1 Chọn đúng input view

- mặc định dùng `aggregated_flows.csv`
- cho phép `samples.csv` như baseline path
- để `flows.csv` cho later-phase experiments

### 7.2 Bảo toàn provenance

Mỗi record sau normalize nên còn biết:

- nó đến từ file nào
- view nào
- scenario nào
- benign hay brute-force

Vì provenance giúp:

- audit leakage
- holdout theo scenario/tool/app
- giải thích performance đúng hơn

### 7.3 Tách signal khỏi metadata

Phải tách rõ:

- `production-like signals`
  - timing
  - volume
  - direction
  - service grouping
- `evaluation metadata`
  - scenario
  - attack tool
  - target app

Nếu trộn sớm, model sẽ rất dễ học benchmark artifact.

### 7.4 Chuẩn bị cho split đúng

Random row split thường không đủ.

Raw domain phải giữ đủ metadata để downstream domain có thể làm:

- time split
- scenario holdout
- tool holdout
- app holdout

## 8. Processing Pipeline Ở Mức Raw Nên Nghĩ Như Thế Nào

Không nên nghĩ:

`raw file -> train model`

Nên nghĩ:

`raw file -> chọn đúng view -> normalize schema -> preserve provenance -> build domain-safe features -> split robustly -> train model`

Với brute-force HTTPS case, pipeline ưu tiên nên là:

`aggregated_flows.csv -> brute_force_https normalizer -> shard by service_key -> feature builder -> robust split`

## 9. Kết Luận Thực Dụng

Nếu hỏi `readme.md` này cần gần với model nào trong picture overview, câu trả lời là:

- nó gần nhất với `Network Layer` model
- và trong 3 raw representations thì `aggregated_flows.csv` là representation gần model nhất cho phase hiện tại

Nếu hỏi `raw domain` nên làm gì, câu trả lời là:

- không train trực tiếp từ mọi raw file như nhau
- phải chọn representation level đúng
- phải giữ provenance và metadata để chống shortcut learning
- phải phục vụ domain downstream, ở đây chủ yếu là `brute_force_https`

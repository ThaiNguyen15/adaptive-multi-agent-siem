# CICIDS2018 Processing Mindset

File này mô tả cách xử lý domain `cicids2018` theo objective trong [OVERVIEW.md](/home/ad1/Project/adaptive-multi-agent-siem/OVERVIEW.md#L38):

- đây là `Network Layer (O4)` cho flow-level network anomalies
- goal chính là phát hiện `abnormal network behavior` ở mức flow
- trọng tâm là `risk scoring`, `anomaly detection`, và quyết định có cần escalate sang layer application hay không
- giá trị nằm ở `traffic behavior pattern`, không nằm ở việc nhớ artifact riêng của dataset lab

## 1. Goal Đúng Của Domain Này

Không nên hiểu CICIDS2018 domain là:

- chỉ predict đúng `attack_label_raw`
- nhớ `dst_port` nào hay là attack
- nhớ pattern riêng của benchmark rồi áp lại nguyên xi

Phải hiểu là:

- đo flow hiện tại lệch thế nào so với traffic behavior bình thường hoặc so với family behavior
- tách flow thành nhiều `characteristics` nhỏ thay vì trộn mọi metric vào một khối phẳng
- giảm shortcut từ port/protocol/label artifact trước khi đưa vào model

Nói ngắn gọn:

- mỗi `flow` là một đơn vị hành vi mạng
- `current flow` phải được mô tả bằng behavior-friendly representation
- model nên học `network behavior pattern`, không học `dataset memorization`

## 2. Dataset Picture Theo Nguồn Chính Thức

Theo trang dataset chính thức của UNB, CSE-CIC-IDS2018:

- được xây để phục vụ network-based anomaly detection
- có traffic benign background dựa trên user profiles
- có 7 attack scenarios chính
- dữ liệu được tổ chức theo ngày
- raw data gồm PCAP và logs theo machine
- flow CSV được trích ra bằng `CICFlowMeter-V3`
- mỗi flow có hơn 80 traffic features

Attack scenarios mà trang UNB nêu trực tiếp gồm:

- `Brute-force`
- `Heartbleed`
- `Botnet`
- `DoS`
- `DDoS`
- `Web attacks`
- `Infiltration`

Ý nghĩa với hệ thống của mình:

- domain này không nên cố giải quyết sâu phần payload semantics của `Web attacks`
- domain này hợp nhất để làm `network behavior filter`
- các family phù hợp nhất với Network Layer thường là:
  - `DDoS / DoS`
  - `Brute-force`
  - `Infiltration`
  - `Botnet`
- `Web attacks` ở flow-level có thể vẫn giữ để evaluate, nhưng không nên kỳ vọng đây là tín hiệu mạnh nhất của layer mạng

Nếu cần baseline rõ và ít nhiễu hơn, nên ưu tiên train/evaluate trước trên:

- `Benign`
- `DoS / DDoS`
- `Brute Force`
- `Infiltration`
- `Botnet`

Rồi mới mở rộng thêm:

- `Heartbleed`
- `Web Attack`

## 3. Character Của Raw Data: Benign vs Abuse/Malicious

Trong network flow domain, attack không luôn lộ ra qua payload.
Nó thường lộ ra qua `shape` của traffic:

- volume
- directionality
- timing
- transport context
- flag behavior

### 2.1 Raw benign thường có shape như sau

- packet/byte volume không quá cực đoan
- chiều forward/backward tương đối cân bằng hoặc hợp với service đang chạy
- timing không burst quá mức nếu không phải workload đặc biệt
- TCP/UDP và port context tương đối hợp lý
- flag pattern không quá bất thường

### 2.2 Raw abuse / malicious thường có shape như sau

- volume tăng mạnh hoặc rate rất cao
- forward/backward lệch mạnh
- duration rất ngắn nhưng packet rate cực cao, hoặc duration dài bất thường
- port/protocol context lạ hoặc không hợp pattern service
- SYN/RST/URG behavior bất thường

Nhưng raw flow data cũng rất nhiễu:

- numeric range rất rộng
- nhiều cột cùng đo gần giống nhau nhưng scale khác nhau
- port rất dễ trở thành shortcut của benchmark
- label raw có thể phản ánh artifact của kịch bản lab nhiều hơn production behavior

Vì vậy, chiến lược xử lý không nên là:

- nhét nguyên raw metrics vào model
- hoặc để model thắng nhờ một vài field shortcut như `dst_port`

Phải đổi raw flow thành representation gần với behavior hơn.

## 4. Character Của Từng Nhóm Dữ Liệu

Schema chuẩn hiện tại ở [normalizer.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/cicids2018/normalizer.py):

- metadata:
  - `event_id`
  - `source_file`
  - `row_index`
  - `timestamp`
- transport context:
  - `dst_port`
  - `protocol`
- raw flow metrics:
  - `flow_duration`
  - `tot_fwd_pkts`
  - `tot_bwd_pkts`
  - `totlen_fwd_pkts`
  - `totlen_bwd_pkts`
  - và nhiều numeric flow metrics khác
- label views:
  - `attack_label_raw`
  - `attack_family`
  - `label_binary`
  - `target_label`

Sau normalize, nên nhìn dữ liệu thành 6 nhóm:

- `event metadata`
  - `event_id`
  - `source_file`
  - `timestamp`
- `transport manifold`
  - `protocol`
  - `dst_port`
- `volume manifold`
  - packets
  - bytes
  - rates
- `directionality manifold`
  - forward/backward packet relation
  - forward/backward byte relation
- `timing manifold`
  - duration
  - active
  - idle
- `flag/control manifold`
  - SYN
  - ACK
  - RST
  - URG

Ý chính:

- raw flow metrics giữ lại vì đó là material gốc
- derived features dùng để gom tín hiệu về các khối hành vi dễ học hơn
- features train chính nên bám vào volume, direction, timing, transport, flags

## 5. Strategy: Split Thành Nhiều Phase

Không nên làm một bước duy nhất kiểu `raw flow row -> flat vector`.

Nên split thành nhiều phase:

### Phase 1: Normalize

Làm data theo các bước:

- đọc raw CICFlowMeter CSV
- drop các duplicated header rows nếu bị lẫn trong file lớn
- rename headers về `snake_case`
  - ví dụ:
    - `Dst Port -> dst_port`
    - `Flow Bytes/s -> flow_bytes_per_s`
    - `Tot Fwd Pkts -> tot_fwd_pkts`
- rename `label` thành `attack_label_raw`
  - đây là nhãn gốc của dataset
  - chưa phải chỉ là attack hay không
  - ví dụ có thể là `Benign`, `Infilteration`, `DoS attacks-Hulk`, `FTP-BruteForce`
- parse `timestamp`
- convert các cột flow metric sang numeric
- replace `inf/-inf` về `NaN`, rồi fill numeric missing bằng `0`
- cast các cột quan trọng như `dst_port`, `protocol` về integer
- map raw label sang:
  - `attack_family`
  - `label_binary`
  - `target_label` theo `label_mode`
- thêm metadata:
  - `source_file`
  - `row_index`
  - `event_id`
- sort data theo `timestamp`, `row_index`

Kết quả của phase này là:

- schema ổn định
- label có nhiều view để train/evaluate
- numeric flow metrics ở dạng sạch để build feature tiếp

Giải thích thêm:

- `attack_label_raw` là nhãn nguyên bản của benchmark
- `attack_family` là nhãn gộp bớt để train/evaluate ổn định hơn
- `label_binary` mới là benign vs attack

Phải map nhiều family vì:

- trang UNB công bố dataset này có nhiều attack scenarios chứ không chỉ `Benign` và `Infilteration`
- code nên chịu được nhiều file/subset khác nhau của CICIDS2018
- downstream evaluation cần có view:
  - binary
  - family
  - raw label

### Phase 2: Noise Reduction / Stable Mapping

Làm data theo các bước:

- giữ raw `dst_port` và `protocol` lại, nhưng không xem đó là semantic đầy đủ
- map transport context sang representation ổn định hơn thay vì chỉ để nguyên integer
- tách phần transport semantics khỏi phần volume/timing để tránh một field dominate toàn bộ model

Ví dụ practical nên làm:

- map `protocol` thành protocol flags:
  - `is_tcp`
  - `is_udp`
- map `dst_port` thành coarse transport tokens hoặc indicators:
  - `is_well_known_port`
  - `is_high_port`
  - sau này có thể thêm:
    - `service_port_group`
    - `is_ephemeral_port`
    - `is_uncommon_service_port`

Ý của phase này là:

- integer như `443`, `80`, `22`, `3389` không nên được xem như semantic hoàn chỉnh
- `well-known port` hay `high port` chỉ là weak context signal, không phải bằng chứng attack
- attacker hoàn toàn có thể dùng port phổ biến như `80/443/22`
- nên port feature phải đứng cùng volume/timing/flags, không được làm dominant signal
- mục đích là đổi transport context thành nhóm ổn định hơn để giảm shortcut, không phải gắn cứng `port phổ biến = benign`

### Phase 3: Behavioral Feature Build

Làm data theo các bước:

- build derived features từ raw flow metrics theo từng manifold hành vi
- không trộn bừa tất cả numeric columns, mà tạo feature có meaning rõ ràng
- mỗi nhóm metric tạo ra một block feature riêng

Lý do phải chia block như vậy:

- mỗi block trả lời một câu hỏi hành vi khác nhau
- nếu trộn hết vào một khối, model rất dễ bám shortcut như port hoặc một vài metric scale lớn
- tách block giúp audit rõ flow bất thường vì volume, timing, direction hay flags
- cách chia này cũng khớp với vai trò của Network Layer:
  - filter
  - score
  - giải thích vì sao cần escalate

Ý nghĩa của từng block:

- `volume block`
  - trả lời: flow này lớn hay nhỏ bất thường
  - hữu ích cho `DoS/DDoS`, bulk transfer, flood-like traffic
- `directionality block`
  - trả lời: flow có lệch mạnh một chiều hay không
  - hữu ích khi attacker gửi nhiều nhưng nhận rất ít, hoặc ngược lại
- `timing block`
  - trả lời: flow burst, dày, ngắn-gắt, hay kéo dài bất thường
  - hữu ích cho rate anomaly và session-shape anomaly
- `packet/header shape block`
  - trả lời: kích thước packet/header có pattern lạ hay không
  - hữu ích khi traffic có cấu trúc packet không giống benign baseline
- `bulk behavior block`
  - trả lời: có dấu hiệu transfer/bulk direction rõ không
  - hữu ích cho exfiltration hoặc upload/download behavior
- `flag/control block`
  - trả lời: control behavior của TCP có bất thường không
  - hữu ích cho SYN-heavy, reset-heavy, urgent-flag oddity

Ví dụ theo từng block:

- volume block:
  - `total_packets`
  - `total_bytes`
  - `bytes_per_packet`
- directionality block:
  - `fwd_bwd_packet_ratio`
  - `fwd_bwd_bytes_ratio`
  - `down_up_ratio_clipped`
- timing block:
  - `flow_bytes_per_second_log1p`
  - `flow_packets_per_second_log1p`
  - `active_idle_ratio`
- packet/header shape block:
  - `avg_packet_length_delta`
  - `header_length_ratio`
- bulk behavior block:
  - `bulk_forward_indicator`
  - `bulk_backward_indicator`
- flag/control block:
  - `syn_ack_flag_ratio`
  - `reset_flag_present`
  - `urgent_flag_present`

Điểm chính:

- mỗi feature nên diễn giải được về network behavior
- feature tốt là feature nói được flow này đang lớn/nhỏ, lệch/cân, burst/chậm, control flags lạ/bình thường

### Phase 4: Multi-Resolution Feature Build

Làm data theo các bước:

- với numeric flow metrics có range rộng, không chỉ giữ một bản raw
- tạo thêm bản `log1p`
- tạo thêm bản clipped hoặc bin/coarse ordinal nếu cần
- làm việc này nhất quán cho byte, packet, rate, duration, ratio

Ví dụ practical:

- với packet/byte count:
  - giữ raw `total_packets`, `total_bytes`
  - thêm `log1p(total_packets)`, `log1p(total_bytes)`
  - nếu cần thì thêm count bin
- với rate:
  - giữ raw rate
  - thêm `log1p(rate)`
  - nếu tail quá dài thì thêm coarse bin
- với ratio:
  - giữ raw ratio khi còn ổn định
  - clip phần tail cực lớn để tránh outlier dominate
  - nếu cần thì thêm bin cho các regime như low/balanced/high

`log1p` để làm gì:

- nén scale rất lớn
- giữ được thứ tự lớn nhỏ
- giúp model thấy relative change tốt hơn ở long-tail metrics

`bin` để làm gì:

- đổi số liên tục thành regime thô
- giúp model học kiểu:
  - thấp
  - vừa
  - cao
  - cực cao
- giảm nhiễu khi exact numeric value không quá quan trọng

`clip` để làm gì:

- chặn outlier cực đoan kéo lệch toàn bộ distribution
- đặc biệt hữu ích cho flow rate hoặc ratio có tail rất dài

### Phase 5: Head-Specific Scoring

Làm data theo các bước:

- chia feature matrix thành nhiều block theo characteristic thay vì một khối phẳng duy nhất
- mỗi block tương ứng một head hay một nhóm signal
- train model riêng cho từng block, hoặc feed từng block vào encoder riêng nếu dùng neural model

Ví dụ chia block:

- `volume head`:
  - `total_packets`
  - `total_bytes`
  - `bytes_per_packet`
- `directionality head`:
  - `fwd_bwd_packet_ratio`
  - `fwd_bwd_bytes_ratio`
  - `down_up_ratio_clipped`
- `timing head`:
  - flow duration
  - active/idle relation
  - packet/byte rate
- `transport head`:
  - protocol indicators
  - port group indicators
- `flag head`:
  - SYN/ACK/RST/URG behavior

Sau đó kết hợp outcome giữa các head bằng một tầng fusion như:

- weighted average
- logistic regression trên các head scores
- gradient boosting trên vector score của các head
- neural fusion MLP nếu dùng multi-encoder

### Phase 6: Multi-Manifold Fusion

Làm data theo các bước:

- giữ riêng từng manifold trước khi fusion:
  - transport manifold
  - volume manifold
  - directionality manifold
  - timing manifold
  - flag/control manifold
- trong mỗi manifold, biểu diễn tín hiệu ở resolution phù hợp:
  - raw
  - log
  - clip
  - bin
- chỉ fusion các manifold sau khi mỗi manifold đã tạo ra signal tương đối ổn định

Ví dụ practical:

- transport manifold:
  - `protocol`
  - `is_tcp`
  - `is_udp`
  - `is_well_known_port`
  - `is_high_port`
- volume manifold:
  - `total_packets`
  - `total_bytes`
  - `bytes_per_packet`
- directionality manifold:
  - `fwd_bwd_packet_ratio`
  - `fwd_bwd_bytes_ratio`
  - `down_up_ratio_clipped`
- timing manifold:
  - `flow_duration`
  - `flow_bytes_per_second_log1p`
  - `flow_packets_per_second_log1p`
  - `active_idle_ratio`
- flag/control manifold:
  - `syn_ack_flag_ratio`
  - `reset_flag_present`
  - `urgent_flag_present`

Thứ tự xử lý nên là:

- normalize raw flow data
- map transport context sang stable semantics
- build behavior-friendly derived features
- expand large-range numeric signals ra raw/log/clip/bin
- chia feature theo manifold/head
- train từng head hoặc encoder riêng
- fusion head outputs thành final network risk

## 6. One Head Detect One Characteristic

Đây là mindset quan trọng để giảm việc model học shortcut.

Ví dụ:

- head 1 không cố học cả port + protocol + bytes + timing + flags trong một vector phẳng
- head 1 chỉ nhìn `volume abnormality`
- head 2 chỉ nhìn `directionality abnormality`
- head 3 chỉ nhìn `timing irregularity`
- head 4 chỉ nhìn `transport context`
- head 5 chỉ nhìn `flag/control anomaly`

Lợi ích:

- dễ audit hơn
- dễ biết flow bị score cao vì volume, timing hay flags
- giảm nguy cơ một field như `dst_port` dominate toàn bộ model

## 7. Multi-Resolution Và Manifold Mindset

Raw network data thường không nằm trên một scale duy nhất.

Ví dụ:

- `total_packets = 2` và `total_packets = 8` có thể khác nhau đáng kể
- nhưng `total_packets = 5000` cũng phải được giữ lại
- nếu chỉ dùng raw count, tail rất lớn có thể làm tín hiệu nhỏ bị chìm

Do đó nên dùng `multi-resolution`:

- raw giữ magnitude
- log giữ relative change ở tail dài
- clip giữ outlier không phá distribution
- bin giữ coarse regime

Nói rõ hơn:

- raw trả lời: giá trị thật là bao nhiêu
- `log1p` trả lời: mức tăng này có lớn tương đối không
- `clip/bin` trả lời: flow đang thuộc vùng hành vi nào

`manifold` ở đây nên hiểu thực dụng:

- transport là một manifold
- volume là một manifold
- directionality là một manifold
- timing là một manifold
- flags/control là một manifold

Không trộn thô tất cả modalities ngay từ đầu.
Nên giữ chúng tách ra trước, rồi mới fusion ở downstream.

## 8. Leakage Và Generalization Control Rules

### Rule 1: không để model thắng nhờ dataset artifact

Không nên để model phụ thuộc quá mạnh vào:

- raw `dst_port`
- một số attack labels quá đặc trưng benchmark
- source file pattern

Nếu để các field này dominate, model có thể thắng trên benchmark nhưng fail ngoài production.

### Rule 2: transport context chỉ là một phần của behavior

Được phép:

- dùng protocol flags
- dùng coarse port semantics
- dùng service-port grouping

Không nên:

- xem `dst_port = X` gần như là bằng chứng đủ mạnh cho attack

### Rule 3: split phải phản ánh tương lai

Không random row split nếu điều đó làm train/test chia sẻ cùng pattern lab quá mạnh.

Tốt hơn là:

- split theo thời gian
- hoặc ít nhất audit thêm theo `attack_family`
- hoặc holdout một số family/scenario để xem generalization

### Rule 4: đánh giá theo nhiều view label

Không chỉ nhìn một metric duy nhất.

Nên xem riêng:

- binary benign vs attack
- attack family
- performance theo từng family
- performance khi port/context thay đổi

## 9. Process Để Train Phù Hợp Với Network Layer

Không nên chỉ có một cách train duy nhất.
Nên tách thành các process train phù hợp với mục đích của layer mạng.

### 9.1 Process A: binary network anomaly baseline

Dùng khi cần một baseline nhanh cho Network Layer:

- target:
  - `label_binary`
- features:
  - volume
  - directionality
  - timing
  - transport indicators
  - flag/control
- model:
  - tree-based baseline như LightGBM / XGBoost / RandomForest
- split:
  - ưu tiên time-based split
  - ít nhất phải tránh train/test lẫn cùng pattern benchmark quá mạnh
- evaluate:
  - ROC-AUC
  - PR-AUC
  - recall ở low false-positive regime

Khi nào dùng:

- cần network risk score tổng quát
- cần filter nhanh trước khi escalate

### 9.2 Process B: family-level training

Dùng khi cần biết abnormal theo family nào mạnh hơn:

- target:
  - `attack_family`
- giữ cùng feature blocks như process A
- audit confusion matrix theo family:
  - `DoS/DDoS`
  - `Brute Force`
  - `Infiltration`
  - `Botnet`
  - `Heartbleed`
  - `Web Attack`

Khi nào dùng:

- muốn biết layer mạng phân biệt family nào tốt
- muốn xác định family nào nên escalate tiếp sang Application Layer

### 9.3 Process C: head-based ensemble training

Dùng khi muốn bám sát mindset nhiều head:

- model 1 chỉ nhìn volume block
- model 2 chỉ nhìn directionality block
- model 3 chỉ nhìn timing block
- model 4 chỉ nhìn transport block
- model 5 chỉ nhìn flag/control block
- lấy score của từng head làm input cho fusion model

Fusion model có thể là:

- logistic regression
- gradient boosting
- weighted average

Khi nào dùng:

- cần audit rõ ràng
- muốn biết head nào đóng góp mạnh nhất cho score cuối

### 9.4 Process D: generalization-first evaluation

Dùng khi muốn test domain này đúng tinh thần system-wide:

- train trên một số family mạnh về network behavior:
  - `DoS/DDoS`
  - `Brute Force`
  - `Infiltration`
  - `Botnet`
- giữ lại một số family khó hơn hoặc khác shape để evaluate riêng
- audit thêm theo:
  - port groups
  - protocol
  - source file/day

Khi nào dùng:

- muốn kiểm tra model có học behavior thật không
- muốn giảm rủi ro benchmark memorization

### 9.5 Thứ tự train nên bắt đầu

Thứ tự thực dụng nhất:

1. train `binary baseline`
2. audit top shortcut features, nhất là `dst_port`
3. train `family-level model`
4. nếu cần explainability tốt hơn thì chuyển sang `head-based ensemble`
5. cuối cùng mới làm holdout/generalization experiments

## 10. Rewrite Code Theo Mindset Này

Code hiện tại nên đi theo cấu trúc sau:

### 8.1 Normalizer

Trong [normalizer.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/cicids2018/normalizer.py):

- normalize header names
- parse timestamp
- convert raw flow metrics sang numeric
- map raw label sang `attack_family`
- build `label_binary`
- build `target_label`
- thêm metadata để trace ngược file và row

Mục tiêu thực dụng:

- schema sạch
- label views rõ ràng
- dữ liệu sẵn sàng cho feature build

### 8.2 Feature Builder

Trong [feature_builder.py](/home/ad1/Project/adaptive-multi-agent-siem/src/domains/cicids2018/feature_builder.py):

- build volume features:
  - `total_packets`
  - `total_bytes`
  - `bytes_per_packet`
- build directionality features:
  - `fwd_bwd_packet_ratio`
  - `fwd_bwd_bytes_ratio`
  - `down_up_ratio_clipped`
- build timing/rate features:
  - `flow_bytes_per_second_log1p`
  - `flow_packets_per_second_log1p`
  - `active_idle_ratio`
- build transport indicators:
  - `is_tcp`
  - `is_udp`
  - `is_well_known_port`
  - `is_high_port`
- build flag/control features:
  - `syn_ack_flag_ratio`
  - `reset_flag_present`
  - `urgent_flag_present`

Các feature này gần với objective của Network Layer hơn là việc giữ một bảng numeric thô.

## 11. Cách Chuẩn Bị Dữ Liệu Train

Khi đưa vào model, nên tách tối thiểu 4 khối:

- `volume block`
  - packet
  - byte
  - bytes per packet
- `directionality/timing block`
  - ratios
  - duration
  - rates
  - active/idle
- `transport/flag block`
  - protocol flags
  - port group indicators
  - control flags
- `target/metadata block`
  - `target_label`
  - `attack_family`
  - `label_binary`
  - metadata chỉ để trace/eval, không đưa thẳng vào train feature

Nếu chỉ làm baseline model:

- ưu tiên volume + directionality + timing + transport indicators
- hạn chế để raw port integer trở thành dominant feature
- audit riêng hiệu quả theo attack family

## 12. Kết Luận Thực Dụng

Mindset tốt cho CICIDS2018 domain là:

- đừng học benchmark artifact
- đừng để raw port dominate
- đừng trộn mọi flow metric thành một khối phẳng
- đừng xem đúng label benchmark là mục tiêu duy nhất

Thay vào đó:

- split thành nhiều phase
- giảm shortcut từ transport context
- build feature theo network behavior
- dùng multi-resolution cho numeric range lớn
- tách nhiều head theo từng characteristic rồi mới fusion

Đó là cách xử lý data gần với vai trò `Network Layer` của toàn hệ thống hơn, và cũng dễ generalize hơn khi đi từ benchmark lab sang traffic thật.

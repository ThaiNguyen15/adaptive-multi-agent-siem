# Tổng Hợp Dataset và Goal Hệ Thống Adaptive Multi-Agent SIEM

## Tổng Quan Hệ Thống

Hệ thống được thiết kế theo kiến trúc phân tầng **adaptive multi-agent SIEM** để tối ưu hóa hiệu suất, giảm false positive và xử lý linh hoạt các loại tấn công:

### Kiến Trúc Phân Tầng
1. **Trigger Layer (Login)**: Điểm vào chính cho authentication-related anomalies
2. **Network Layer (O4)**: Phát hiện anomalies ở tầng network/transport
3. **Application Layer**: Phân tích sâu payload và request/response behavior

### Luồng Xử Lý Linh Hoạt
- **Không phải luồng tuyến tính cố định**: Hệ thống adaptive có thể trigger từ bất kỳ layer nào, hoặc từ external alerts (SIEM logs, IDS alerts, etc.)
- **Hierarchical Escalation**: Mỗi layer có thể tự quyết định escalate lên layer cao hơn nếu phát hiện abnormal behavior
- **Filter Theo Layer**: Mỗi layer focus vào khía cạnh riêng để tránh noise và optimize performance

**Ví dụ thực tế**:
- User bình thường (login OK, network bình thường) nhưng biết SQL injection: Chỉ affect **Application Layer** (API traffic analysis phát hiện malicious payload). **Login Layer** và **Network Layer** không notify vì không có dấu hiệu ở đó.
- User brute force login: Trigger từ **Login Layer** → Escalate sang **Network Layer** để xác nhận traffic patterns.
- DDoS attack: Có thể trigger trực tiếp từ **Network Layer** mà không qua login.

Luồng cơ bản: Login Abnormal → Check Network → Nếu Network Abnormal → Check Application. Nhưng hệ thống hỗ trợ multiple entry points để cover tất cả scenarios.

## Chi Tiết Goal Từng Dataset

### 1. Login Dataset
**Vị trí trong hệ thống**: Trigger Layer (điểm vào chính)

**Goal chi tiết**:
- Phát hiện `abnormal login behavior` theo từng user
- Nhận ra thay đổi hành vi (IP mới, device mới, location mới)
- Hỗ trợ risk scoring và anomaly detection
- Tập trung vào pattern theo thời gian, không phải từng record độc lập
- Tách biệt các nhóm feature: identity, network context, geo context, device context, temporal behavior

**Khớp với hệ thống**: Là một trong các entry points chính cho authentication anomalies. Khi phát hiện login abnormal, có thể escalate sang Network Layer để xác nhận traffic patterns. Hoặc hoạt động độc lập nếu chỉ cần login analysis.

### 2. CICIDS2018 Dataset
**Vị trí trong hệ thống**: Network Layer (O4) - Flow-level network traffic

**Goal chi tiết**:
- Phát hiện bất thường mạng ở mức flow
- Nắm được pattern tấn công qua traffic behavior
- Tạo representation dùng được ngoài dataset lab
- Tách nhóm feature: volume, directionality, timing, transport, flags
- Tránh phụ thuộc vào artifact riêng của dataset (port-specific memorization)

**Khớp với hệ thống**: Phát hiện network anomalies có thể trigger từ Login Layer (login abnormal), từ Application Layer (nếu cần xác nhận traffic), hoặc từ external alerts (DDoS, scanning). Nếu phát hiện abnormal, có thể escalate sang Application Layer để phân tích payload.

### 3. Brute Force HTTPS Dataset
**Vị trí trong hệ thống**: Network Layer (O4) - HTTPS-specific brute force detection

**Goal chi tiết**:
- Phát hiện `HTTPS brute-force attempt`
- Nhận ra pattern ổn định qua attack tools và target applications
- Tạo feature cho production-like detection
- Tách nhóm: volume, timing, service context, scenario metadata
- Tránh shortcut learning qua scenario/tool/app specifics

**Khớp với hệ thống**: Bổ sung cho CICIDS2018 trong Network Layer, tập trung vào HTTPS-specific attacks. Có thể trigger từ Login Layer (brute force login attempts) hoặc trực tiếp từ network monitoring. Khi phát hiện abnormal, hỗ trợ escalate sang Application Layer.

### 4. API Traffic Dataset
**Vị trí trong hệ thống**: Application Layer - Request/response analysis

**Goal chi tiết**:
- Phát hiện `malicious request behavior`
- Tách rõ attacker-controlled input khỏi system response
- Kiểm tra leakage giữa request-side và response-side
- Tách modalities: request, response, protocol metadata, abstraction/token stats
- Ưu tiên request-only features để tránh response leakage
- Giữ `response_only` như leakage-audit path và `combined` như upper bound tham khảo
- Tập trung vào attack-shape learning thay vì endpoint/raw literal memorization
- Hỗ trợ cả 2 task của ATRDF:
  - binary `Benign` vs `Malware`
  - multi-class `attack_type`
- Bao phủ các nhóm attack chính:
  - `Cookie Injection`
  - `Directory Traversal`
  - `LOG4J`
  - `Log Forging`
  - `RCE`
  - `SQL Injection`
  - `XSS`
- Chú ý độ khó tăng dần qua `Dataset_1` đến `Dataset_4`, nên abstraction càng quan trọng ở các dataset sau

**Khớp với hệ thống**: Layer cuối cùng cho payload analysis. Có thể trigger từ Network Layer (network abnormal), từ Login Layer (nếu cần phân tích request trong login context), hoặc trực tiếp từ application monitoring (SQL injection, XSS, etc.). Phân tích sâu malicious intent, tách biệt attacker input và system reactions.

## Nguyên Tắc Chung Đảm Bảo Khớp Nhau

1. **Adaptive Triggering**: Mỗi layer có thể trigger độc lập hoặc từ layer khác/external alerts. Không bắt buộc luồng tuyến tính.
2. **Hierarchical Escalation**: Escalate lên layer cao hơn chỉ khi cần thiết để giảm false positive và optimize performance.
3. **Feature Separation**: Mỗi domain tách nhóm feature riêng, tránh trộn thô
4. **Leakage Prevention**: Ưu tiên features không bị leak từ downstream reactions
5. **Generalization Focus**: Features phải ổn định qua users/tools/apps, không dataset-specific
6. **Temporal Awareness**: Tất cả domains đều nhấn mạnh pattern theo thời gian
7. **Multi-resolution Numeric**: Sử dụng raw + log + bin cho metrics có range rộng

## Risk Mitigation

- **Login**: Tránh ID memorization, đảm bảo time-based split
- **Network (CICIDS2018/Brute Force)**: Tránh port/label artifacts, test generalization theo attack family
- **API Traffic**: Audit response leakage, ưu tiên request-centric features

Hệ thống này đảm bảo efficiency bằng cách chỉ phân tích sâu khi cần thiết, giảm computational cost và false alarms.

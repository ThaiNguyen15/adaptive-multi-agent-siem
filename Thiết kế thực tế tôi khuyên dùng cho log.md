  Thiết kế thực tế tôi khuyên dùng cho login domain

  1. Raw logs
  2. Normalize schema
  3. Partition theo hash(user_id)
  4. Sort trong shard theo timestamp
  5. Build history features theo rolling window
  6. Ghi parquet
  7. Split train/val/test theo thời gian
  8. Train model
  9. Inference online dùng đúng logic state giống lúc build feature offline

  Viết cho tôi một thiết kế cụ thể cho dataset login của bạn:

  - cấu trúc thư mục shard
  - rule split train/val/test
  - danh sách feature nên giữ

  Viết theo cấu trúc chuẩn của 1 Expert Data Engineer, làm phase process data trước, viết code theo pattern chuẩn, chia code ra cho dễ đọc, maintain, scale, bởi vì tui còn nhiều dataset khác phải process (agent log, agent network) theo cách khác nên cần viết 1 cách hợp lí
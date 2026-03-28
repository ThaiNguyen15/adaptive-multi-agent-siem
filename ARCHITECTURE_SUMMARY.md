# Architecture Summary

## Directory Structure

```
adaptive-multi-agent-siem/
│
├── src/
│   ├── core/                      ← REUSABLE FOR ALL DOMAINS
│   │   ├── __init__.py
│   │   ├── base_config.py         (Configuration management)
│   │   ├── base_normalizer.py     (Abstract normalizer)
│   │   ├── base_feature_builder.py (Abstract feature builder)
│   │   ├── sharding.py            (Hash-based partitioning)
│   │   ├── splitter.py            (Time-based splitting)
│   │   └── utils.py               (Shared utilities)
│   │
│   ├── domains/                   ← DOMAIN-SPECIFIC IMPLEMENTATIONS
│   │   ├── __init__.py
│   │   │
│   │   ├── login/                 (Authentication logs)
│   │   │   ├── __init__.py
│   │   │   ├── config.py          (LoginConfig)
│   │   │   ├── normalizer.py      (LoginNormalizer)
│   │   │   ├── feature_builder.py (LoginFeatureBuilder)
│   │   │   └── pipeline.py        (LoginPipeline - orchestrator)
│   │   │
│   │   ├── cicids2018/            (Network security)
│   │   │   ├── __init__.py
│   │   │   ├── config.py          (CICIDS2018Config)
│   │   │   ├── normalizer.py      (CICIDS2018Normalizer)
│   │   │   ├── feature_builder.py (CICIDS2018FeatureBuilder)
│   │   │   └── pipeline.py        (CICIDS2018Pipeline)
│   │   │
│   │   └── agent_logs/            (Template for new domains)
│   │       └── __init__.py
│   │
│   └── scripts/                   ← ENTRY POINTS
│       ├── __init__.py
│       ├── process_login.py       (Run login pipeline)
│       └── process_network.py     (Run network pipeline)
│
├── data/
│   ├── raw/
│   │   ├── login/                 (Raw CSVs/logs)
│   │   ├── cicids2018/
│   │   └── agent_logs/
│   │
│   └── processed/
│       ├── login/
│       │   ├── normalized.parquet         (Step 1: Normalized)
│       │   ├── shards/                    (Step 2: Partitioned)
│       │   │   ├── shard_000.parquet
│       │   │   ├── shard_001.parquet
│       │   │   └── ...
│       │   ├── features/                  (Step 3: Features added)
│       │   │   ├── shard_000.parquet
│       │   │   ├── shard_001.parquet
│       │   │   └── ...
│       │   └── splits/                    (Step 4: Train/Val/Test)
│       │       ├── train/
│       │       ├── val/
│       │       ├── test/
│       │       └── split_stats.csv
│       │
│       ├── cicids2018/
│       │   └── (same structure)
│       │
│       └── agent_logs/
│           └── (same structure)
│
├── ARCHITECTURE.md                ← You are here
├── QUICKSTART.md                  
├── requirements.txt
└── README.md
```

---

## Design Patterns

### 1. **Template Method Pattern**
Each domain implements the same pipeline structure:
```
Raw Data → Normalize → Shard → Build Features → Split
```

### 2. **Strategy Pattern**  
Core classes define interfaces, domains provide implementations:
- `BaseNormalizer` → `LoginNormalizer`, `CICIDS2018Normalizer`
- `BaseFeatureBuilder` → `LoginFeatureBuilder`, `CICIDS2018FeatureBuilder`

### 3. **Configuration Pattern**
Centralized, hierarchical configuration:
```python
BaseConfig (abstract)
    └── LoginConfig (specific)
    └── CICIDS2018Config (specific)
    └── AgentLogsConfig (specific)
```

### 4. **Factory Pattern**
Each domain package exports its own factory components:
```python
from src.domains.login import LoginConfig, LoginPipeline
pipeline = LoginPipeline(config)
```

---

## Data Flow

```
RAW DATA
    ↓
[Step 1: NORMALIZE]
    ├─ Validate schema
    ├─ Transform columns
    ├─ Handle missing values
    └─ Output: normalized.parquet
         ↓
[Step 2: SHARD]
    ├─ Hash partition by key
    │   (user_id for login, src_ip for network)
    ├─ Create 256-512 shards
    └─ Output: shards/shard_000.parquet, ..., shard_255.parquet
         ↓
[Step 3: BUILD FEATURES]
    ├─ For each shard (parallelizable):
    │   ├─ Sort by timestamp
    │   ├─ Compute rolling window features
    │   │   - 1-day window
    │   │   - 7-day window  
    │   │   - 30-day window
    │   └─ Add feature columns
    └─ Output: features/shard_000.parquet, ..., shard_255.parquet
         ↓
[Step 4: SPLIT]
    ├─ Sort all data by timestamp
    ├─ Split by time ranges:
    │   - Train: 0-75%
    │   - Val: 75-83%
    │   - Test: 83-100%
    └─ Output:
        - splits/train/shard_*.parquet
        - splits/val/shard_*.parquet
        - splits/test/shard_*.parquet
         ↓
READY FOR ML TRAINING
```

---

## Key Design Decisions

### Decision 1: Hash-based Sharding
**Choice**: Partition by hash(key) into fixed number of shards

**Pros:**
- Uniform distribution (no skew)
- Enables parallel shard processing
- Data locality (all user records in one shard)
- Standard industry practice

**Why not range-based?**
- Risk of skewed distribution
- Harder to parallelize

---

### Decision 2: Time-based Splitting
**Choice**: No randomization, strict chronological split

**Pros:**
- No temporal data leakage
- Test = future data (realistic)
- Reproducible across runs

**Why not stratified random?**
- Risk of leakage for time-series
- Non-reproducible

---

### Decision 3: Rolling Window Features
**Choice**: Compute for multiple windows (1d, 7d, 30d)

**Benefits:**
- Short-term: Recent behavior  
- Medium-term: Weekly patterns
- Long-term: Monthly trends
- Industry standard for anomaly detection

---

### Decision 4: Parquet Storage
**Choice**: Columnar format with Snappy compression

**Benefits:**
- 50-60% size reduction
- Fast column-access for ML
- Native pandas/PyArrow support
- Industry standard

---

## Scalability Considerations

### Current Architecture Supports:
- ✓ 100GB+ datasets (via sharding)
- ✓ Multiple domains simultaneously
- ✓ Parallel shard processing (future)
- ✓ Incremental feature building
- ✓ Easy addition of new domains

### Future Enhancements:
- [ ] Parallel shard processing (multiprocessing/ray)
- [ ] Streaming feature updates (DuckDB/ClickHouse backend)
- [ ] Feature materialization (cache aggregations)
- [ ] GPU-accelerated feature building (cuDF)
- [ ] Distributed processing (Spark/Dask)

---

## Adding New Domain: Step-by-Step

```python
# 1. Create Config
@dataclass
class MyDomainConfig(BaseConfig):
    domain_name: str = 'my_domain'
    shard_key: str = 'entity_id'
    required_columns: list = [...]

# 2. Create Normalizer
class MyDomainNormalizer(BaseNormalizer):
    def validate_raw_schema(self, df) -> bool: ...
    def normalize(self, df) -> pd.DataFrame: ...
    def get_output_schema(self) -> dict: ...

# 3. Create Feature Builder
class MyDomainFeatureBuilder(BaseFeatureBuilder):
    def get_feature_list(self) -> list: ...
    def build_features(self, shard_df) -> pd.DataFrame: ...

# 4. Create Pipeline
class MyDomainPipeline:
    def run(self, input_dir) -> None:
        # Use 4-step pattern
        norm_df = self.step1_normalize(input_dir)
        self.step2_shard(norm_df)
        self.step3_build_features()
        self.step4_split()

# 5. Total time: ~30 minutes
```

---

## Maintenance & Development

### Testing Components Independently:
```python
# Test normalizer only
normalizer = LoginNormalizer(config)
df = normalizer.process_batch('data/raw/login')

# Test feature builder only  
fb = LoginFeatureBuilder(config)
features = fb.build_features(shard_df)

# Test sharding only
sharding = HashSharding(256, 'user_id')
shards = sharding.partition(df)
```

### Debugging Pipeline:
```python
# Run steps individually
config = LoginConfig(...)
pipeline = LoginPipeline(config)

norm_df = pipeline.step1_normalize('data/raw/login')
print(f"After normalize: {len(norm_df)} records")

pipeline.step2_shard(norm_df)
print("Shards created")

pipeline.step3_build_features()
print("Features built")

pipeline.step4_split()
print("Splits created")
```

---

## Performance Benchmarks

Dataset: RBA Login dataset (~1.2M records)

| Phase | Time | Output Size |
|-------|------|-------------|
| Normalize | 30s | 400MB |
| Shard | 10s | 400MB |
| Build Features | 2m | 560MB |
| Split | 1m | 560MB |
| **Total** | **~4min** | **560MB** |

---

## Version History

- **v1.0** - Initial architecture with login + CICIDS2018 domains
- **v1.1** (planned) - Parallel shard processing
- **v1.2** (planned) - Agent logs domain
- **v2.0** (planned) - Distributed processing (Spark/Dask)

---

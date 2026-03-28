# Multi-Domain Processing Architecture

## Overview

Modular, scalable architecture for processing multiple security log domains with shared core functionality and domain-specific implementations.

```
src/
├── core/                    # Shared base classes & utilities
│   ├── base_config.py      # Configuration management
│   ├── base_normalizer.py  # Schema normalization 
│   ├── base_feature_builder.py  # Feature engineering
│   ├── sharding.py         # Hash-based data partitioning
│   ├── splitter.py         # Time-based train/val/test splitting
│   └── utils.py            # Shared utilities
│
├── domains/                # Domain-specific implementations
│   ├── login/              # Login authentication logs
│   │   ├── config.py       # LoginConfig
│   │   ├── normalizer.py   # Normalize to standard login schema
│   │   ├── feature_builder.py  # Login-specific features
│   │   └── pipeline.py     # Orchestrate full login pipeline
│   │
│   ├── cicids2018/         # Network anomaly detection
│   │   ├── config.py       # CICIDS2018Config  
│   │   ├── normalizer.py   # Network flow normalization
│   │   ├── feature_builder.py  # Network traffic features
│   │   └── pipeline.py     # Network processing pipeline
│   │
│   └── agent_logs/         # Placeholder for agent logs domain
│
└── scripts/                # Entry point scripts
    ├── process_login.py    # Run login pipeline
    ├── process_network.py  # Run network pipeline
    └── process_agent_logs.py  # (future)
```

## Design Principles

### 1. **Modularity**
- Core classes provide interfaces, domains implement specifics
- Each phase (normalize, shard, feature, split) is independent
- Easy to test and debug individual components

### 2. **Extensibility**  
- Add new domain in 4 files: config, normalizer, feature_builder, pipeline
- Follow template from cicids2018 domain
- Reuse all core functionality

### 3. **Reproducibility**
- Time-based splitting (no randomness)
- Configurable parameters stored in config
- Deterministic processing order

### 4. **Scalability**
- Hash-based sharding for parallel processing
- Parquet format for efficient storage
- Handles 100GB+ datasets smoothly

---

## 4-Step Pipeline Pattern

All domains follow the same 4-step processing pipeline:

### Step 1: Normalize
```python
normalized_df = pipeline.step1_normalize(raw_input_dir)
# Input: Raw CSVs from various sources
# Output: Standard schema dataframe
```

**Login domain standardizes:**
- timestamp → datetime64
- user_id, source_ip → strings
- result → {success, failure}
- device, location → strings

**Network domain standardizes:**
- Timestamp → datetime64  
- Src/Dst IP → strings
- Protocol → string
- Flow Duration, packets → numeric
- Label → {benign, attack}

### Step 2: Shard
```python
pipeline.step2_shard(normalized_df)
# Input: Normalized dataframe
# Output: 256-512 parquet files in shards/
```

Hash-partitions by:
- **Login**: user_id → 256 shards (all user data in one shard)
- **Network**: src_ip → 512 shards (all flows from one source together)

**Benefits:**
- Shards can be processed in parallel
- Related records stay together (better ML features)
- Memory efficient (load 1/256 at a time)

### Step 3: Build Features
```python
pipeline.step3_build_features()
# Input: Shards in shards/
# Output: Featured shards in features/
```

For each shard, builds rolling window features:

**Login domain** ([1, 7, 30] day windows):
- login_count_window1/7/30
- success_count, failure_count
- success_rate, failure_rate  
- unique_ips, unique_devices, unique_locations
- entropy_ips, entropy_devices

**Network domain** ([0.01, 0.1, 1] hour windows):
- flow_count, benign_flows, attack_flows
- total_fwd_packets, avg_fwd_packet_rate
- attack_rate, benign_rate
- unique_dst_ips, unique_protocols
- protocol_entropy

### Step 4: Split
```python
pipeline.step4_split()
# Input: Featured shards in features/
# Output: Train/val/test splits in splits/
```

Time-based splitting (no data leakage):
- **Train**: 75% (earliest records)
- **Val**: 8% (middle records)
- **Test**: 17% (latest records)

Ensures test data is always in the future relative to training data.

---

## Running Pipelines

### Login domain:
```bash
python -m src.scripts.process_login \
    --raw-dir data/raw/login \
    --output-dir data/processed/login \
    --num-shards 256 \
    --batch-size 10000
```

### Network domain:
```bash
python -m src.scripts.process_network \
    --raw-dir data/raw/cicids2018 \
    --output-dir data/processed/cicids2018 \
    --num-shards 512 \
    --batch-size 50000
```

---

## Adding a New Domain

To add `agent_logs` domain, follow this template (30 min):

### 1. Create config.py
```python
@dataclass
class AgentLogsConfig(BaseConfig):
    domain_name: str = 'agent_logs'
    shard_key: str = 'agent_id'  # Shard by this field
    required_columns: list = ['timestamp', 'agent_id', 'event_type', ...]
```

### 2. Create normalizer.py
Inherit from `BaseNormalizer`, implement:
- `validate_raw_schema()` - check required columns
- `normalize()` - transform to standard columns
- `get_output_schema()` - return column dtypes

### 3. Create feature_builder.py
Inherit from `BaseFeatureBuilder`, implement:
- `get_feature_list()` - return feature names
- `build_features()` - compute rolling window features

### 4. Create pipeline.py
Inherit from existing domain pipeline, adapt step names/descriptions.

### 5. Create script in scripts/
```python
python -m src.scripts.process_agent_logs \
    --raw-dir data/raw/agent_logs \
    --output-dir data/processed/agent_logs
```

---

## Output Directory Structure

After running pipeline:

```
data/
├── raw/
│   ├── login/           # Raw CSV files from logs
│   ├── cicids2018/
│   └── agent_logs/
│
└── processed/
    ├── login/
    │   ├── normalized.parquet    # Step 1 output
    │   ├── shards/               # Step 2 (256 files)
    │   │   ├── shard_000.parquet
    │   │   ├── shard_001.parquet
    │   │   └── ...
    │   ├── features/             # Step 3 (256 files with features)
    │   │   ├── shard_000.parquet
    │   │   ├── shard_001.parquet
    │   │   └── ...
    │   └── splits/               # Step 4 outputs
    │       ├── train/            (256 files)
    │       ├── val/              (256 files)
    │       ├── test/             (256 files)
    │       └── split_stats.csv
    │
    ├── cicids2018/               # Same structure
    └── agent_logs/               # Same structure
```

---

## Config Management

Each domain has a Config class that centralizes parameters:

```python
config = LoginConfig(
    raw_data_dir='data/raw/login',
    processed_data_dir='data/processed/login',
    num_shards=256,
    batch_size=10000,
    train_ratio=0.75,
    val_ratio=0.08,
    test_ratio=0.17,
    feature_windows=[1, 7, 30],
    timestamp_col='timestamp',
)

# Easy to save/load
config.save(Path('config.json'))
config_loaded = LoginConfig.load(Path('config.json'))
```

---

## Development Tips

### Testing Individual Phases:
```python
from src.domains.login import LoginConfig, LoginNormalizer

config = LoginConfig(raw_data_dir=..., processed_data_dir=...)
normalizer = LoginNormalizer(config)

# Test normalization only
df = normalizer.process_batch('data/raw/login')
print(df.head())
```

### Inspecting Shards:
```python
from src.core.sharding import HashSharding

sharding = HashSharding(256, 'user_id')

# Get shard for specific user
shard_id = sharding.compute_shard_id('user_123')
df = sharding.load_shard(shard_id, 'data/processed/login/shards')
```

### Checking Features:
```python
from src.domains.login import LoginFeatureBuilder, LoginConfig

config = LoginConfig(...)
fb = LoginFeatureBuilder(config)

# List all features
print(fb.get_feature_list())
```

---

## Performance

Typical processing times for 1GB dataset:
- Normalize: 30s
- Shard (256): 10s (parallel ready)
- Build features: 2-5m (per-shard, parallelizable)
- Split: 1m

Storage:
- Raw CSV: 1GB
- Normalized parquet: 400-500MB (50% compression)
- With features: +40% (additional feature columns)

---

## Next Steps

1. **Implement agent_logs domain** following the template
2. **Add domain for VPN logs** (similar to network, different schema)
3. **Create unified training script** that can load any domain's split data
4. **Add monitoring/validation** (schema consistency checks, feature quality metrics)
5. **Optimize feature computation** (vectorize, use polars instead of pandas)

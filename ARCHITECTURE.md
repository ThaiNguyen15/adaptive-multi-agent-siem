# Multi-Domain Processing Architecture

## Overview

Modular, scalable architecture for processing multiple security log domains with shared core functionality and domain-specific implementations.

```
src/
├── core/                    # Shared processing primitives
│   ├── base_config.py
│   ├── base_normalizer.py
│   ├── base_feature_builder.py
│   ├── sharding.py
│   ├── splitter.py
│   └── utils.py
│
├── domains/                # Domain-centric lifecycle packages
│   ├── login/              # Login authentication logs
│   │   ├── processing/     # normalize -> shard -> feature -> split
│   │   │   ├── config.py
│   │   │   ├── normalizer.py
│   │   │   ├── feature_builder.py
│   │   │   └── pipeline.py
│   │   ├── training/       # domain-specific experiment defaults
│   │   │   ├── config.py
│   │   │   └── runner.py
│   │   ├── evaluation/
│   │   │   └── runner.py
│   │   ├── testing/
│   │   │   └── runner.py
│   │   └── __init__.py     # public domain API
│   │
│   ├── cicids2018/
│   ├── api_traffic/
│   ├── brute_force_https/
│   └── agent_logs/
│   │
├── training/               # Train-stage code and experiment artifacts
│   ├── config.py           # ExperimentConfig
│   ├── dataset.py          # Split parquet loader
│   ├── model.py            # NumPy baseline model
│   └── runner.py           # Train runner
│
├── evaluation/             # Validation / offline evaluation stage
│   ├── metrics.py
│   └── runner.py
│
├── testing/                # Final holdout test stage
│   └── runner.py
│
└── scripts/                # Thin CLI entrypoints
    ├── process_login.py
    ├── process_network.py
    ├── process_api_traffic.py
    ├── process_brute_force_https.py
    ├── train_tabular.py
    ├── evaluate_tabular.py
    └── test_tabular.py
```

## Design Principles

### 1. **Domain-First Ownership**
- each domain owns its full lifecycle package: `processing`, `training`, `evaluation`, `testing`
- shared infrastructure can still live outside the domain, but the domain package is the main entry surface

### 2. **Extensibility**
- Add new security domain in `domains/`
- Reuse the same training/evaluation/test stack across domains
- Move from baseline NumPy models to stronger backends later without changing processed data layout

### 3. **Reproducibility**
- Time-based splitting (no randomness)
- Processing config stored in processed directory
- Experiment config stored in experiment directory
- Deterministic processing order

### 4. **Scalability**
- Hash-based sharding for parallel processing
- Parquet format for efficient storage
- Processing and modeling are decoupled, so the same processed dataset can back multiple experiments

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

## Training / Evaluation / Testing

Once a processed dataset exists, the ML lifecycle is independent from preprocessing.

### Train
```bash
python -m src.scripts.train_tabular \
    --processed-dir data/processed/login \
    --experiment-dir experiments/login_baseline \
    --label-col login_successful \
    --feature-blocks temporal novelty continuity familiarity outcome_pressure diversity
```

### Evaluate
```bash
python -m src.scripts.evaluate_tabular \
    --processed-dir data/processed/login \
    --experiment-dir experiments/login_baseline \
    --label-col login_successful \
    --split val
```

### Test
```bash
python -m src.scripts.test_tabular \
    --processed-dir data/processed/login \
    --experiment-dir experiments/login_baseline \
    --label-col login_successful
```

The current training stack is intentionally simple:

- it expects a binary numeric target column
- it reads feature groups from `feature_manifest.json` when available
- it trains a NumPy logistic-regression baseline
- it writes reports and parquet predictions per split

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

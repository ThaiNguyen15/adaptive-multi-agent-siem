# Quick Start Guide - Multi-Domain Processing

## 1. Running Login Pipeline  

```bash
# Activate environment
source .venv/bin/activate

Install the required packages:

```bash
pip install -r requirements.txt
```

# Process login data
python -m src.scripts.process_login \
    --raw-dir data/raw/rba-dataset/test \
    --output-dir data/processed/login \
    --num-shards 3 \
    --batch-size 10
```
# View parquet
python3 -m src.scripts.inspect_parquet \
  --file data/processed/login/splits/train/shard_000.parquet \
  --rows 10


## 2. Running Network Pipeline

```bash
# Process CICIDS 2018 CICFlowMeter data
python -m src.scripts.process_network \
    --raw-dir data/raw/cicflowmeter/Processed\ Traffic\ Data\ for\ ML\ Algorithms \
    --output-dir data/processed/cicids2018 \
    --num-shards 256 \
    --batch-size 50000 \
    --label-mode binary
```

## 3. Running HTTPS Brute-force Pipeline

```bash
# Recommended default: repo-native processing from aggregated flows
python3 -m src.scripts.process_brute_force_https \
    --raw-dir data/raw/brute-force-dataset \
    --output-dir data/processed/brute_force_https \
    --input-view aggregated_flows \
    --num-shards 128 \
    --batch-size 25000 \
    --label-mode binary
```

```bash
# Fast baseline from author-provided engineered samples
python3 -m src.scripts.process_brute_force_https \
    --raw-dir data/raw/brute-force-dataset \
    --output-dir data/processed/brute_force_https_samples \
    --input-view samples \
    --num-shards 64 \
    --batch-size 25000 \
    --label-mode binary
```

```bash
# Generalization experiment target: predict attack tool instead of binary label
python3 -m src.scripts.process_brute_force_https \
    --raw-dir data/raw/brute-force-dataset \
    --output-dir data/processed/brute_force_https_tool \
    --input-view aggregated_flows \
    --num-shards 128 \
    --batch-size 25000 \
    --label-mode tool
```

Why `brute_force_https` is processed this way:

- the public dataset ships in 3 views: `flows.csv`, `aggregated_flows.csv`, and `samples.csv`
- `aggregated_flows` is the best default for this repo because it is still flow-centric but avoids the heavier packet-prefix parsing cost of `flows.csv`
- `samples` is useful for a fast benchmark because the dataset authors already extracted features
- sharding uses `service_key` instead of `dst_port`, because a large share of the data targets HTTPS on port `443` and `dst_port` alone would create skew

Recommended usage:

- start with `aggregated_flows + label_mode=binary` for the main baseline
- run `samples + label_mode=binary` to compare against the author-engineered feature space
- use `label_mode=tool` or `label_mode=app` when you want cross-tool or cross-application generalization experiments

Current limitation:

- the core splitter is still time-based, so scenario-holdout evaluation is not yet automated in the pipeline

## 4. Running API Traffic Pipeline

```bash
# Process ATRDF / Cisco Ariel API traffic data
python -m src.scripts.process_api_traffic \
    --raw-dir data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets/test \
    --output-dir data/processed/api_traffic \
    --num-shards 16 \
    --batch-size 5000 \
    --task-type binary \
    --feature-mode request_only \
    --text-mode hybrid
```

```bash
# Example for leakage audit using response-only features
python -m src.scripts.process_api_traffic \
    --raw-dir data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets \
    --output-dir data/processed/api_traffic_response_audit \
    --num-shards 64 \
    --batch-size 5000 \
    --task-type binary \
    --feature-mode response_only \
    --text-mode hybrid
```

```bash
# Example for multiclass attack-type preparation with combined view
python -m src.scripts.process_api_traffic \
    --raw-dir data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets \
    --output-dir data/processed/api_traffic_attack_type \
    --num-shards 256 \
    --batch-size 5000 \
    --task-type attack_type \
    --feature-mode combined \
    --text-mode hybrid
```

```bash
# View processed API traffic parquet
python3 -m src.scripts.inspect_parquet \
  --file data/processed/api_traffic/splits/train/shard_000.parquet \
  --rows 10
```

Notes on `--num-shards` for `api_traffic`:

- Yes, this domain supports `--num-shards`
- Higher shard counts can help when datasets are large and you want smaller parquet files or parallel downstream loading
- Too many shards can slow processing because of extra file overhead
- For Dataset 1 or small local tests, use `16` to `64`
- For larger datasets like Dataset 3 or 4, `128` to `512` is a reasonable starting range
- `api_traffic` is event-level, so sharding is mainly for scale and I/O management, not for preserving per-user history like the `login` domain

### Why `api_traffic` is processed this way

ATRDF / Cisco Ariel is an event-level HTTP security dataset. Each sample is one
API request/response transaction, not a long user behavior history like the
`login` domain.

The preprocessing strategy is intentionally split into request and response
modalities:

- `request` is the primary signal for security detection because it contains the
  attacker-controlled payload: URL, query string, headers, cookies, and body
- `response` is kept separately because it is useful for debugging and leakage
  auditing, but it should not automatically become the main source of truth for
  a security model

Why separate `request` and `response` instead of merging everything immediately:

- request-side features help model malicious intent or attack attempts
- response-side features can reveal dataset shortcuts, for example a model that
  learns to predict from `401`, `404`, or error strings instead of from the
  attack payload itself
- keeping them separate makes it easy to compare:
  - `request_only`: request-centric modeling
  - `response_only`: leakage audit
  - `combined`: upper-bound practical performance

Important interpretation:

- a suspicious request does not automatically mean the backend is truly
  vulnerable
- for this dataset, labels are closer to `malicious request family` than to
  `confirmed exploit success`
- this is why request-centric detection is useful, but should be interpreted as
  attack-attempt detection, not guaranteed compromise detection

What the pipeline does for `api_traffic`:

1. Normalize nested JSON into a flat event schema
2. Create modality-separated text fields:
   `request_text`, `response_text`, `combined_text`
3. Build lexical and token-stat features according to:
   `feature_mode=request_only|response_only|combined`
4. Save shards and train/val/test splits for downstream experiments

Recommended next steps after preprocessing:

- train a `request_only` baseline first
- train a `response_only` model to audit leakage
- train a `combined` model to measure the accuracy ceiling on this dataset
- compare all three before deciding what to trust in production-like settings

## 5. Using Output for ML Training

```python
import pandas as pd
from pathlib import Path

# Load training data from all shards
def load_split(split_dir, split_name='train'):
    """Load all shards for a specific split."""
    split_path = Path(split_dir) / split_name
    dfs = []
    for shard_file in split_path.glob('shard_*.parquet'):
        dfs.append(pd.read_parquet(shard_file))
    return pd.concat(dfs, ignore_index=True)

# Example
train_df = load_split('data/processed/login/splits', 'train')
val_df = load_split('data/processed/login/splits', 'val')
test_df = load_split('data/processed/login/splits', 'test')

print(f"Train: {len(train_df)} records")
print(f"Val: {len(val_df)} records")
print(f"Test: {len(test_df)} records")

# Features are ready for ML training
print(train_df.columns)
```

## 6. Customizing Configuration

```python
from src.domains.login import LoginConfig, LoginPipeline

# Custom config
config = LoginConfig(
    raw_data_dir='data/raw/login',
    processed_data_dir='data/processed/login',
    num_shards=512,      # More shards for parallel processing
    batch_size=20000,    # Larger batches
    train_ratio=0.70,    # 70% train, 15% val, 15% test
    val_ratio=0.15,
    test_ratio=0.15,
    feature_windows=[1, 7, 14, 30],  # More windows
)

# Run pipeline
pipeline = LoginPipeline(config)
pipeline.run(config.raw_data_dir)
```

## 7. Adding New Domain (Agent Logs Example)

### Step 1: Create config.py
```python
# src/domains/agent_logs/config.py
from dataclasses import dataclass, field
from src.core.base_config import BaseConfig

@dataclass
class AgentLogsConfig(BaseConfig):
    domain_name: str = 'agent_logs'
    shard_key: str = 'agent_id'
    num_shards: int = 128
    
    required_columns: list = field(default_factory=lambda: [
        'timestamp',
        'agent_id', 
        'event_type',
        'severity',
        'message',
    ])
```

### Step 2: Create normalizer.py
```python
# src/domains/agent_logs/normalizer.py
import pandas as pd
from src.core.base_normalizer import BaseNormalizer

class AgentLogsNormalizer(BaseNormalizer):
    STANDARD_COLUMNS = [
        'timestamp',
        'agent_id',
        'event_type',
        'severity',
        'message',
    ]
    
    def validate_raw_schema(self, df):
        required = self.config.required_columns
        missing = set(required) - set(df.columns)
        if missing:
            raise ValueError(f"Missing: {missing}")
        return True
    
    def normalize(self, df):
        df = df[self.STANDARD_COLUMNS].copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['agent_id'] = df['agent_id'].astype(str)
        df = df.sort_values(['agent_id', 'timestamp'])
        return df
    
    def get_output_schema(self):
        return {
            'timestamp': 'datetime64[ns]',
            'agent_id': 'object',
            'event_type': 'object',
            'severity': 'object',
            'message': 'object',
        }
```

### Step 3: Create feature_builder.py
```python
# src/domains/agent_logs/feature_builder.py
import pandas as pd
import numpy as np
from src.core.base_feature_builder import BaseFeatureBuilder

class AgentLogsFeatureBuilder(BaseFeatureBuilder):
    def get_feature_list(self):
        features = []
        for window in self.windows:
            features.extend([
                f'event_count_window{window}',
                f'critical_severity_window{window}',
                f'event_type_entropy_window{window}',
            ])
        return features
    
    def build_features(self, shard_df):
        df = shard_df.copy()
        # ... implement feature logic similar to login/network
        return df
```

### Step 4: Create pipeline.py
```python
# src/domains/agent_logs/pipeline.py
from src.core.sharding import HashSharding
from src.core.splitter import TimeBasedSplitter
from .config import AgentLogsConfig
from .normalizer import AgentLogsNormalizer
from .feature_builder import AgentLogsFeatureBuilder

class AgentLogsPipeline:
    def __init__(self, config):
        self.config = config
        self.normalizer = AgentLogsNormalizer(config)
        self.sharding = HashSharding(config.num_shards, config.shard_key)
        self.feature_builder = AgentLogsFeatureBuilder(config)
        self.splitter = TimeBasedSplitter(
            config.train_ratio, config.val_ratio, config.test_ratio
        )
    
    def run(self, input_dir):
        # Same 4-step pattern
        norm_df = self.step1_normalize(input_dir)
        self.step2_shard(norm_df)
        self.step3_build_features()
        self.step4_split()
```

### Step 5: Create __init__.py
```python
# src/domains/agent_logs/__init__.py
from .config import AgentLogsConfig
from .normalizer import AgentLogsNormalizer
from .feature_builder import AgentLogsFeatureBuilder
from .pipeline import AgentLogsPipeline

__all__ = [
    'AgentLogsConfig',
    'AgentLogsNormalizer',
    'AgentLogsFeatureBuilder',
    'AgentLogsPipeline',
]
```

### Step 6: Create entry script
```python
# src/scripts/process_agent_logs.py
import argparse
from pathlib import Path
from src.domains.agent_logs import AgentLogsConfig, AgentLogsPipeline

def main():
    parser = argparse.ArgumentParser(description='Process agent logs')
    parser.add_argument('--raw-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--num-shards', type=int, default=128)
    
    args = parser.parse_args()
    
    config = AgentLogsConfig(
        raw_data_dir=args.raw_dir,
        processed_data_dir=args.output_dir,
        num_shards=args.num_shards,
    )
    
    pipeline = AgentLogsPipeline(config)
    pipeline.run(args.raw_dir)

if __name__ == '__main__':
    main()
```

### Step 7: Run it
```bash
python -m src.scripts.process_agent_logs \
    --raw-dir data/raw/agent_logs \
    --output-dir data/processed/agent_logs
```

Done! You've added a new domain in ~30 minutes by following the template.

---

## Common Patterns

### Load all splits efficiently:
```python
def load_all_splits(domain_splits_dir):
    """Load train/val/test as single dataframes."""
    import pandas as pd
    from pathlib import Path
    
    def _load_split(split_name):
        split_dir = Path(domain_splits_dir) / split_name
        dfs = [pd.read_parquet(f) for f in split_dir.glob('shard_*.parquet')]
        return pd.concat(dfs, ignore_index=True)
    
    return {
        'train': _load_split('train'),
        'val': _load_split('val'),
        'test': _load_split('test'),
    }

# Usage
splits = load_all_splits('data/processed/login/splits')
X_train = splits['train'].drop(columns=['timestamp', 'user_id', 'source_ip'])
y_train = splits['train']['result'].map({'success': 0, 'failure': 1})
```

### Process multiple domains in sequence:
```python
from src.domains.login import LoginConfig, LoginPipeline
from src.domains.cicids2018 import CICIDS2018Config, CICIDS2018Pipeline

def process_all_domains():
    # Login
    login_config = LoginConfig(
        raw_data_dir='data/raw/login',
        processed_data_dir='data/processed/login',
    )
    LoginPipeline(login_config).run(login_config.raw_data_dir)
    
    # Network
    net_config = CICIDS2018Config(
        raw_data_dir='data/raw/cicids2018',
        processed_data_dir='data/processed/cicids2018',
    )
    CICIDS2018Pipeline(net_config).run(net_config.raw_data_dir)

process_all_domains()
```

---

## Debugging

### Inspect a specific shard:
```python
import pandas as pd

# Load one shard to inspect
df = pd.read_parquet('data/processed/login/features/shard_000.parquet')
print(df.head())
print(df.columns)
print(df.dtypes)
```

### Check split stats:
```python
import pandas as pd

# Load split statistics
stats = pd.read_csv('data/processed/login/splits/split_stats.csv')
print(stats)
print(f"Total records: {stats[['train', 'val', 'test']].sum().sum()}")
```

### Verify no data leakage:
```python
import pandas as pd
from pathlib import Path

# Load train and test timestamps
train_df = pd.read_parquet(Path('data/processed/login/splits/train').glob('*').pop())
test_df = pd.read_parquet(Path('data/processed/login/splits/test').glob('*').pop())

train_max = train_df['timestamp'].max()
test_min = test_df['timestamp'].min()

print(f"Latest train: {train_max}")
print(f"Earliest test: {test_min}")
assert train_max <= test_min, "Data leakage detected!"
```

---

## Performance Tips

1. **Adjust num_shards** based on available CPU cores
   - More shards = more parallelization
   - Default 256 works for most cases

2. **Use parquet** for all intermediate formats
   - 50-60% storage reduction
   - Fast column access

3. **Process shards in parallel** (future enhancement)
   - Feature building can run per-shard in parallel
   - Use `multiprocessing` or `ray`

4. **Monitor memory** for large datasets
   - Load shards one at a time
   - Stream processed results to disk

---

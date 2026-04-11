# Login Domain Template

`src/domains/login/` is organized by lifecycle stage instead of by loose files.

## Structure

- `processing/`
  - owns raw-to-feature work: normalize, shard, feature build, split
- `training/`
  - owns experiment defaults and train-stage runner for login
- `evaluation/`
  - owns validation / offline evaluation runner for login
- `testing/`
  - owns final holdout test runner for login
- `__init__.py`
  - exports the public domain API

## Why this layout scales better

- all code for one domain lives together
- processing and modeling decisions stay close to the domain mindset
- each stage remains small and debuggable
- new domains can follow the same template without copying unrelated project-level code

## How To Run

Activate the project environment first:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### 1. Processing Pipeline

Small local smoke test:

```bash
python -m src.scripts.process_login \
  --raw-dir data/raw/rba-dataset/test \
  --output-dir data/processed/login \
  --num-shards 3 \
  --batch-size 10 \
  --feature-windows 1 7 30
```

Recommended larger baseline:

```bash
python -m src.scripts.process_login \
  --raw-dir data/raw/rba-dataset \
  --output-dir data/processed/login_full \
  --num-shards 128 \
  --batch-size 5000 \
  --feature-windows 1 7 30
```

Processing output:

- `normalized.parquet`
- `shards/`
- `features/`
- `splits/`
- `config.json`
- `feature_manifest.json`

### 2. Training Pipeline

```bash
python -m src.scripts.train_login \
  --processed-dir data/processed/login \
  --experiment-dir experiments/login_risk \
  --alert-rate-target 0.05
```

What this training stage does:

- fits a robust baseline profile for each behavior block
- scores each block by deviation from the training baseline
- fuses block scores into one risk score
- calibrates the final alert threshold on the validation split by alert budget
- keeps `login_successful` only as a reference metric, not as the primary objective

Fast smoke test before full training:

```bash
python -m src.scripts.train_login \
  --processed-dir data/processed/login \
  --experiment-dir experiments/login_smoke \
  --max-rows-per-split 200 \
  --alert-rate-target 0.10
```

Training output:

- `login_block_risk_model.npz`
- `login_block_risk_model.json`
- `reports/train_metrics.json`
- `reports/val_metrics.json`
- `reports/block_structure.json`
- `predictions/train.parquet`
- `predictions/val.parquet`

### 3. Evaluation Pipeline

Evaluate the validation split:

```bash
python -m src.scripts.evaluate_login \
  --processed-dir data/processed/login \
  --experiment-dir experiments/login_risk \
  --split val
```

This writes:

- `reports/val_metrics.json`
- `predictions/val.parquet`

### 4. Test Pipeline

Run the final holdout test:

```bash
python -m src.scripts.test_login \
  --processed-dir data/processed/login \
  --experiment-dir experiments/login_risk
```

This writes:

- `reports/test_metrics.json`
- `predictions/test.parquet`

### 5. Audit Pipeline

Review whether the current weakness comes more from processing or training:

```bash
python -m src.scripts.audit_login_experiment \
  --processed-dir data/processed/login \
  --experiment-dir experiments/login_risk
```

This writes:

- `reports/audit_summary.json`

## Recommended Order

Run the login lifecycle in this order:

1. `process_login` on a small sample
2. `train_login --max-rows-per-split ...` to confirm the risk model and thresholding behave sensibly
3. inspect `train/val` reports and run `audit_login_experiment`
4. process the full dataset
5. run full `train_login`
6. run `evaluate_login`
7. run `test_login`

## Practical Guidance

- do a quick smoke train on a small split first so you can catch bad labels, broken features, or unstable thresholds cheaply
- do full-dataset processing and training only after the smoke run looks sane
- if `val` and `test` are tiny, prioritize processing more data before trusting leaderboard-style comparisons
- if alert rate calibration is unstable across val/test, improve training and evaluation before expanding feature engineering again

## Suggested template for future domains

For any mature domain, keep this shape:

```text
src/domains/<domain>/
├── processing/
├── training/
├── evaluation/
├── testing/
└── __init__.py
```

# API Traffic Domain

This domain follows the standard project lifecycle layout:

- `processing/`: raw API events -> normalized records -> static feature splits
- `training/`: endpoint-aware retrieval model and training runner
- `evaluation/`: split scoring, metrics, predictions, explanations
- `testing/`: final test split runner

## Processing

```bash
python -m src.scripts.process_api_traffic \
  --raw-file data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets/dataset_1_train.7z \
  --output-dir data/processed/api_traffic_d1 \
  --num-shards 32 \
  --static-view request_response
```

Processing output:

- `normalized.parquet`
- `shards/`
- `features/` for full audit/debug features
- `features_static/` for static model-ready features
- `splits/train`, `splits/val`, `splits/test`
- `config.json`
- `feature_manifest.json`

## Training

Training code lives in `src/domains/api_traffic/training/`.

Training fits the model on `splits/train` and tunes the alert threshold on
`splits/val`. It does not read `splits/test`.

```bash
python -m src.scripts.train_api_retrieval \
  --processed-dir data/processed/api_traffic_d1 \
  --experiment-dir experiments/api_traffic_d1_retrieval
```

Training output:

- `retrieval_model.npz`
- `retrieval_model_meta.json`
- `config.json`
- `reports/train_metrics.json`
- `reports/val_metrics.json`
- `predictions/train.csv`
- `predictions/val.csv`

## Evaluation

Evaluation code lives in `src/domains/api_traffic/evaluation/`.

Use evaluation for development checks on non-final splits, usually `train` or
`val`, or for scoring unlabeled challenge validation data.

```bash
python -m src.scripts.score_api_retrieval \
  --processed-dir data/processed/api_traffic_d1 \
  --experiment-dir experiments/api_traffic_d1_retrieval \
  --split val
```

For unlabeled challenge validation files, process the validation archive first,
then score `--split unlabeled_validation`.

## Testing

Testing code lives in `src/domains/api_traffic/testing/`.

Use the processed holdout test split created from a labeled train archive:

```bash
python -m src.scripts.test_api_retrieval \
  --processed-dir data/processed/api_traffic_d1 \
  --experiment-dir experiments/api_traffic_d1_retrieval
```

This writes:

- `reports/test_metrics.json`
- `predictions/test.parquet`
- `predictions/test.csv`

The important test columns are:

- `y_true`
- `y_pred`
- `y_score`
- `attack_type_true`
- `predicted_attack_type`
- `security_finding`
- `explanation`

### External Challenge Validation

The challenge validation archives, for example `dataset_1_val.7z`, are treated
as unlabeled inference data. They must still be processed with the same pipeline,
but they should not be used for F1/accuracy unless labels are available.

```bash
python -m src.scripts.process_api_traffic \
  --raw-file data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets/dataset_1_val.7z \
  --output-dir data/processed/api_traffic_d1_val \
  --num-shards 32 \
  --static-view request_response
```

```bash
python -m src.scripts.score_api_retrieval \
  --processed-dir data/processed/api_traffic_d1_val \
  --experiment-dir experiments/api_traffic_d1_retrieval \
  --split unlabeled_validation
```

This writes:

- `predictions/unlabeled_validation.parquet`
- `predictions/unlabeled_validation.csv`

For unlabeled validation, inspect:

- `y_pred`
- `y_score`
- `predicted_attack_type`
- `security_finding`
- `explanation`

No `test_metrics.json` is produced for unlabeled validation because there is no
ground-truth label to compare against.

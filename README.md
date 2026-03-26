# adaptive-multi-agent-siem

A multi-agent SIEM system that detects anomalies and autonomously adapts to mitigate security threats across multiple layers.

## Setup

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

If `python3 -m venv .venv` fails, install the system package first:

```bash
sudo apt install python3-venv
```

## Configuration

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Example `.env` values:

```env
INPUT_FILE=/content/drive/MyDrive/rba-dataset.csv
OUTPUT_DIR=/content/drive/MyDrive/rba_features/
OUTPUT_FILE=/content/drive/MyDrive/rba_risk_scores.csv
CHUNK_SIZE=200000
MAX_WORKERS=2
```

Configuration notes:

- `CHUNK_SIZE` controls how many rows are loaded at once
- `MAX_WORKERS` controls how many chunks are processed in parallel
- For low-memory environments, start with `MAX_WORKERS=2`

## Run Preprocessing

Run the preprocessing script:

```bash
python src/preprocess.py
```

The script will:

- Read the input CSV in chunks
- Process multiple chunks in parallel
- Create behavior-based RBA features
- Save each processed chunk as a parquet file in the output directory

## Run Streaming RBA

Run the sequential streaming RBA pipeline:

```bash
python3 src/rba_streaming.py
```

Or override the paths explicitly:

```bash
python3 src/rba_streaming.py /path/to/logins.csv -o /path/to/risk_scores.csv
```

Optional flags:

- `--smoothing 1.0` for Laplace smoothing on probability estimates
- `--anomaly-threshold 3.0` to flag high-risk events
- `--user-history-limit 1000` to cap per-user retained history for count updates

Streaming `.env` values:

```env
INPUT_FILE=/content/drive/MyDrive/rba-dataset.csv
OUTPUT_FILE=/content/drive/MyDrive/rba_risk_scores.csv
```

The streaming pipeline:

- Reads one CSV row at a time with `csv.DictReader`
- Computes risk before updating state for the current login
- Stores only aggregate counts in dictionaries for global and per-user state
- Avoids full-dataset `groupby` and does not load the full file into memory
- Accepts either normalized columns like `user_id` / `timestamp` or raw dataset columns like `User ID` / `Login Timestamp`

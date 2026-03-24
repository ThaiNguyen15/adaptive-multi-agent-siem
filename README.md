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

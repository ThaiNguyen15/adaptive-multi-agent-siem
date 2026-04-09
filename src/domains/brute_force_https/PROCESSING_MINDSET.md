# HTTPS Brute-Force Detection: Data Preprocessing Phase

## Overview

This document defines the production preprocessing phase for the HTTPS brute-force detection pipeline.

The preprocessing layer is responsible for converting raw CESNET brute-force dataset artifacts into a stable, model-ready representation for downstream feature engineering and anomaly or classification models. Its job is not only to load CSV files, but to choose the correct source view, normalize network-flow semantics, preserve service-level context, and reduce shortcut-prone metadata leakage.

In practice, this phase sits between raw dataset ingestion and feature extraction:

`raw dataset view -> normalized flow record -> service-aware shard -> feature-ready record -> train/validation/test split`

This stage is operationally critical. If preprocessing is inconsistent, the model will learn scenario artifacts, tool-specific naming patterns, or hashed identifiers instead of learning reusable HTTPS brute-force behavior.

## Objectives

The preprocessing phase has five concrete objectives:

1. Ingest the CESNET brute-force dataset from the correct raw view and preserve source provenance.
2. Normalize flow-level fields into a consistent schema that can be reused across views.
3. Separate production-like behavioral signals from evaluation-only metadata.
4. Group traffic by stable service context so downstream features are computed in the right operational neighborhood.
5. Produce deterministic normalized records that support robust evaluation beyond random row-level splitting.

Three principles drive the design:

- Representation choice is part of preprocessing quality. `aggregated_flows.csv` is the preferred default because it is close to network behavior while still practical for repo-native feature building.
- Reducing shortcut features improves generalization. Scenario, tool, and app metadata are useful for evaluation, but should not dominate the production feature space.
- Service-level grouping is required. Brute-force behavior is relative to the service being targeted, not just to global traffic volume.

## Input / Output Definition

### Input

The preprocessing phase accepts raw dataset files from:

`data/raw/brute-force-dataset`

Supported source views:

| View | Description | Recommended Usage |
| --- | --- | --- |
| `flows.csv` | Raw extended network flows with packet-prefix characteristics | Advanced experiments, not the default first path |
| `aggregated_flows.csv` | Aggregated flow records close to network behavior | Default repo-native preprocessing path |
| `samples.csv` | Dataset-provided extracted features | Fast baseline or benchmark reference |

Minimum required fields depend on the configured view, but in general the pipeline expects:

| Field | Type | Description |
| --- | --- | --- |
| `SRC_IP` | string | Hashed source identifier |
| `DST_IP` | string | Hashed destination identifier |
| `DST_PORT` | integer | Destination port |
| `PROTOCOL` | string or integer | Transport protocol |
| `TIME_FIRST` | timestamp-like | First observed packet time |
| `TIME_LAST` | timestamp-like | Last observed packet time |
| `SCENARIO` | string | Scenario label from dataset generation |
| `CLASS` | integer | `0` benign, `1` brute-force |

View-specific fields may include:

| Field | Type | Description |
| --- | --- | --- |
| `BYTES` | numeric | Forward byte volume |
| `BYTES_REV` | numeric | Reverse byte volume |
| `PACKETS` | numeric | Forward packet count |
| `PACKETS_REV` | numeric | Reverse packet count |
| `ROUNDTRIPS` | numeric | Request/response roundtrip count |
| `DURATION` | numeric | Flow duration |

### Output

The preprocessing phase emits a structured record suitable for sharding, feature extraction, and robust split generation.

Core output fields:

| Field | Type | Description |
| --- | --- | --- |
| `event_id` | string | Stable flow-level identifier if derivable |
| `event_timestamp` | timestamp | Normalized event timestamp |
| `service_key` | string | Stable grouping key for service-aware sharding |
| `src_ip` | string | Normalized hashed source id |
| `dst_ip` | string | Normalized hashed destination id |
| `dst_port` | integer | Clean destination port |
| `protocol` | string | Normalized protocol |
| `scenario` | string | Normalized scenario metadata |
| `label` | integer or string | Binary or configured label mode |
| `source_view` | string | `flows`, `aggregated_flows`, or `samples` |
| `normalization_flags` | map | Flags describing coercions or missing-data handling |
| `parse_status` | string | `ok`, `partial`, or `invalid` |

Optional derived fields:

| Field | Type | Description |
| --- | --- | --- |
| `attack_tool` | string | Parsed tool from scenario when applicable |
| `target_app` | string | Parsed target application from scenario when applicable |
| `is_benign_scenario` | integer | Whether scenario comes from benign backbone captures |
| `duration_seconds` | float | Derived duration from timestamps |
| `flow_directionality_ratio` | float | Derived directional ratio when possible |

## Processing Pipeline (step-by-step)

The preprocessing pipeline is deterministic. The same input must always produce the same output.

### 1. Ingest brute-force dataset view

For this domain, the raw source should be taken from:

`data/raw/brute-force-dataset`

Expected source artifacts:

- `flows.csv`
- `aggregated_flows.csv`
- `samples.csv`

Processing rule:

- prefer `aggregated_flows.csv` as the default repo-native input view
- allow `samples.csv` for benchmark baselines and `flows.csv` for advanced follow-up work
- attach `source_view` and original file provenance to every emitted record
- validate that the configured view has the required columns before normalization begins

Why this step exists:

- the three files are different representation levels, not interchangeable duplicates
- choosing the wrong view changes what the model is actually learning
- preprocessing must make that representation choice explicit and auditable

Output of this step:

- source-scoped raw records with `source_view` metadata attached

### 2. Ingest raw flow event

The pipeline receives a raw row plus dataset provenance metadata.

Actions:

- assign or derive `event_id` where possible
- attach source file, configured view, and label-mode metadata
- preserve original row values for audit if needed
- reject rows that do not meet minimum schema requirements

Output of this step:

- immutable raw input record

### 3. Parse and normalize core flow fields

The parser converts the raw row into a stable internal representation.

Normalization actions:

- rename source columns into the domain schema
- normalize timestamps into UTC-compatible datetimes
- coerce numeric fields into consistent numeric types
- standardize protocol representation
- trim and normalize text metadata such as `SCENARIO`
- convert `CLASS` into the configured label mode

Why this matters:

- downstream feature logic depends on a stable schema across input views
- inconsistent timestamp and numeric handling creates artificial drift
- label and scenario parsing must be deterministic for reproducible evaluation

### 4. Derive scenario semantics

The scenario field is useful, but it must be handled carefully.

Actions:

- parse `SCENARIO` into higher-level metadata such as benign capture, attack tool, and target application when possible
- preserve raw `scenario` for audit and evaluation
- separate evaluation metadata from production-like modeling fields
- mark benign backbone captures distinctly from attack-generated scenarios

Why this is critical:

- scenario names are powerful shortcuts for models
- tool and app metadata are valuable for holdout evaluation
- parsing them explicitly lets the pipeline use them safely without leaking them into the primary feature path

### 5. Validate numeric and traffic semantics

Traffic statistics must be checked before feature extraction.

Validation actions:

- ensure counts and byte fields are non-negative
- derive duration from timestamps when the view does not provide it directly
- detect impossible or suspicious values such as negative duration or empty traffic with inconsistent counters
- set normalization flags for clipped, missing, or coerced values

Why numeric validation matters:

- flow data often contains edge cases that silently poison feature distributions
- brute-force detection relies heavily on count, rate, and timing stability
- feature builders need explicit signals about data quality, not hidden coercions

### 6. Extract service identity

The service extraction stage derives the operational grouping key used by downstream sharding and feature builders.

Service key format:

`coalesce(tls_sni, dst_ip) + ":" + dst_port + ":" + protocol`

Example:

`hashed_sni_or_ip:443:tcp`

This step may also preserve related grouping metadata:

- `dst_ip`
- `dst_port`
- `protocol`
- normalized `tls_sni` when available

Why service-level grouping is required:

- brute-force behavior is tied to the targeted service
- the same packet or byte rates may be normal for one service and suspicious for another
- sharding by service context keeps related traffic together for more meaningful downstream features

### 7. Build normalized feature-ready record

After normalization and validation, the pipeline assembles a canonical structured record that is stable across equivalent flow rows.

Recommended composition:

1. normalized event timestamp
2. service key and service context
3. normalized traffic counters and timing fields
4. directionality and rate prerequisites
5. parsed scenario metadata as evaluation fields
6. configured label output

Example feature-ready record:

```text
event_timestamp=2024-01-01T00:00:00Z service_key=abc123:443:tcp bytes=1200 bytes_rev=3400 packets=12 packets_rev=20 roundtrips=4 scenario=wordpress_hydra attack_tool=hydra target_app=wordpress label=1
```

### 8. Emit sharding-ready output

The final preprocessing output contains:

- normalized fields
- service grouping key
- parsed evaluation metadata
- normalization flags
- provenance fields such as `source_view`

This output becomes the contract for sharding, feature building, and train or validation split generation.

## Detailed Transformation Rules

This section defines the exact transformation behavior.

### Source View Rules

| Input View | Rule | Rationale |
| --- | --- | --- |
| `aggregated_flows.csv` | default production-like preprocessing path | best balance between fidelity and practicality |
| `samples.csv` | baseline-only path unless explicitly needed | fast benchmark, but less preprocessing control |
| `flows.csv` | advanced path for later experiments | highest raw fidelity, highest processing cost |

### Timestamp Rules

| Input Component | Rule | Example |
| --- | --- | --- |
| `TIME_FIRST` | parse into normalized datetime | raw string -> UTC timestamp |
| `TIME_LAST` | parse into normalized datetime | raw string -> UTC timestamp |
| duration | compute as `TIME_LAST - TIME_FIRST` when needed | derived float seconds |

### Numeric Rules

| Rule | Behavior |
| --- | --- |
| byte and packet counts | coerce to numeric and require non-negative values |
| missing numeric values | impute only with explicit normalization flags |
| extreme values | keep raw value, optionally clip later in feature engineering |
| rates | derive only from validated duration or timing support |

### Scenario Rules

| Scenario Pattern | Output Behavior |
| --- | --- |
| `backbone_capture_*` | mark as benign scenario |
| `*_hydra` | parse `attack_tool=hydra` |
| `*_patator` | parse `attack_tool=patator` |
| `*_ncrack` | parse `attack_tool=ncrack` |
| other scenario strings | preserve raw scenario, parse best effort only |

### Label Rules

| Label Mode | Behavior |
| --- | --- |
| `binary` | use `CLASS` directly as benign vs brute-force |
| `scenario` | use normalized scenario value |
| `tool` | emit parsed tool label where possible |
| `app` | emit parsed target application where possible |
| `raw` | preserve raw dataset label semantics for analysis |

## Service Extraction Logic

Service extraction is performed after timestamp and field normalization.

### Service key construction

Base key:

`service_key = coalesce(tls_sni, dst_ip) + ":" + dst_port + ":" + protocol`

Example:

```text
9f4e...:443:tcp
```

### Grouping strategy

Use service-aware grouping because:

- `dst_port` alone is not enough when many records target `443`
- hashed identifiers are only useful when anchored to service context
- flow behavior should be compared within similar service neighborhoods

Operational guidance:

- use `service_key` for sharding and local feature computation
- preserve raw scenario metadata separately for evaluation
- avoid treating service hashes as standalone semantic content features

## Design Decisions & Rationale

### Prefer `aggregated_flows.csv` as the default path

It is the most practical raw view for repo-native preprocessing. It remains close to network behavior while avoiding the full parsing overhead of `flows.csv`.

### Keep metadata and production signals separate

Scenario, tool, and app values are informative, but they are also high-risk shortcut features. They belong in evaluation and analysis paths before they belong in the primary production-like feature path.

### Treat hashed identifiers carefully

Hashed IPs, ports, or SNIs can support grouping, but they should not be trusted as rich semantic tokens. The model should learn behavior, not memorize dataset identities.

### Group by service

HTTPS brute-force patterns are service-relative. Volume, timing, and repetition make sense only when anchored to the destination service context.

### Preserve support for stronger evaluation

The preprocessing contract must support scenario-holdout, tool-holdout, and app-holdout evaluation modes, not only random row-level splits.

## Edge Cases Handling

The preprocessing phase must be resilient to imperfect or incomplete rows.

### Missing timestamps

Behavior:

- attempt to parse whichever timestamp fields are present
- set `parse_status=partial` if duration cannot be derived safely
- preserve row provenance for later audit

### Missing service identity

Behavior:

- fallback from `tls_sni` to `dst_ip`
- if both are unavailable, mark service key as unknown with a normalization flag

### Invalid numeric values

Behavior:

- coerce where safe
- mark values as invalid when coercion would hide a semantic problem
- avoid silently inventing traffic statistics

### Unparseable scenario strings

Behavior:

- preserve raw scenario value
- avoid forcing tool or app extraction when parsing confidence is low
- keep evaluation metadata partial rather than wrong

### Mixed source views

Behavior:

- do not merge records from different source views without preserving `source_view`
- ensure downstream experiments can distinguish `flows`, `aggregated_flows`, and `samples`

### Highly imbalanced scenarios

Behavior:

- preserve scenario metadata for robust holdout and error analysis
- avoid preprocessing choices that erase minority attack scenarios

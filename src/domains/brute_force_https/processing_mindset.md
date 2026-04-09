# Brute Force HTTPS Processing Mindset

## 1. Scope in the Larger System

This document defines the recommended data processing mindset for the `brute_force_https` domain.

In the larger architecture, this domain belongs to the `Network Layer`. Its responsibility is narrow:

- detect `HTTPS brute-force behavior`
- operate on flow-level traffic representations
- produce stable, behavior-oriented features for downstream detection

This domain is not responsible for:

- login behavior modeling
- payload or request-body semantics
- application-layer abuse classification

Because of that, the processing design must stay centered on network behavior and service-targeted repetition.

## 2. Correct Goal of the Domain

The correct goal is not:

- predicting the exact dataset scenario
- identifying the attack tool name
- memorizing application names
- overfitting to hashed identifiers

The correct goal is:

- separate `benign` from `HTTPS brute-force`
- learn patterns that generalize across tools and target applications
- preserve service context so traffic is interpreted relative to the attacked service
- support robust evaluation without leaking lab-specific shortcuts into the main feature path

In practical terms:

- the core unit is a `flow event`
- the primary signal is `behavior shape`
- metadata should support evaluation, not dominate modeling

## 3. Raw Data Strategy

The raw source for this domain is:

`data/raw/brute-force-dataset`

The dataset exposes three processing levels:

- `flows.csv`
- `aggregated_flows.csv`
- `samples.csv`

These files should not be treated as interchangeable copies. They represent different abstraction levels and should be used differently.

### Recommended usage of each view

#### `aggregated_flows.csv`

This should be the default path for the domain.

Why:

- close enough to real traffic behavior
- lightweight enough for repo-native feature engineering
- suitable for service-aware temporal modeling
- avoids unnecessary complexity in the first production-oriented pipeline

#### `samples.csv`

This should be used only for:

- quick baselines
- sanity checks
- benchmark comparisons

It should not define the domain’s core preprocessing logic because:

- the feature semantics are already partially decided upstream
- leakage and shortcut risks are harder to audit

#### `flows.csv`

This should be reserved for:

- advanced experiments
- packet-prefix modeling
- deeper temporal or sequence research

It should not be the default processing path because:

- parsing cost is higher
- schema handling is more complex
- the added complexity is not required for a strong first brute-force detector

## 4. Behavioral Interpretation of the Data

HTTPS brute-force is usually not visible through payload content. It appears through repeated service-targeted traffic behavior.

### Benign traffic tends to look like:

- more diverse service access
- less mechanical repetition
- more natural timing rhythm
- lower persistence against one service in a short period
- less rigid forward/reverse traffic structure

### Brute-force traffic tends to look like:

- repeated attempts against the same destination service
- short-gap or bursty timing
- repeated packet and byte patterns
- high concentration around one service identity
- tool-driven regularity in flow structure

The processing pipeline should therefore emphasize:

- service-aware grouping
- timing and rate features
- directional flow relationships
- temporal repetition

The processing pipeline should not emphasize:

- raw identity values
- dataset-specific scenario names
- app names as direct attack evidence

## 5. Recommended Representation Model

After normalization, the data should be interpreted as six groups of information:

- `event metadata`
  - event identifier
  - source file
  - source view
  - event time
- `service context`
  - service identity
  - destination endpoint context
  - protocol context
  - TLS context if present
- `source context`
  - source-side identifiers
  - source-side port or origin information
- `traffic behavior`
  - bytes
  - packets
  - duration
  - roundtrips
  - rates
  - directionality
- `evaluation metadata`
  - scenario
  - attack tool
  - target app
- `label views`
  - binary label
  - alternate label spaces for evaluation

The modeling priority should be:

1. traffic behavior
2. service context
3. temporal context
4. evaluation metadata only for analysis and robustness testing

## 6. Processing Pipeline

The domain should process data in explicit phases, not in one flat transformation.

### Phase 1: Select the correct source view

Recommended policy:

- use `aggregated_flows.csv` as the default
- use `samples.csv` only for quick baseline experiments
- use `flows.csv` only for advanced research paths

Why this matters:

- the source view determines what the detector can learn
- poor representation choice cannot be fixed later by feature engineering alone

### Phase 2: Validate raw schema and source integrity

Before normalization:

- validate required columns for the selected source view
- reject malformed files early
- attach source provenance immediately
- preserve the original source view as metadata

Recommended minimum raw fields:

- source and destination identifiers
- destination port
- protocol
- start and end time
- packet and byte counts
- scenario or label fields

Why this matters:

- brute-force detection depends on stable traffic semantics
- silent schema drift will contaminate downstream features

### Phase 3: Canonicalize the schema

All raw headers should be mapped into a single domain schema.

Best-practice normalization:

- convert field names into stable snake_case
- normalize time columns into UTC-aware datetimes
- normalize numeric columns into consistent numeric types
- preserve text identifiers as strings even when hashed
- expose one canonical event timestamp field

Typical canonical field families:

- `event_timestamp`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`
- `protocol`
- `bytes`, `bytes_rev`
- `packets`, `packets_rev`
- `duration`
- `roundtrips`
- `scenario`

The goal of this phase is not to engineer features yet. The goal is to create a stable semantic record.

### Phase 4: Normalize missing values and invalid values

Recommended rules:

- replace impossible numeric values with explicit null handling
- convert `inf/-inf` into missing values before imputation
- fill missing numeric fields only where that preserves semantic safety
- fill missing text identifiers with explicit empty or `unknown` values
- never let malformed values silently propagate into rate features

Best-practice principle:

- cleaning should reduce technical noise
- cleaning should not invent attack evidence

### Phase 5: Build stable label views

The domain should support multiple label views, but one label view must remain primary.

Recommended label strategy:

- primary label: `binary` (`benign` vs `brute-force`)
- evaluation labels:
  - `scenario`
  - `tool`
  - `app`
  - raw label if needed

Best-practice rule:

- binary detection is the production-centered target
- scenario/tool/app labels are for slicing, robustness checks, and holdout evaluation
- they should not become the main source of predictive power

### Phase 6: Parse evaluation metadata carefully

Scenario strings often encode:

- whether traffic is benign
- which attack tool generated it
- which application was targeted

This information is useful, but dangerous.

Recommended handling:

- preserve raw scenario text
- parse derived fields such as `attack_tool` and `target_app`
- keep these fields for:
  - data slicing
  - evaluation
  - generalization testing
- avoid making them dominant production features

Best-practice principle:

- metadata should help measure robustness
- metadata should not replace behavioral evidence

### Phase 7: Derive service identity

This is one of the most important steps in the domain.

Recommended service identity construction:

- use TLS SNI when available
- otherwise fall back to destination IP
- combine service identity with destination port and protocol

Recommended format:

`service_key = service_name : dst_port : protocol`

Why this matters:

- brute-force behavior is service-relative
- `443` alone is too coarse
- hashed identifiers become more useful when anchored to service context

This key should be used for:

- sharding
- local aggregation
- temporal feature construction
- service-relative comparison

### Phase 8: Derive duration and rate prerequisites

The normalized record should expose enough information to compute timing and rate features consistently.

Best-practice rules:

- derive `duration` from timestamps when it is missing
- clip negative duration to zero
- keep rate derivation deterministic
- separate raw counts from derived rates

This phase should prepare for later features such as:

- bytes per second
- packets per second
- roundtrips per second
- short-window intensity

### Phase 9: Emit feature-ready normalized records

The output of preprocessing should already be stable enough for feature extraction.

A feature-ready record should include:

- event metadata
- service context
- traffic metrics
- derived duration
- label views
- evaluation metadata
- provenance fields

The output should be:

- deterministic
- sortable
- sharding-ready
- safe for offline training and evaluation

## 7. Feature Engineering Best Practices

This domain should organize features by behavior family.

### Volume features

- total bytes
- total packets
- bytes per packet
- forward vs reverse traffic balance

Why:

- brute-force traffic often has repetitive volume structure

### Directionality features

- reverse-to-forward byte ratio
- reverse-to-forward packet ratio
- response asymmetry indicators

Why:

- brute-force attempts often create asymmetric exchange patterns

### Timing features

- duration
- log-transformed duration
- rate features
- inter-event timing summaries per service

Why:

- brute-force is often visible through timing regularity or burstiness

### Temporal features

This domain should strongly favor temporal aggregation around the service.

Recommended families:

- rolling flow counts
- rolling packet totals
- rolling byte totals
- short-vs-long window deviations
- burst indicators
- recent repetition counts

Why:

- a single flow may not be obviously malicious
- repeated behavior within a time window is often the real signal

### Service-context features

- service-local traffic rarity
- per-service novelty
- service-relative baseline deviation
- frequency of repeated attempts against one service

Why:

- brute-force is not global traffic noise
- it is concentrated pressure on a target service

### Numeric transformation best practice

Use multi-resolution numeric representations:

- raw value
- `log1p` value
- optionally clipped or binned variants

Why:

- traffic metrics usually have wide dynamic ranges
- raw-only representations are unstable

## 8. Sharding Strategy

The correct sharding key should be service-centered.

Recommended rule:

- shard by `service_key`

Do not shard primarily by:

- `dst_port`
- `scenario`
- `src_ip`

Why:

- `dst_port` is too coarse
- `scenario` leaks lab structure
- `src_ip` is hashed and source-centric, not target-service-centric

Service-aware sharding is the right default because:

- it keeps related traffic together
- it supports local temporal baselines
- it matches the operational shape of brute-force attacks

## 9. Split and Evaluation Strategy

Random row-level splitting is not enough for this domain.

Recommended evaluation modes:

- time-based split
- scenario holdout
- tool holdout
- app holdout

Why:

- brute-force datasets are highly vulnerable to shortcut learning
- good random-split metrics may hide poor generalization

Recommended mindset:

- use time split for baseline realism
- use holdout splits to test robustness
- report both benchmark performance and generalization performance

## 10. Main Risks

### Risk 1: Scenario memorization

If the model learns `scenario` too directly, it may appear strong while learning very little about brute-force behavior.

### Risk 2: Over-trusting hashed identifiers

Hashed identifiers help grouping, but they are weak semantic features.

### Risk 3: Over-reliance on port 443

Port `443` is context, not sufficient evidence.

### Risk 4: Mixing source views without provenance

If `flows`, `aggregated_flows`, and `samples` are mixed carelessly, analysis becomes distorted.

### Risk 5: Underusing temporal context

A brute-force detector built only from per-row static features is usually too weak.

## 11. Practical Conclusion

If this domain stays aligned with its actual goal, the correct processing mindset is:

- use `aggregated_flows.csv` as the primary path
- normalize all records into one stable schema
- derive service-aware context explicitly
- keep binary brute-force detection as the central modeling target
- treat scenario/tool/app as evaluation metadata first
- build behavior-heavy features around volume, directionality, timing, and service repetition
- evaluate with robust splits, not just easy benchmark splits

In short:

- this domain does not need payload semantics
- this domain does not need login history
- this domain needs a clean, service-aware, temporally meaningful flow representation so the detector learns real `HTTPS brute-force behavior`

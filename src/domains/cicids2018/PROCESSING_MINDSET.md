# CICIDS2018 Processing Mindset

## 1. Scope

This document defines the recommended processing strategy for the `cicids2018` domain.

In the larger system, this domain is the `network behavior` layer for flow-level anomaly detection. Its job is to:

- normalize CICFlowMeter flow exports into a stable schema
- reduce dataset-specific shortcuts before modeling
- build behavior-oriented features from flow shape
- preserve enough metadata for audit, evaluation, and escalation

This domain is not responsible for:

- packet payload semantics
- exact web-application attack interpretation
- memorizing benchmark scenario artifacts

The unit of analysis is one `network flow`.

## 2. Correct Goal

The goal is not:

- predict the exact raw benchmark label
- learn that one port is always malicious
- memorize one lab day, one machine, or one scenario file

The goal is:

- describe how abnormal the current flow looks relative to normal traffic shape
- separate transport context from behavior magnitude
- preserve signals that generalize across attack families

In practical terms, the model should learn:

- volume behavior
- directionality behavior
- timing behavior
- control-flag behavior
- coarse transport context

It should not depend on:

- raw destination port alone
- raw scenario file identity
- exact benchmark naming conventions

## 3. What CICIDS2018 Flows Represent

The CICIDS2018 CSV exports are already `aggregated flows`, not packet streams. That means the primary useful signals are already summarized into numeric flow metrics.

Typical benign flows tend to show:

- less extreme packet and byte counts
- more balanced forward and backward traffic
- less pathological duration or rate combinations
- less abnormal flag behavior

Typical malicious or abusive flows tend to show one or more of:

- extreme burst rate
- very short duration with very high packet rate
- very asymmetric forward/backward structure
- unusual flag pressure such as SYN or RST concentration
- strong transport concentration around attacked services

Because the dataset is lab-generated, the processing pipeline must assume that some columns can leak benchmark shortcuts. The main examples are:

- `dst_port`
- protocol identifiers used too directly
- family labels that encode scenario wording

## 4. Processing Principles

The pipeline should follow these principles:

1. normalize first, feature engineer second
2. keep raw columns for audit, but avoid using all raw columns directly for training
3. group numeric fields by behavior type and by observed range
4. use transform rules that match the field distribution, not one scaler for everything
5. represent high-cardinality transport context through coarse tokens
6. persist a processing profile so later experiments use the same grouping logic

## 5. Canonical Column Groups

After normalization, the dataset should be interpreted through the following groups.

### Event metadata

- `event_id`
- `source_file`
- `row_index`
- `timestamp`

These columns are for audit and reproducibility, not for direct training.

### Transport context

- `protocol`
- `dst_port`
- `protocol_token`
- `port_token`
- `transport_token`

These columns provide coarse routing and service context. Raw integers should not be treated as semantic truth by themselves.

### Volume fields

Typical examples:

- packet counts
- byte counts
- header lengths
- average packet lengths

These fields are usually non-negative and often long-tailed.

### Directionality fields

Typical examples:

- forward vs backward packet relationships
- forward vs backward byte relationships
- down/up ratio

These fields explain whether the flow is balanced, one-sided, or server-heavy.

### Timing fields

Typical examples:

- `flow_duration`
- active statistics
- idle statistics
- packet and byte rates

These fields often have very wide numeric ranges and usually need clipping plus `log1p`.

### Control and flag fields

Typical examples:

- `syn_flag_cnt`
- `ack_flag_cnt`
- `rst_flag_cnt`
- `urg_flag_cnt`

These fields are usually sparse counts. Most rows are often near zero, with small malicious tails.

### Labels

- `attack_label_raw`
- `attack_family`
- `label_binary`
- `target_label`

These exist for supervision and evaluation, not for feature construction.

## 6. Field Grouping by Observed Range

The pipeline should not hardcode grouping only from column names. It should also inspect actual numeric ranges from the normalized dataset.

The recommended procedure is:

1. compute per-column statistics:
   - missing ratio
   - zero ratio
   - min
   - max
   - mean
   - std
   - median
   - p95
   - p99
   - approximate cardinality
2. use these statistics to place each numeric field into a `range bucket`
3. keep a second semantic grouping by field name and behavior type
4. derive scaling recommendations from both the semantic group and the observed range

Recommended numeric range buckets:

- `binary_or_flag`
  - values are effectively `0/1`
- `bounded_0_1`
  - ratios or shares naturally bounded in `[0, 1]`
- `small_scale`
  - typical max around `<= 10^2`
- `medium_scale`
  - typical max around `<= 10^4`
- `large_scale`
  - typical max around `<= 10^6`
- `extreme_scale`
  - very large positive values, often durations or rates
- `signed`
  - values can be negative, usually deltas

This is important because `flow_duration`, `tot_fwd_pkts`, `ack_flag_cnt`, and `down_up_ratio` should not receive the same preprocessing even though they are all numeric.

## 7. Scaling Policy

Scaling should be chosen per group.

### 7.1 Binary or flag-like features

Examples:

- `is_tcp`
- `is_udp`
- `rst_flag_present`
- `urg_flag_present`

Recommended handling:

- keep as `0/1`
- do not standardize unless a downstream model requires a fully standardized matrix

### 7.2 Bounded ratios and shares

Examples:

- forward packet share
- backward byte share
- bounded rate ratios after clipping

Recommended handling:

- clip to a safe interval first if needed
- keep raw bounded value
- optional standardization is acceptable after clipping

### 7.3 Positive heavy-tailed counts, bytes, durations, rates

Examples:

- `total_packets`
- `total_bytes`
- `flow_duration`
- `flow_byts_per_s`
- `flow_pkts_per_s`

Recommended handling:

1. clip extreme outliers using a high percentile such as `p99` or `p99.5`
2. apply `log1p`
3. optionally z-score the transformed value for linear models

Why `log1p`:

- many network-flow metrics are highly right-skewed
- `log1p(x)` compresses the tail but preserves order
- it is safe for zero because `log1p(0) = 0`

Examples:

- `log1p(0) = 0`
- `log1p(9) ≈ 2.30`
- `log1p(999) ≈ 6.91`

This means the difference between `9` and `999` stays visible, but no single huge value dominates the model as strongly as in raw space.

### 7.4 Signed delta-like features

Examples:

- forward mean packet length minus backward mean packet length

Recommended handling:

- keep the raw signed value
- optionally use robust scaling or z-score
- do not apply `log1p` directly to signed values

If a compressed magnitude view is useful, derive:

- `sign(x) * log1p(abs(x))`

or keep:

- raw signed delta
- `log1p(abs(delta))` as an auxiliary feature

### 7.5 Sparse flag counts

Examples:

- `syn_flag_cnt`
- `rst_flag_cnt`
- `urg_flag_cnt`

Recommended handling:

- keep presence indicators
- optionally keep clipped counts
- if the tail is long, also keep `log1p(count)`

## 8. Noise Reduction Policy

Noise reduction should happen before feature construction.

Recommended rules:

- remove duplicate embedded header rows
- normalize headers to stable `snake_case`
- convert malformed numerics to `NaN`
- replace `inf/-inf` with `NaN`
- fill numeric missing values with `0` only where zero is a safe neutral value
- keep raw labels, but also create coarser family mappings

The goal is to reduce technical noise, not invent attack evidence.

## 9. Token Strategy for Network Context

Network data still contains high-leakage transport identifiers. For CICIDS2018, tokenization should be coarse and behavior-friendly.

Recommended token columns:

- `protocol_token`
  - `tcp`
  - `udp`
  - `icmp`
  - `other_protocol`
- `port_token`
  - `system_port`
  - `registered_port`
  - `dynamic_port`
  - `invalid_port`
- `transport_token`
  - combine protocol and port family
  - example: `tcp|system_port`

Why use tokens:

- they reduce raw identifier granularity
- they preserve context without making one exact port dominate
- they are easier to audit than arbitrary integer embeddings

These token columns should usually be:

- kept in the dataset
- available for audit
- optional for training

## 10. Feature Construction Strategy

Derived features should emphasize behavior blocks rather than one flat pile of unrelated metrics.

Recommended feature blocks:

- `transport`
  - protocol indicators
  - port family indicators
- `volume`
  - total packets
  - total bytes
  - bytes per packet
  - log-compressed packet and byte magnitude
- `directionality`
  - forward share
  - backward share
  - imbalance ratios
  - clipped forward/backward ratios
- `timing`
  - `flow_duration_log1p`
  - `flow_bytes_per_second_log1p`
  - `flow_packets_per_second_log1p`
  - active vs idle relationship
- `flags`
  - SYN pressure
  - ACK pressure
  - reset and urgent indicators

The point is to let downstream training run:

- one model on all blocks
- or ablations per block
- or weighted multi-head scoring

## 11. Recommended End-to-End Pipeline

The domain pipeline should run in explicit phases.

### Phase 1: Normalize raw CSV flows

- validate required CICFlowMeter columns
- drop duplicate header rows
- rename to canonical `snake_case`
- parse timestamps
- convert numeric columns
- build label views
- attach metadata
- attach transport tokens

Output:

- normalized flow rows with stable schema

### Phase 2: Profile the normalized dataset

- compute per-column statistics
- group columns by observed range
- group columns by semantic behavior type
- emit scaling recommendations

Output:

- `processing_profile.json`

This file should become the reference for later experiments. If the profile changes a lot between subsets, that is a warning that the train path is unstable.

### Phase 3: Shard

- shard for scalable processing
- keep flows with similar transport keys together if that helps downstream batch work

### Phase 4: Build features

- create volume, directionality, timing, and flag features
- create both raw and transformed versions where useful
- keep raw transport tokens for audit

### Phase 5: Persist feature manifest

- save feature blocks
- save token columns
- save notes about optional blocks and leakage risk

### Phase 6: Split train, validation, and test

- use time-based splitting
- avoid shuffling across time

## 12. Practical Recommendation for This Repository

For this repo, the default CICIDS2018 implementation should:

- keep raw columns for audit
- persist transport tokens
- emit a statistics-driven processing profile
- expose feature blocks for downstream ablations
- use `log1p` primarily on positive long-tailed flow metrics
- avoid training directly on raw `dst_port` as the only service signal

## 13. Summary

The correct CICIDS2018 mindset is:

- treat each row as a flow behavior record
- split processing into normalize, profile, feature, and split phases
- group numeric columns by actual observed scale, not only by raw type
- apply scaling rules that match the distribution
- use coarse tokens for transport context
- let the model learn network behavior, not benchmark shortcuts

# API Anomaly Detection: Data Preprocessing Phase

## Overview

This document defines the production preprocessing phase for an API anomaly detection pipeline that models HTTP requests with NLP-oriented features and text representations.

The preprocessing layer is responsible for converting raw HTTP traffic into a stable, consistent, model-ready representation. Its job is not only to parse requests, but to reduce token noise, preserve attack-relevant structure, and produce endpoint-aware artifacts that can be consumed by downstream feature builders, vectorizers, and anomaly models.

In practice, this phase sits between raw ingestion and feature extraction:

`raw HTTP request -> parsed request object -> normalized request view -> endpoint-aware token stream -> model-ready record`

This stage is operationally critical. If preprocessing is inconsistent, the model will learn formatting artifacts, environment-specific strings, and one-off token variants instead of learning reusable attack patterns.

## Objectives

The preprocessing phase has five concrete objectives:

1. Parse raw HTTP requests into a structured internal representation.
2. Normalize request content so semantically equivalent requests map to the same or similar token space.
3. Reduce token variability to improve model generalization across clients, hosts, encodings, and payload styles.
4. Extract endpoint identity at the `method + host + path` level so requests can be grouped and modeled in operational context.
5. Produce a deterministic tokenization and transformation schema that can be versioned, tested, and reused across training and inference.

Three principles drive the design:

- Normalization is mandatory for ML quality. Attack payloads often vary only in encoding, casing, compression, and superficial formatting.
- Reducing token variability improves generalization. The model should learn structural attack signals, not memorize random literals.
- Endpoint-level grouping is required. A request that is normal for one endpoint may be anomalous for another.

## Input / Output Definition

### Input

The preprocessing phase accepts raw HTTP request events from packet capture reconstruction, reverse proxy logs, API gateways, WAF mirrors, or application-side request logs.

Minimum required fields:

| Field | Type | Description |
| --- | --- | --- |
| `raw_request` | string or bytes | Full HTTP request including request line, headers, and optional body |
| `event_timestamp` | timestamp | Event time from the collector or source system |
| `source_id` | string | Source stream, file, host, or sensor identifier |

Optional but recommended fields:

| Field | Type | Description |
| --- | --- | --- |
| `client_ip` | string | Source IP if available |
| `transport_protocol` | string | Typically `http` or `https` |
| `tls_sni` | string | SNI if host header is missing or untrusted |
| `request_id` | string | Upstream request correlation id |

### Output

The preprocessing phase emits a structured record suitable for downstream feature extraction and NLP modeling.

Core output fields:

| Field | Type | Description |
| --- | --- | --- |
| `event_id` | string | Stable event identifier |
| `event_timestamp` | timestamp | Normalized event time |
| `method` | string | Uppercased HTTP method |
| `host` | string | Normalized request host |
| `path` | string | Normalized path |
| `query_string` | string | Normalized query string |
| `endpoint_key` | string | `METHOD host path` |
| `filtered_headers` | map | Whitelisted and normalized headers |
| `body_text` | string | Decoded and normalized body |
| `request_text` | string | Canonical request text for NLP/vectorization |
| `token_stream` | list[string] | Tokenized representation after transformation |
| `normalization_flags` | map | Flags describing applied transformations |
| `parse_status` | string | `ok`, `partial`, or `invalid` |

Optional derived fields:

| Field | Type | Description |
| --- | --- | --- |
| `path_template` | string | Path with dynamic segments abstracted |
| `query_key_set` | list[string] | Sorted normalized query parameter names |
| `content_type_bucket` | string | Normalized content type family |
| `body_encoding` | string | `plain`, `gzip`, `deflate`, `br`, `unknown` |

## Processing Pipeline (step-by-step)

The preprocessing pipeline is deterministic. The same input must always produce the same output.

### 1. Ingest Cisco Ariel raw datasets

For this domain, the raw source should be taken from:

`data/raw/Cisco_Ariel_Uni_API_security_challenge/Datasets`

Expected source artifacts:

- `dataset_1_train.7z`
- `dataset_1_val.7z`
- `dataset_2_train.7z`
- `dataset_2_val.7z`
- `dataset_3_train.7z`
- `dataset_3_val.7z`
- `dataset_4_train.7z`
- `dataset_4_val.7z`

Processing rule:

- unpack each archive into a deterministic staging location before parsing
- preserve dataset id and split as first-class metadata on every emitted record
- process datasets in ascending order `1 -> 2 -> 3 -> 4` because complexity increases by level
- do not mix raw files from different dataset levels before normalization and schema validation

Dataset-specific mindset:

- `Dataset_1`: basic API traffic, fewest attacks, fewest endpoints, suitable for validating the parser and base normalization path
- `Dataset_2`: more attacks, more endpoints, more randomization, so token normalization and endpoint grouping must be more stable
- `Dataset_3`: same traffic family but with more complex parameters in requests, so parameter parsing and value abstraction become mandatory rather than optional
- `Dataset_4`: most advanced traffic with redirection, more request types, deeper data access, and the widest behavioral coverage, so edge-case handling must already be production-ready

Why this step exists:

- the four Cisco Ariel datasets are not equivalent difficulty levels of the same exact raw shape
- each level introduces more variability that directly affects parsing, normalization, and feature stability
- the preprocessing contract must hold across all four datasets, not only on the easiest one

Output of this step:

- dataset-scoped raw artifacts ready for parsing with `dataset_id` and `data_split` attached

### 2. Ingest raw request event

The pipeline receives raw bytes or text plus source metadata.

Actions:

- assign or derive `event_id`
- attach source metadata
- preserve the original payload for audit or replay
- reject empty payloads early if they do not meet minimum parse requirements

Output of this step:

- immutable raw input record

### 3. Parse raw HTTP request

The parser separates the request into:

- request line
- method
- target URL or path
- HTTP version
- headers
- body

Parsing rules:

- split header block and body at the first `\r\n\r\n` or `\n\n`
- parse the first line as `METHOD target HTTP/version`
- treat malformed or missing version as a partial parse, not an automatic drop
- preserve duplicate headers where protocol semantics allow them
- store original header order only if later forensic analysis requires it

Why this matters:

- downstream logic depends on a correct distinction between path, query, headers, and body
- attack indicators are often field-specific
- combining malformed components too early destroys useful structure

### 4. Normalize request components

Normalization is applied after parsing and before tokenization.

Normalization actions:

- uppercase HTTP method
- lowercase host
- lowercase header names
- trim whitespace around header names and values
- decode percent-encoded URL components
- collapse duplicate slash runs in path only if the deployment treats them as equivalent
- decode compressed bodies when `Content-Encoding` is supported
- decode bytes into text using charset from `Content-Type`, then UTF-8 fallback, then safe replacement
- normalize line endings in body content

Why normalization is critical for ML models:

- `SELECT`, `select`, `%53%45%4c%45%43%54`, and mixed-case variants should not become unrelated features
- the same exploit can be wrapped in gzip, URL encoding, or mixed casing
- without normalization, the model wastes capacity learning format noise instead of attack semantics

### 5. Validate and filter headers

Header handling is intentionally strict. Most headers are operational noise for anomaly modeling.

The pipeline validates headers, then keeps only a whitelist of security-relevant or context-relevant headers.

Typical whitelist:

- `host`
- `content-type`
- `content-length`
- `content-encoding`
- `user-agent`
- `cookie`
- `authorization`
- `x-forwarded-for`
- `x-requested-with`
- `accept`

Actions:

- drop non-whitelisted headers from the modeling view
- keep the full raw header map only in audit storage if needed
- normalize repeated headers into a stable join rule
- redact or hash sensitive values when policy requires it

Why whitelist-based filtering matters:

- high-cardinality headers inflate vocabulary size
- infrastructure headers vary across environments and deployments
- reducing irrelevant token diversity improves generalization and lowers inference cost

### 6. Extract endpoint identity

The endpoint extraction stage derives the operational grouping key used by downstream models and baselines.

Endpoint key format:

`METHOD host path`

Example:

`POST api.example.com /v1/orders`

This step may also produce a path template:

`POST api.example.com /v1/orders/{id}`

Why endpoint-level grouping is required:

- the same payload can be normal for `/search` and anomalous for `/admin/import`
- token distributions differ significantly by endpoint
- anomaly thresholds should be learned relative to endpoint behavior, not globally across all traffic

### 7. Build canonical request text

After normalization and filtering, the pipeline assembles a canonical request text that is stable across equivalent requests.

Recommended composition:

1. method
2. host
3. normalized path or path template
4. normalized query keys and transformed values
5. whitelisted header names and transformed values
6. normalized body representation

Example canonical text:

```text
POST api.example.com /v1/users query:role=<alpha> sort=<alpha> header:content-type=application/json body:{"username":"<alpha>","email":"<email>"}
```

### 8. Tokenize and transform

Tokenization should preserve security-relevant delimiters and common exploit primitives.

The tokenizer emits:

- lexical tokens
- structural markers
- abstracted value classes
- optional attack-pattern markers

Typical outputs:

- raw lexical tokens for stable keywords
- normalized placeholders for variable values
- explicit separators for path, query, headers, and body regions

### 9. Emit model-ready record

The final record contains:

- normalized fields
- endpoint grouping key
- transformed token stream
- flags that describe parse and normalization outcomes
- dataset provenance fields such as `dataset_id` and `data_split`

This output becomes the contract for feature builders and training/inference jobs.

## Detailed Transformation Rules

This section defines the exact transformation behavior.

### Request Line Rules

| Input Component | Rule | Example |
| --- | --- | --- |
| method | uppercase | `post` -> `POST` |
| host | lowercase, strip default port if configured | `API.EXAMPLE.COM:443` -> `api.example.com` |
| path | URL decode, normalize slashes if allowed | `/v1/%75sers//123` -> `/v1/users/123` |
| query string | parse into key-value pairs, normalize keys, transform values | `A=1&b=Admin` -> `a=<int>&b=<alpha>` |

### Header Rules

| Rule | Behavior |
| --- | --- |
| header names | lowercase and trim |
| non-whitelisted headers | removed from modeling view |
| repeated headers | join using a deterministic delimiter such as `;` |
| header values | trim, decode if encoded, redact or hash if sensitive |

### Body Rules

| Condition | Behavior |
| --- | --- |
| `Content-Encoding: gzip` | decompress before parsing |
| `Content-Type: application/json` | parse as JSON if valid, then canonicalize |
| `Content-Type: application/x-www-form-urlencoded` | parse as key-value pairs |
| `Content-Type: text/*` | normalize whitespace and casing policy |
| unsupported binary body | replace with a stable binary placeholder and length metadata |

### Value Abstraction Rules

Replace high-variability literals with stable classes where possible.

| Value Pattern | Output Token |
| --- | --- |
| integer | `<int>` |
| float | `<float>` |
| UUID | `<uuid>` |
| email | `<email>` |
| long hex string | `<hex>` |
| base64-like string | `<base64>` |
| alpha-only word | `<alpha>` if value identity is not important |
| mixed alphanumeric id | `<id>` |
| timestamp/date | `<timestamp>` |
| URL value | `<url>` |
| SQL-like fragment | `<sql_pattern>` |
| script-like fragment | `<script_pattern>` |

This is one of the main mechanisms for reducing token variability. It prevents the model from overfitting to request-specific values while preserving attack shape.

## Endpoint Extraction Logic

Endpoint extraction is performed after method, host, and path normalization.

### Endpoint key construction

Base key:

`endpoint_key = METHOD + " " + normalized_host + " " + normalized_path`

Example:

```text
PUT api.example.com /v2/profile/update
```

### Path templating

When path segments are likely dynamic identifiers, convert them into placeholders for grouping and generalization.

Templating candidates:

- numeric ids
- UUIDs
- long hashes
- opaque mixed-case tokens

Examples:

| Raw Path | Path Template |
| --- | --- |
| `/v1/orders/12345` | `/v1/orders/{id}` |
| `/v1/orders/550e8400-e29b-41d4-a716-446655440000` | `/v1/orders/{uuid}` |
| `/download/4f9a91bcaa12ef99` | `/download/{token}` |

### Grouping strategy

Use both forms when needed:

- `endpoint_key_raw` for exact routing context
- `endpoint_key_template` for generalized endpoint statistics

Operational guidance:

- use template grouping for baseline behavior modeling
- use raw grouping when exact endpoint matching is important for alert investigation

## Design Decisions & Rationale

### Normalize before feature extraction

Feature extraction on raw traffic creates sparse, unstable vocabularies. Normalization reduces representational entropy before the model sees the request.

### Keep field boundaries explicit

Path, query, headers, and body should not be flattened too early. Different fields carry different semantics and different attack surfaces.

### Prefer whitelist filtering over blacklist filtering

A blacklist is difficult to maintain and tends to leak irrelevant infrastructure noise into the feature space. A whitelist keeps the modeling surface controlled and reviewable.

### Abstract values aggressively, but not blindly

Identifiers, timestamps, and generated tokens usually hurt generalization. However, some literal values are security-relevant and should be preserved or pattern-labeled. For example, `union select` should not be abstracted away.

### Group by endpoint

API behavior is endpoint-dependent. The same content type, parameter count, or token distribution can be benign for one route and suspicious for another.

## Edge Cases Handling

The preprocessing phase must be resilient to imperfect traffic.

### Malformed requests

Behavior:

- attempt partial parse
- set `parse_status=partial`
- preserve raw payload for audit
- emit best-effort normalized fields when possible

### Missing host header

Behavior:

- use absolute URL host if present
- otherwise fallback to TLS SNI or source metadata if policy allows
- if still unavailable, set `host=unknown`

### Unsupported compression

Behavior:

- keep body as undecoded bytes summary
- set `body_encoding=unknown`
- record a normalization flag

### Double-encoded payloads

Behavior:

- decode in controlled passes up to a configured maximum
- stop early if further decoding is unsafe or non-deterministic

### Large bodies

Behavior:

- cap body size for NLP text generation
- keep length metadata separately
- optionally retain a truncated normalized preview

### Sensitive data in headers or body

Behavior:

- redact or hash secrets such as bearer tokens, session cookies, and API keys
- do not emit secrets into `request_text` or `token_stream`

### Binary or mixed-content payloads

Behavior:

- do not force binary blobs into text tokenization
- replace with stable placeholders such as `<binary_body>`
- expose size and content-type metadata separately

## Performance Considerations

Preprocessing can become the dominant cost in large-scale traffic analysis if not controlled.

Key considerations:

- parsing and decompression must be streaming-friendly where possible
- body normalization should enforce hard size limits
- repeated regex passes over large payloads should be minimized
- tokenization rules should be compiled and reused
- whitelist filtering should happen before expensive body or header transformations when possible
- canonicalization must be deterministic but not unnecessarily expensive

Production recommendations:

- precompile normalization and tokenization regex patterns
- cache path templating decisions for hot endpoints
- process request bodies conditionally based on content type and size
- emit counters for parse failures, decompression failures, truncation, and redaction

## Extensibility & Configuration

The preprocessing phase should be configurable without changing code behavior accidentally.

Recommended configuration surface:

| Config Key | Purpose |
| --- | --- |
| `header_whitelist` | Controls headers kept in the modeling view |
| `max_body_bytes` | Caps body size processed for text extraction |
| `supported_content_encodings` | Defines allowed decompressors |
| `url_decode_passes` | Limits recursive decoding |
| `enable_path_templating` | Enables endpoint generalization |
| `sensitive_header_policy` | `drop`, `hash`, or `redact` |
| `value_abstraction_policy` | Controls literal-to-placeholder mapping |
| `preserve_security_keywords` | Prevents abstraction of critical exploit tokens |
| `emit_raw_audit_copy` | Keeps raw request for offline review |

Versioning guidance:

- treat preprocessing as a versioned contract
- every rule change should increment a preprocessing version
- models should record which preprocessing version they were trained on

## Example (before/after transformation)

### Raw HTTP request

```http
POST /V1/Users/%32%31/profile?id=98765&role=Admin&redirect=https%3A%2F%2Fevil.example%2Fcb HTTP/1.1
Host: API.EXAMPLE.COM
User-Agent: Mozilla/5.0
Content-Type: application/json
Content-Encoding: gzip
X-Trace-Id: 3f8c8ab2-2a11-49fd-8a18-7713b55d1111
Authorization: Bearer eyJhbGciOi...

<gzip body bytes>
```

Decoded body:

```json
{
  "username": "AdminUser",
  "comment": "<ScRiPt>alert(1)</ScRiPt>",
  "profileId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### After preprocessing

#### Structured fields

| Field | Value |
| --- | --- |
| `method` | `POST` |
| `host` | `api.example.com` |
| `path` | `/v1/users/21/profile` |
| `path_template` | `/v1/users/{id}/profile` |
| `query_string` | `id=<int>&redirect=<url>&role=<alpha>` |
| `endpoint_key` | `POST api.example.com /v1/users/21/profile` |
| `endpoint_key_template` | `POST api.example.com /v1/users/{id}/profile` |
| `filtered_headers` | `content-type=application/json`, `content-encoding=gzip`, `user-agent=mozilla/5.0`, `authorization=<redacted>` |
| `body_text` | `{"username":"<alpha>","comment":"<script_pattern>","profileid":"<uuid>"}` |

#### Canonical request text

```text
POST api.example.com /v1/users/{id}/profile query:id=<int> role=<alpha> redirect=<url> header:content-type=application/json header:user-agent=mozilla/5.0 body:{"username":"<alpha>","comment":"<script_pattern>","profileid":"<uuid>"}
```

#### Token stream

```text
[
  "POST",
  "api.example.com",
  "/v1/users/{id}/profile",
  "query:id",
  "<int>",
  "query:role",
  "<alpha>",
  "query:redirect",
  "<url>",
  "header:content-type",
  "application/json",
  "header:user-agent",
  "mozilla/5.0",
  "body:username",
  "<alpha>",
  "body:comment",
  "<script_pattern>",
  "body:profileid",
  "<uuid>"
]
```

### Token mapping table

| Raw Token | Normalized Output | Reason |
| --- | --- | --- |
| `API.EXAMPLE.COM` | `api.example.com` | host normalization |
| `%32%31` | `21` | URL decoding |
| `98765` | `<int>` | reduce numeric variability |
| `Admin` | `<alpha>` | reduce lexical variability |
| `https%3A%2F%2Fevil.example%2Fcb` | `<url>` | preserve semantic type |
| `Bearer eyJhbGciOi...` | `<redacted>` | secret protection |
| `<ScRiPt>alert(1)</ScRiPt>` | `<script_pattern>` | preserve attack semantics |
| `550e8400-e29b-41d4-a716-446655440000` | `<uuid>` | abstract dynamic identifier |

### Second example: SQL-style query payload

#### Raw request

```http
GET /search?q=%27%20UNION%20SELECT%20password%20FROM%20users--&page=1 HTTP/1.1
Host: shop.example.com
Accept: application/json
X-Debug-Trace: abc-123
```

#### After preprocessing

Canonical request text:

```text
GET shop.example.com /search query:q=<sql_pattern> page=<int> header:accept=application/json
```

Token mapping:

| Raw Token | Normalized Output |
| --- | --- |
| `%27%20UNION%20SELECT%20password%20FROM%20users--` | `<sql_pattern>` |
| `1` | `<int>` |
| `X-Debug-Trace` | removed |

## Summary

The data preprocessing phase is a control surface for model quality. It determines whether the anomaly detector learns reusable request behavior or overfits to formatting noise, dynamic values, and environment artifacts.

For production use, preprocessing must be:

- deterministic
- endpoint-aware
- normalization-heavy
- token-variability aware
- explicit about filtering and redaction
- versioned as part of the model contract

If those guarantees hold, downstream NLP-based anomaly models will train on a cleaner and more operationally meaningful representation of API traffic.

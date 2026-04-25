# API Traffic Processing Mindset

## Purpose

This document defines how raw API traffic should be processed before feature extraction and modeling.

The goal is not just to parse requests. The goal is to turn noisy HTTP events into stable, repeatable, endpoint-aware records that preserve attack-relevant structure while reducing useless variation.

The processing contract is:

`raw event -> parsed request -> normalized request view -> semantic representation -> model-ready record`

If this stage is inconsistent, downstream models will learn formatting noise, one-off literals, and environment artifacts instead of reusable behavioral patterns.

## Core Goals

The processing layer must do five things well:

1. Parse each raw request into a structured representation.
2. Normalize semantically equivalent content into a stable form.
3. Reduce token and field variability without erasing attack signals.
4. Preserve endpoint identity so behavior is interpreted in context.
5. Emit deterministic outputs that can be reused across training and inference.

## Guiding Principles

- Normalization is required, not optional.
- Endpoint context matters. A request that is normal for one endpoint may be anomalous for another.
- Preserve both raw fidelity and normalized structure.
- Determinism matters more than cleverness.
- Processing must scale from Dataset 1 through Dataset 4 without changing the contract.

## Input Expectations

At minimum, each event should provide:

- `raw_request` or equivalent request fields
- `event_timestamp` if available
- `source_id`

For the Cisco Ariel dataset used in this repo, the practical raw shape is already partially structured:

- `request.method`
- `request.url`
- `request.headers`
- `request.body`
- `request.Attack_Tag`
- `response.status`
- `response.headers`
- `response.status_code`
- `response.body`

Even when the raw data is nested JSON, processing should still treat it as an ingestion problem first and a feature problem second.

## Required Output Shape

Each processed record should expose a stable representation that downstream code can trust.

Recommended fields:

- `event_id`
- `dataset_id`
- `data_split`
- `record_index`
- `method`
- `host`
- `path_raw`
- `path_normalized`
- `path_template`
- `query_string`
- `query_pairs`
- `query_key_set`
- `headers_filtered`
- `body_raw`
- `body_normalized`
- `endpoint_key`
- `semantic_tokens`
- `normalization_flags`
- `parse_status`

Optional but useful:

- `request_text`
- `response_text`
- `attack_tag`
- `content_type_bucket`
- `body_encoding`
- `request_ast`

## Dataset Handling Rules

Raw Cisco Ariel data should be processed dataset-by-dataset, not mixed together at ingestion time.

Expected artifacts:

- `dataset_1_train.7z`
- `dataset_1_val.7z`
- `dataset_2_train.7z`
- `dataset_2_val.7z`
- `dataset_3_train.7z`
- `dataset_3_val.7z`
- `dataset_4_train.7z`
- `dataset_4_val.7z`

Rules:

- unpack archives into deterministic staging locations
- attach `dataset_id` and `data_split` to every emitted record
- process in ascending order from Dataset 1 to Dataset 4
- validate schema stability before combining outputs across dataset levels

Dataset mindset:

- `Dataset_1`: validate parser behavior, normalization rules, and baseline endpoint grouping
- `Dataset_2`: harden token normalization and endpoint-template stability
- `Dataset_3`: improve parameter parsing and abstraction
- `Dataset_4`: handle the full set of edge cases, redirection patterns, and broad behavioral variation

## Processing Stages

### 1. Ingest

Start from raw archive or JSON input and convert it into immutable input records.

Required actions:

- derive a stable `event_id`
- preserve source metadata
- preserve the original raw payload for replay or audit
- reject empty or unusable records early

### 2. Parse Request Structure

Build a structured request view before tokenization.

Required fields to derive:

- method
- host
- path
- query string
- query pairs
- headers
- body

For this dataset, the JSON already gives most of this structure. Even so, the processing code should rebuild a consistent internal representation rather than trusting raw field formatting blindly.

### 3. Normalize

Normalization happens before semantic extraction.

Required normalization steps:

- uppercase HTTP method
- lowercase host
- lowercase header names
- trim surrounding whitespace
- percent-decode URL components where safe
- normalize body encoding and line endings
- sort query keys when deriving set-style views
- keep both raw and normalized values

Normalization must reduce noise without destroying evidence. For example, encoded SQLi, traversal, or template-injection payloads should become easier to compare across requests, but the original raw form must still be recoverable.

### 4. Filter and Validate Headers

Headers should be handled conservatively.

Recommended modeling whitelist:

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

Rules:

- keep the full raw header map only for audit if needed
- use a stable join rule for repeated headers
- redact or hash sensitive values where policy requires it
- avoid feeding high-cardinality infrastructure headers directly into modeling

### 5. Derive Endpoint Identity

Endpoint identity is a first-class feature, not a convenience field.

Use:

`endpoint_key = METHOD + host + normalized_path_or_template`

Also derive a `path_template` when dynamic segments or injected values appear.

Why this matters:

- anomaly meaning depends on endpoint context
- the same token pattern can be benign on one endpoint and suspicious on another
- endpoint-aware grouping improves both detection quality and interpretability

### 6. Build Semantic Representation

After structure and normalization are stable, convert the request into semantic units.

Examples:

- method tokens
- path-segment tokens
- path-template tokens
- query-key tokens
- body-shape tokens
- header-presence tokens
- encoding flags
- attack-pattern indicators such as traversal, SQL keywords, template markers, script markers, or log-forging separators

This stage should capture meaning, not just text fragments.

## Worked Example: Raw Request -> Processed Request

The mindset should always be explainable on a single concrete request.

Example raw event from `dataset_1_train_first_1000.json`:

```json
{
  "request": {
    "headers": {
      "Host": "127.0.0.1:5000",
      "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0",
      "Accept-Encoding": "gzip, deflate, br",
      "Accept": "*/*",
      "Connection": "keep-alive",
      "Accept-Language": "de",
      "Sec-Fetch-Site": "none",
      "Sec-Fetch-Mode": "same-origin",
      "Sec-Fetch-User": "?1",
      "Sec-Fetch-Dest": "document",
      "Set-Cookie": "['ck=<long_value>; Domain=localhost:5000; Expires=Wed, 21 Dec 2022 18:12:16 GMT', 'uu=<long_value>; Domain=localhost:5000; Expires=Tue, 06 Dec 2022 18:12:16 GMT', 'session=d1642031-df8b-4857-8e78-d9582228031e; Expires=Mon, 21 Nov 2022 18:42:16 GMT']",
      "Date": "Mon, 21 Nov 2022 18:12:16 GMT",
      "Cookie": "username=<very_long_payload>; username=<second_payload>"
    },
    "method": "GET",
    "url": "http://127.0.0.1:5000/cookielogin",
    "body": "",
    "Attack_Tag": "Cookie Injection"
  },
  "response": {
    "status": "200 OK",
    "headers": {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": "105"
    },
    "status_code": 200,
    "body": "<h1>Logged in as Cedric</h1><form method='POST'><input type='submit' name='logout' value='Logout'></form>"
  }
}
```

This example is useful because it shows the central processing problem:

- many raw fields exist
- some fields are useful for modeling
- some fields are only operational noise
- some values are dynamic and must be abstracted
- the attack meaning is concentrated in a specific field, not across the entire request equally

### Step 1: Preserve Raw Event

Do not mutate or overwrite the original structure.

Keep:

- the full raw event
- original header names and values
- original URL string
- original body
- original response body if later audit is needed

Why:

- audit and replay need the original payload
- later normalization bugs are easier to detect when raw data is preserved
- attack evidence may be lost if only normalized output is kept

### Step 2: Build Parsed Request View

From the raw event above, derive:

```json
{
  "method": "GET",
  "scheme": "http",
  "host": "127.0.0.1:5000",
  "path_raw": "/cookielogin",
  "query_string_raw": "",
  "headers_raw": {
    "Host": "127.0.0.1:5000",
    "User-Agent": "Mozilla/5.0 ...",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": "*/*",
    "Connection": "keep-alive",
    "Accept-Language": "de",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "same-origin",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Set-Cookie": "[...]",
    "Date": "Mon, 21 Nov 2022 18:12:16 GMT",
    "Cookie": "username=<payload>; username=<payload>"
  },
  "body_raw": ""
}
```

At this stage, the goal is only structural separation.

### Step 3: Remove Fields That Are Not Needed for Modeling

This is where many pipelines fail. They keep too much.

For anomaly detection on API traffic, not every field should enter the modeling view.

For the example above:

Keep in modeling view:

- `method`
- `host`
- `path`
- `accept`
- `accept-encoding`
- `user-agent` only if you explicitly want client-behavior context
- `cookie`
- `response.status_code` only if response-side features are allowed

Drop from modeling view:

- `connection`
- `accept-language`
- `sec-fetch-site`
- `sec-fetch-mode`
- `sec-fetch-user`
- `sec-fetch-dest`
- `date`
- raw `set-cookie` unless response-cookie behavior is part of the task

Why these are dropped:

- they are browser or transport noise
- they are high-variability and low-semantic for attack detection
- they increase vocabulary size without improving attack discrimination

Important distinction:

- dropped from modeling view does not mean deleted from raw storage
- raw storage and model view are different layers

### Step 4: Normalize Useful Fields

Convert the same request into a stable form:

```json
{
  "method": "GET",
  "host": "127.0.0.1:5000",
  "path_normalized": "/cookielogin",
  "query_pairs": [],
  "headers_filtered": {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br",
    "cookie": "username=<payload>; username=<payload>",
    "host": "127.0.0.1:5000",
    "user-agent": "mozilla/firefox"
  },
  "body_normalized": ""
}
```

Normalization rules used here:

- lowercase header names
- trim header whitespace
- normalize `User-Agent` into a family bucket instead of keeping the full literal string
- preserve cookie structure but do not keep opaque payload bytes as-is in the modeling view

## Dynamic Value Standardization

Dynamic values should be treated like variables in code.

The model should learn:

- where the variable appears
- what type of variable it is
- whether its structure is suspicious

The model should not memorize:

- exact session IDs
- exact timestamps
- exact random tokens
- exact encoded blobs

Examples of dynamic-to-static conversion:

- UUID -> `<UUID>`
- integer id -> `<INT>`
- long random string -> `<RAND>`
- base64-like blob -> `<B64>`
- date/time -> `<DATETIME>`
- email -> `<EMAIL>`
- IP -> `<IP>`
- hash-like token -> `<HASH>`
- path parameter value -> `{PATH_VAR}`
- query parameter value -> `{QUERY_VAL}`
- cookie value -> `{COOKIE_VAL}`

For the cookie injection example, the key standardization idea is:

```text
Cookie: username=<very_long_payload>; username=<second_payload>
```

becomes

```text
cookie: username={COOKIE_VAL_B64_SUSPICIOUS}; username={COOKIE_VAL_SERIALIZED}
```

or, at a more general level,

```text
cookie: username={COOKIE_VAL}; username={COOKIE_VAL}
```

The correct level depends on your modeling goal:

- coarse abstraction if you want stronger generalization
- typed abstraction if you want better interpretability and attack-family separation

## Attack-Focused Processing

Some attacks are field-centric. Processing should respect that.

Examples:

- `Cookie Injection` focuses primarily on the `cookie` header
- `SQL Injection` often concentrates in query values, form fields, or path fragments
- `Directory Traversal` often concentrates in path segments
- `Log Forging` often concentrates in newline or separator patterns in parameters
- template or code injection often appears in path, query, cookie, or body text

For `Cookie Injection`, the best practice is:

1. Preserve the cookie header.
2. Parse the cookie into key/value pairs.
3. Standardize dynamic values.
4. Emit cookie-focused semantic features.
5. Do not let unrelated browser metadata dominate the token space.

So the processed cookie should look more like:

```json
{
  "cookies_raw": [
    {"name": "username", "value": "<payload_1>"},
    {"name": "username", "value": "<payload_2>"}
  ],
  "cookies_normalized": [
    {"name": "username", "value_type": "encoded_serialized_blob"},
    {"name": "username", "value_type": "encoded_serialized_blob"}
  ],
  "cookie_features": {
    "cookie_count": 2,
    "duplicate_cookie_name": true,
    "cookie_name_set": ["username"],
    "has_long_cookie_value": true,
    "has_base64_like_cookie": true,
    "has_serialized_object_pattern": true
  }
}
```

This is much better than feeding the entire raw cookie string into a tokenizer.

## Attack Tag Handling Strategy

The document should handle every attack tag explicitly.

The goal is not to build seven separate pipelines. The goal is to run one common processing pipeline with tag-aware feature emphasis.

For each tag, define:

- primary signal location
- what to preserve
- what to abstract
- what to drop from modeling view
- what semantic features should be emitted

### Benign

Meaning:

- normal application traffic with no known attack intent

Primary signal location:

- endpoint behavior
- normal parameter patterns
- ordinary header and body structure

Handling strategy:

- process with the exact same parser and normalization rules as attack traffic
- do not create special benign-only preprocessing rules
- use benign records to learn normal endpoint templates, parameter sets, and body shapes

Keep:

- endpoint key
- path template
- query key set
- body structure
- stable header presence

Abstract:

- IDs
- timestamps
- session values
- UUIDs
- randomized strings

Drop from modeling view:

- browser transport noise
- unstable infrastructure-only headers

Good semantic outputs:

- endpoint template frequency
- normal query-key combinations
- common body-schema patterns

### SQL Injection

Meaning:

- attack content is inserted into SQL-facing inputs so backend query logic changes

Primary signal location:

- query parameter values
- form fields in body
- JSON field values
- sometimes path fragments

Handling strategy:

- parse query and body fields into key/value structure
- percent-decode and normalize case where safe
- preserve raw payload beside normalized payload
- detect SQL meta-syntax, operators, comments, boolean tautologies, and query chaining patterns

Keep:

- query keys
- query values in normalized and abstracted form
- body field names
- body field value types
- endpoint context

Abstract:

- literal usernames, ids, emails, and passwords
- numeric constants
- quoted string constants

Do not over-abstract:

- SQL keywords
- quote boundaries
- comment markers
- operator sequences
- union/select/order/by/drop style patterns

Drop from modeling view:

- unrelated browser headers
- unrelated response decoration unless response leakage study is intended

Good semantic outputs:

- `SQL_KEYWORD_SELECT`
- `SQL_KEYWORD_UNION`
- `SQL_COMMENT_MARKER`
- `SQL_BOOLEAN_TAUTOLOGY`
- `QUERY_KEY_username`
- `BODY_FIELD_password`
- `HAS_QUOTE_BREAKOUT`

### Directory Traversal

Meaning:

- path navigation strings attempt to access files or directories outside the intended scope

Primary signal location:

- path segments
- download target parameters
- filename query parameters
- occasionally body fields

Handling strategy:

- preserve raw path exactly
- percent-decode path repeatedly but safely for normalized analysis
- split path into segments
- count traversal indicators such as `..`, encoded `..`, repeated separators, and file-target suffixes

Keep:

- raw path
- normalized path
- path segment list
- file-like suffixes
- endpoint key

Abstract:

- target file names into typed placeholders when needed
- platform-specific absolute paths into categories such as `{UNIX_PATH}` or `{WINDOWS_PATH}`

Do not abstract away:

- `../`
- `..\\`
- repeated traversal depth
- sensitive filename markers like `passwd`, `shadow`, `windows.ini`

Drop from modeling view:

- unrelated cookies or browser metadata if not part of the exploit surface

Good semantic outputs:

- `PATH_TRAVERSAL_MARKER`
- `TRAVERSAL_DEPTH_5_PLUS`
- `TARGET_FILE_PASSWD`
- `TARGET_FILE_WINDOWS_INI`
- `ENCODED_TRAVERSAL`

### Remote Code Execution (RCE)

Meaning:

- attacker-controlled input attempts to cause server-side command or code execution

Primary signal location:

- path payloads
- query values
- body values
- sometimes cookies or custom headers

Handling strategy:

- normalize encoding aggressively but preserve raw content
- detect template execution syntax, shell syntax, function-call syntax, import or exec markers, and command separators
- separate command-like content from ordinary text

Keep:

- raw payload
- normalized payload
- payload location such as path, query, body, or cookie
- endpoint key

Abstract:

- command arguments
- file paths inside commands
- specific usernames or hostnames

Do not abstract away:

- execution verbs like `exec`, `eval`, `system`, `os.system`, `subprocess`
- shell separators like `;`, `&&`, `|`, backticks
- template execution markers like `{{ ... }}`
- import and function-call structure

Drop from modeling view:

- unrelated client noise

Good semantic outputs:

- `RCE_EXEC_FUNC`
- `RCE_TEMPLATE_EXPR`
- `RCE_SHELL_SEPARATOR`
- `RCE_IMPORT_OS`
- `PAYLOAD_LOCATION_PATH`
- `PAYLOAD_LOCATION_BODY`

### Cookie Injection

Meaning:

- attacker injects cookie values not legitimately issued for the current session or identity

Primary signal location:

- `cookie` header
- sometimes `set-cookie` response patterns if response-aware processing is enabled

Handling strategy:

- parse cookie header into separate name/value pairs
- preserve duplicate cookie names
- type the cookie values rather than learning full opaque strings
- emphasize cookie names, counts, repetition, value length, encoding style, and serialization patterns

Keep:

- cookie names
- cookie duplication behavior
- cookie value type
- endpoint key

Abstract:

- long cookie payloads into typed placeholders
- session ids into `<UUID>` or `<SESSION_TOKEN>`
- base64-like blobs into `<B64>`

Do not abstract away:

- duplicate cookie keys
- unusual cookie count
- suspicious serialized-object patterns
- mismatch between endpoint and cookie structure

Drop from modeling view:

- `sec-fetch-*`
- `date`
- `connection`

Good semantic outputs:

- `COOKIE_NAME_username`
- `COOKIE_DUPLICATE_NAME`
- `COOKIE_VAL_B64`
- `COOKIE_VAL_SERIALIZED_OBJECT_LIKE`
- `COOKIE_COUNT_2_PLUS`

### Cross Site Scripting (XSS)

Meaning:

- attacker injects client-side executable markup or script that later runs in a browser context

Primary signal location:

- path payloads
- query values
- form values
- JSON string fields

Handling strategy:

- preserve raw encoded payload
- decode HTML and percent encodings into a normalized analysis view
- detect script tags, event handlers, javascript URIs, DOM-breaking sequences, and HTML tag injection patterns

Keep:

- field location
- raw payload
- normalized payload
- endpoint key

Abstract:

- benign surrounding text
- literal constant strings that do not affect the exploit structure

Do not abstract away:

- `<script>`
- `onerror=`
- `onload=`
- `javascript:`
- tag open/close structure
- quote breakout markers

Drop from modeling view:

- unrelated cookies or headers unless the endpoint behavior needs them

Good semantic outputs:

- `XSS_SCRIPT_TAG`
- `XSS_EVENT_HANDLER`
- `XSS_JS_URI`
- `XSS_HTML_BREAKOUT`
- `PAYLOAD_LOCATION_QUERY`

### Log4J

Meaning:

- attacker injects Log4Shell-style lookup expressions that may trigger remote resolution and code execution in vulnerable Java logging paths

Primary signal location:

- path
- query values
- headers such as `user-agent`, `x-forwarded-for`, or custom headers
- body fields

Handling strategy:

- preserve raw `${...}` expressions
- normalize nested or obfuscated lookup syntax when possible
- detect JNDI markers, protocol specifiers, and lookup nesting
- record the field location because Log4J payloads often hide in headers

Keep:

- payload location
- raw lookup string
- normalized lookup string
- endpoint key

Abstract:

- external hostnames into `<REMOTE_HOST>`
- callback paths into typed placeholders

Do not abstract away:

- `${`
- `}`
- `jndi:`
- `ldap:`, `rmi:`, `dns:`, `http:`
- nested variable expansion structure

Drop from modeling view:

- unrelated browser headers that do not carry payloads

Good semantic outputs:

- `LOG4J_LOOKUP_EXPR`
- `LOG4J_JNDI`
- `LOG4J_PROTOCOL_LDAP`
- `LOG4J_NESTED_LOOKUP`
- `PAYLOAD_IN_HEADER_USER_AGENT`

### Log Forging

Meaning:

- attacker injects content that makes generated logs appear to contain fake records, broken structure, or misleading identities

Primary signal location:

- query values
- body fields
- path fragments
- headers that are later logged by the server

Handling strategy:

- preserve newline and separator characters in raw view
- create a normalized structural view that marks CR, LF, tab, delimiter, and log-prefix patterns
- detect timestamp-like fragments, fake severity prefixes, and multi-line injection structure

Keep:

- raw text with newline markers preserved
- normalized text with explicit control-character tokens
- payload location
- endpoint key

Abstract:

- dynamic names, ids, or values inside the forged content

Do not abstract away:

- `\r`
- `\n`
- log prefix markers
- fake timestamp skeletons
- severity-like prefixes such as `INFO`, `WARN`, `ERROR`

Drop from modeling view:

- unrelated static headers if they are not part of the logged fields

Good semantic outputs:

- `LOG_FORGING_CRLF`
- `LOG_FORGING_FAKE_PREFIX`
- `LOG_FORGING_TIMESTAMP_SKELETON`
- `LOG_FORGING_MULTILINE`

## Tag-to-Field Priority Map

When processing a request, the system should know where to focus first.

- `SQL Injection`: query, form body, JSON body, path
- `Directory Traversal`: path, filename query, download target body field
- `RCE`: path, query, body, cookie
- `Cookie Injection`: cookie
- `XSS`: path, query, body
- `Log4J`: headers, query, path, body
- `Log Forging`: query, body, path, logged headers

This priority map should influence semantic extraction, but it should not disable the rest of the common pipeline.

## Raw -> Reduced -> Abstracted Example

Using the same request, the processing should conceptually move through three views.

### View A: Raw

```text
Cookie: username=gASVyQAAAA...; username=gASVKgAAAA...
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0
Connection: keep-alive
Sec-Fetch-Site: none
Date: Mon, 21 Nov 2022 18:12:16 GMT
```

### View B: Reduced Modeling View

```text
method=GET
host=127.0.0.1:5000
path=/cookielogin
cookie=username=<payload>; username=<payload>
accept=*/*
accept-encoding=gzip, deflate, br
user-agent-family=mozilla/firefox
```

### View C: Abstracted Semantic View

```text
METHOD_GET
ENDPOINT_/cookielogin
HEADER_COOKIE_PRESENT
COOKIE_NAME_username
COOKIE_DUPLICATE_NAME
COOKIE_VAL_ENCODED
COOKIE_VAL_LONG
COOKIE_VAL_SERIALIZED_OBJECT_LIKE
UA_BROWSER
UA_FIREFOX
```

This final view is what the model should mostly learn from.

## Static Template Construction

One of the best practices from log parsing also applies here:

- keep the stable words
- abstract the changing words

Examples:

- `/orders/12345` -> `/orders/{PATH_VAR}`
- `/user/alice/profile` -> `/user/{PATH_VAR}/profile`
- `?username=admin&password=123456` -> `?username={QUERY_VAL}&password={QUERY_VAL}`
- `session=d1642031-df8b-4857-8e78-d9582228031e` -> `session={UUID}`
- `username=gASVyQAAAA...` -> `username={COOKIE_VAL_B64}`

For API traffic, this is the equivalent of replacing variables in source code with symbolic placeholders.

The stable template is what defines behavior.
The variable type is what refines the behavior.

## What to Remove vs What to Abstract

This distinction should be explicit.

Remove when the field is mostly transport or browser noise:

- `connection`
- `sec-fetch-*`
- `date`
- unstable one-off infrastructure headers

Abstract when the field is useful but too dynamic in raw form:

- cookie values
- auth tokens
- UUIDs
- IDs in path or query
- timestamps
- long encoded payloads
- randomized filenames

Keep raw and normalized side by side when the field is security-relevant:

- path
- query
- cookie
- authorization
- body

## Minimum Explainability Standard

For every processed field, the pipeline should be able to answer:

1. Why was this field kept?
2. Why was this field dropped?
3. Why was this value abstracted?
4. What stable semantic meaning remains after abstraction?

If the pipeline cannot explain those four points, the preprocessing is still too weak.

## Recommended Internal Representation

If you want a hierarchical view, use an HTTP request tree rather than a source-code AST.

Example structure:

- request
- method
- host
- path
- path segments
- query
- query key/value pairs
- headers
- body
- response metadata

This supports downstream semantic extraction and graph construction without forcing code-analysis tools onto log-like data.

## Graph Mindset

If graph features are needed, the useful graph is a request/entity graph, not a code CFG.

Useful node types:

- request
- endpoint
- query key
- body field
- semantic pattern
- session or client entity if available

Useful edge types:

- request -> endpoint
- request -> query key
- request -> body field
- request -> semantic token
- endpoint -> common template

Graph construction should come after parsing and normalization, not before.

## Label Handling

`Attack_Tag` is valuable for supervision and evaluation, but it should not control parsing logic.

Rules:

- do not make the parser label-aware
- do not let labels change normalization behavior
- use labels for evaluation, diagnostics, supervised experiments, and leakage checks

## Best Practices

- Preserve raw, normalized, and abstracted views side by side.
- Keep the pipeline deterministic.
- Validate on Dataset 1 before scaling out.
- Add new normalization rules only when they reduce noise without erasing behavior.
- Prefer endpoint-aware features over global bag-of-tokens features.
- Separate parsing, normalization, semantic extraction, and feature building into clear stages.
- Keep schema validation strict and early.

## Anti-Patterns

- Treating API traffic as plain free text.
- Mixing all dataset levels before validating processing stability.
- Collapsing raw and normalized values into one lossy field.
- Using source-code AST or CFG tools directly on HTTP data.
- Overusing raw header values or other high-cardinality literals.
- Baking labels into preprocessing decisions.

## Operational Standard

The processing layer is production infrastructure for the modeling stack.

That means:

- every transformation should be explainable
- every emitted field should have a clear contract
- every normalization rule should be deterministic
- every dataset level should pass through the same conceptual pipeline

If a transformation cannot be justified in terms of stability, generalization, or preservation of attack-relevant structure, it probably does not belong in preprocessing.

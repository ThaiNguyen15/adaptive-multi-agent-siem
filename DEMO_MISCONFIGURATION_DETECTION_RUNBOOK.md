# Misconfiguration Detection Demo Runbook

## Local 5-Minute Demo

This repo now includes a minimal runnable demo under `demo_misconfig/`:

```text
demo_misconfig/api_app.py       FastAPI app that generates API request logs
demo_misconfig/infer_alerts.py  Batch model/alert loop that reads logs
requirements-demo.txt           Demo-only web dependencies
```

Architecture:

```text
curl/browser -> FastAPI demo API -> demo_misconfig/logs/api_requests.jsonl
                                      |
                                      v
                         demo_misconfig/infer_alerts.py
                                      |
                                      v
                         demo_misconfig/alerts/alerts.jsonl + SOC console output
```

The alert loop uses simple rule-based inference as a live-demo stand-in. Replace `detect_signal()` or `build_alert()` in `demo_misconfig/infer_alerts.py` with your trained model call when you want to connect the real model.

### 1. Install Demo Dependencies

From the repo root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-demo.txt
```

If your machine exposes Python as `python3` instead of `python`, use `python3 -m venv .venv` and `python3 -m uvicorn ...` for the commands below. If your virtual environment already exists, just activate it and run the two `pip install` commands.

### 2. Start The Demo API

Terminal 1:

```bash
source .venv/bin/activate
python -m uvicorn demo_misconfig.api_app:app --reload --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

### 3. Start The Model/Alert Loop

Terminal 2:

```bash
source .venv/bin/activate
python -m demo_misconfig.infer_alerts
```

The loop reads new log lines every second from:

```text
demo_misconfig/logs/api_requests.jsonl
```

It prints SOC-style alerts and writes them to:

```text
demo_misconfig/alerts/alerts.jsonl
```

### 4. Run Demo Scenarios

Terminal 3:

#### Scenario A: Normal Request, No Alert

```bash
curl -H "Authorization: Bearer demo-token" \
  "http://127.0.0.1:8000/api/profile"
```

Expected behavior:

- API returns `200`.
- A normal log line is written.
- No alert is printed.

#### Scenario B: Misconfiguration, Suspicious Request Accepted With 2xx

SQL-shaped input accepted by an order endpoint:

```bash
curl "http://127.0.0.1:8000/orders/get/country?country=US%27%20OR%201%3D1--"
```

Expected behavior:

- API returns `200`.
- Alert loop prints `CRITICAL - Input validation misconfiguration`.
- This is the main AI-based misconfiguration story: suspicious request shape plus `2xx` response means the endpoint accepted dangerous input.

Optional second accepted-misconfiguration example:

```bash
curl "http://127.0.0.1:8000/static/download_txt/%2e%2e/%2e%2e/etc/passwd.txt"
```

Expected alert:

```text
HIGH - File path validation misconfiguration
```

Optional Log4J/JNDI header example:

```bash
curl -H 'User-Agent: ${jndi:ldap://demo.local/a}' \
  "http://127.0.0.1:8000/forgot-password"
```

Expected alert:

```text
CRITICAL - Dependency/logging misconfiguration risk
```

#### Scenario C: Blocked Attack, Suspicious Request Rejected With 4xx

```bash
curl "http://127.0.0.1:8000/api/search?q=%27%20OR%201%3D1--"
```

Expected behavior:

- API returns `403`.
- Alert loop prints `MEDIUM - Blocked suspicious request: SQL Injection`.
- This is abuse telemetry, not a confirmed misconfiguration, because the endpoint rejected the suspicious request.

### 5. Example SOC Alert Output

```text
CRITICAL - Input validation misconfiguration
Endpoint: GET /orders/get/country
Status: HTTP 200
Finding: SQL Injection
Summary: /orders/get/country accepted suspicious SQL Injection shaped input with HTTP 200.
Root cause: SQL-shaped input reached an API parameter. The endpoint returned 2xx, so this is likely a misconfiguration.
Evidence: request_contains_sql_keywords, response_status_is_2xx, suspicious_request_got_2xx
Zero Trust action: Block or step-up matching requests, alert the API owner, and open a root-cause fix ticket.
Recommended fix: Use parameterized queries and allowlisted input types.
```

### 6. Reset Demo Logs

Stop the API and alert loop, then run:

```bash
rm -f demo_misconfig/logs/api_requests.jsonl demo_misconfig/alerts/alerts.jsonl
```

Restart Terminal 1 and Terminal 2 before the next live demo.

### 7. Where To Connect Your Trained Model

The smallest integration point is:

```python
# demo_misconfig/infer_alerts.py
def detect_signal(event):
    ...
```

Replace the rule checks with your trained model pipeline:

```python
features = build_features_from_event(event)
y_score = model.predict_proba(features)[0, 1]
y_pred = y_score >= threshold
```

Then keep `build_alert()` as the SOC translation layer. That lets the live demo stay simple while the trained model owns the suspicious-request decision.

---

This demo presents `experiments/api_traffic_d1_d2_d3_d4_improved` as a root-cause misconfiguration detection system, not as an attack-label classifier.

The model still uses the learned attack patterns, but the SOC-facing output is:

```text
Suspicious request pattern + endpoint response behavior -> probable misconfiguration -> Zero Trust action -> recommended fix
```

## Demo Positioning

Use this framing:

> The model does not just say "SQL Injection" or "XSS". It detects when an API accepts, rejects, or errors on security-sensitive request shapes. Accepted suspicious requests indicate likely misconfiguration. Rejected suspicious requests indicate attempted abuse with working controls. Server errors indicate fragile or unsafe handling.

Current test performance for the demo experiment:

| Metric | Value |
|---|---:|
| Test rows | 31,072 |
| Accuracy | 0.988 |
| Precision | 0.954 |
| Recall | 0.993 |
| F1 | 0.973 |
| Threshold | 0.05 |

Coverage by labeled signal:

| Dataset label | Test rows | Detection recall | SOC interpretation |
|---|---:|---:|---|
| Cookie Injection | 1,306 | 1.000 | Authentication/session misconfiguration |
| SQL Injection | 1,322 | 1.000 | Input validation misconfiguration |
| Directory Traversal | 671 | 1.000 | Input validation/access-control misconfiguration |
| RCE | 667 | 1.000 | Input validation/design misconfiguration |
| LOG4J | 654 | 1.000 | Dependency/system misconfiguration |
| Log Forging | 677 | 1.000 | Logging/input validation misconfiguration |
| XSS | 1,391 | 0.968 | Input/output validation misconfiguration |

## Detection Pipeline

### 1. Logs

Input sources:

- API gateway, reverse proxy, WAF, or application access logs
- Request method, host, path, query, headers, cookies, body summary
- Response status, content type, response body summary, error indicators
- Optional identity context: user id, service account, auth scheme, source IP

Demo fields already present in the prediction output:

- `event_id`
- `dataset_id`
- `event_timestamp`
- `endpoint_key`
- `path_template`
- `method`
- `status_code`

### 2. Normalization

Normalize the request before scoring so encoded payloads and route variants compare consistently:

- Percent-decode path/body where safe
- Collapse route variables into templates such as `/orders/get/country/{num}`
- Preserve raw values for evidence
- Extract headers and cookies into structured fields

Important model evidence fields:

- `path_percent_decoded`
- `body_percent_decoded`
- `request_has_authorization`
- `request_has_cookie`

### 3. Feature Extraction

The feature layer converts logs into security signals:

| Feature | Meaning |
|---|---|
| `request_contains_sql_keywords` | SQL meta-syntax, boolean tautologies, comments, query chaining |
| `request_contains_traversal` | `../`, encoded traversal, file breakout patterns |
| `request_contains_xss` | script tags, JavaScript URI, event handlers, HTML breakout |
| `request_contains_log4j` | Log4J lookup/JNDI syntax |
| `request_header_contains_log4j` | Log4J lookup/JNDI syntax in headers |
| `request_contains_rce` | template execution, shell, Python builtins/import markers |
| `request_contains_log_forging` | newline/control markers that can alter logs |
| `response_status_is_2xx` | API accepted the suspicious request |
| `response_status_is_4xx` | API rejected the suspicious request |
| `response_status_is_5xx` | API errored while handling the request |
| `suspicious_request_got_2xx` | strongest misconfiguration evidence |
| `suspicious_request_got_4xx` | attempted abuse, control probably worked |
| `suspicious_request_got_5xx` | unsafe handling or crash-prone control path |

### 4. Model

The retrieval model compares current request behavior against benign endpoint behavior.

Outputs:

- `y_score`: anomaly score
- `nearest_benign_similarity`: similarity to normal endpoint traffic
- `y_pred`: anomaly decision
- `predicted_attack_type`: nearest attack-shaped behavior
- `security_finding`: SOC-facing finding key
- `explanation`: compact evidence string

Do not present `predicted_attack_type` as the final answer. Use it as an internal routing key for the misconfiguration explanation.

### 5. Alert

Alert schema for the demo:

```json
{
  "title": "Input validation misconfiguration on /orders/get/country",
  "severity": "critical",
  "root_cause": "SQL-facing parameter accepted SQL syntax and returned 2xx",
  "model": {
    "anomaly_score": 0.311,
    "nearest_benign_similarity": 0.689,
    "internal_signal": "SQL Injection"
  },
  "evidence": [
    "request_contains_sql_keywords",
    "response_status_is_2xx",
    "suspicious_request_got_2xx"
  ],
  "zero_trust_action": "block request, alert owner, require parameterized-query fix"
}
```

## Attack Label To Misconfiguration Mapping

### Authentication/session misconfiguration

| Dataset label | Reinterpreted signal | Root cause language | Demo evidence | Response |
|---|---|---|---|---|
| `Cookie Injection` | Client-controlled session material is accepted or reused | Session cookie integrity and flags are weak or missing | `request_has_cookie`, `response_status_is_2xx`, `/cookielogin` | Step-up auth, rotate session, alert app owner |

Explain it this way:

> The model saw cookie/session context that does not match benign login behavior. If the endpoint accepts this request, the issue is not "cookie attack" as a label. The likely root cause is that session state is trusted from a client-controlled cookie without sufficient integrity checks, binding, expiration, or cookie flags.

Recommended fixes:

- Set `HttpOnly`, `Secure`, `SameSite=Strict` or `Lax` as appropriate.
- Use signed or server-side session tokens.
- Bind session validation to user id, expiry, and auth context.
- Rotate token after login and privilege changes.
- Add CSRF protection for state-changing requests.

### Input validation misconfiguration

| Dataset label | Reinterpreted signal | Root cause language | Demo evidence | Response |
|---|---|---|---|---|
| `SQL Injection` | SQL syntax reached a SQL-facing parameter | Query construction lacks parameterization or allowlisted input typing | `request_contains_sql_keywords`, `suspicious_request_got_2xx` | Block, alert, require prepared statements |
| `Directory Traversal` | File path breakout was accepted | File-serving path is built from user input without canonicalization | `request_contains_traversal`, `/static/download_txt/...`, 2xx | Block, alert, restrict file root |
| `XSS` | Browser-executable input reached a rendered context | Output encoding, template escaping, or CSP is missing | `request_contains_xss`, `/forum`, `/greet`, 2xx/302 | Alert or block depending on acceptance |
| `RCE` | Template/shell execution marker reached an executable context | Template rendering or command execution is exposed to user input | `request_contains_rce`, encoded path normalized, 2xx | Block immediately, isolate endpoint |
| `Log Forging` | Newline/control marker reached logs or log-facing endpoint | Log fields are not sanitized before persistence | `request_contains_log_forging`, 4xx/2xx | Alert, sanitize structured logging |

Use acceptance to separate attempted attack from actual misconfiguration:

- `suspicious_request_got_2xx`: misconfiguration likely exists.
- `suspicious_request_got_4xx`: control rejected the request; keep as blocked attempt.
- `suspicious_request_got_5xx`: handler is fragile; open reliability/security defect.

### Dependency/system misconfiguration

| Dataset label | Reinterpreted signal | Root cause language | Demo evidence | Response |
|---|---|---|---|---|
| `LOG4J` | JNDI lookup string reached headers/path/body and was accepted | Java/logging dependency or request logging path may evaluate untrusted lookup syntax | `request_contains_log4j`, `request_header_contains_log4j`, 2xx | Block, alert platform team, verify Log4J version/config |

Explain it this way:

> The request contains JNDI lookup syntax in a location commonly written to logs. A 2xx response does not prove exploitation, but it proves the service accepted and likely processed the dangerous string. The root-cause investigation is dependency posture and logging configuration, not just request blocking.

Recommended fixes:

- Verify Log4J is upgraded to a non-vulnerable line.
- Disable JNDI lookup behavior where applicable.
- Remove message lookup expansion from logging configuration.
- Block `${jndi:` patterns at gateway/WAF while patching.
- Confirm egress restrictions prevent LDAP/RMI callback traffic.

## Root-Cause Explanation Rules

Turn model output into root-cause language with this decision table:

| Condition | Alert title | Root-cause explanation |
|---|---|---|
| `predicted_attack_type=SQL Injection` and `suspicious_request_got_2xx` | SQL input validation misconfiguration | SQL-shaped input was accepted by a SQL-facing endpoint; parameterization or input typing is missing. |
| `predicted_attack_type=Directory Traversal` and `suspicious_request_got_2xx` | File path validation misconfiguration | A path breakout sequence was accepted; path canonicalization and base-directory enforcement are missing. |
| `predicted_attack_type=XSS` and 2xx/302 | Output encoding/session exposure risk | Script-capable input reached a rendered or redirecting flow; escaping, CSP, or cookie protections may be insufficient. |
| `predicted_attack_type=RCE` and `suspicious_request_got_2xx` | Unsafe execution design | Template or command-execution markers were accepted; untrusted input may reach an interpreter. |
| `predicted_attack_type=LOG4J` and `request_header_contains_log4j` | Dependency/logging misconfiguration | JNDI lookup syntax was accepted in a logged surface; dependency version and logging config need verification. |
| `predicted_attack_type=Cookie Injection` | Session integrity misconfiguration | Cookie/session context differs from normal login traffic; validate signing, binding, expiry, and cookie flags. |
| `predicted_attack_type=Log Forging` | Log integrity misconfiguration | Log-control characters were supplied; structured logging and newline sanitization are needed. |
| any suspicious request with 4xx | Control worked | Keep as blocked abuse telemetry, not a confirmed misconfiguration. |
| any suspicious request with 5xx | Unsafe failure mode | Open a defect for crash-prone validation/error handling. |

## Zero Trust Response Strategy

Default policy:

| Risk | Trigger | Action | Ticket |
|---|---|---|---|
| Critical | RCE, SQL Injection, LOG4J with 2xx | Block request, quarantine token/session, page service owner | Required fix before suppression |
| High | Directory Traversal, Cookie Injection, XSS with 2xx | Block or step-up auth, alert owner | Fix validation/session control |
| Medium | Suspicious request got 4xx | Log and aggregate | Tune controls if volume spikes |
| Medium/High | Suspicious request got 5xx | Alert reliability + security | Fix unsafe error path |

Response phrasing:

```text
Block: deny the current request because it violates endpoint-specific expected behavior.
Alert: notify SOC and service owner with endpoint, evidence features, and model score.
Recommend fix: create a root-cause ticket mapped to config/code owner.
Verify: replay a benign request and a blocked payload after remediation.
```

## Demo Scenarios

### Scenario 1: SQL accepted by order endpoint

Source row example:

```text
endpoint_key: GET 127.0.0.1:5000 /orders/get/country
status_code: 200
y_score: 0.311
nearest_benign_similarity: 0.689
predicted_attack_type: SQL Injection
security_finding: possible_sql_injection_exposure
explanation: signals=SQL keywords, response accepted with 2xx, suspicious request accepted
```

SOC alert:

```text
CRITICAL - Input validation misconfiguration

/orders/get/country accepted SQL-shaped input and returned 200.
Root cause: SQL-facing input is probably not strongly typed or parameterized.
Zero Trust action: block matching request, alert API owner, require prepared statements.
Fix: parameterized query plus allowlisted country values.
```

### Scenario 2: Traversal accepted by static file endpoint

Source row example:

```text
endpoint_key: GET 127.0.0.1:5000 /static/download_txt/../../../../../etc/passwd.txt
status_code: 200
y_score: 0.332
predicted_attack_type: Directory Traversal
security_finding: possible_path_traversal_exposure
explanation: signals=path traversal marker, response accepted with 2xx, suspicious request accepted
```

SOC alert:

```text
HIGH - File path validation misconfiguration

/static/download_txt accepted a path breakout sequence and returned 200.
Root cause: file path is likely constructed from user input without canonicalization.
Zero Trust action: block traversal tokens at gateway and restrict file serving to an allowlisted root.
Fix: resolve real path, enforce base directory, remove direct filename access where possible.
```

### Scenario 3: Log4J/JNDI marker accepted in headers

Source row example:

```text
endpoint_key: GET 127.0.0.1:5000 /forgot-password
status_code: 200
y_score: 0.405
predicted_attack_type: LOG4J
security_finding: possible_log4j_lookup_exposure
explanation: signals=Log4J/JNDI marker, Log4J/JNDI marker in request header, response accepted with 2xx, suspicious request accepted
```

SOC alert:

```text
CRITICAL - Dependency/system misconfiguration risk

The service accepted a JNDI lookup string in request headers.
Root cause to investigate: vulnerable logging dependency, unsafe logging lookup expansion, or missing gateway filtering.
Zero Trust action: block JNDI lookup patterns, check dependency inventory, and verify egress deny rules.
Fix: patch Log4J, disable lookup expansion, restrict outbound LDAP/RMI/DNS callbacks.
```

### Scenario 4: Cookie/session anomaly on login

Source row example:

```text
endpoint_key: GET 127.0.0.1:5000 /cookielogin
status_code: 200
y_score: 0.122
predicted_attack_type: Cookie Injection
security_finding: attempted_session_cookie_integrity_issue
explanation: signals=cookie/session context present, response accepted with 2xx
```

SOC alert:

```text
HIGH - Authentication/session misconfiguration

/cookielogin accepted abnormal cookie/session context.
Root cause: session state may be trusted from client-controlled cookies or lacks token binding.
Zero Trust action: rotate session, step-up authenticate the user, alert identity/app owner.
Fix: signed server-side sessions, Secure/HttpOnly/SameSite cookies, expiry and user binding checks.
```

## Demo Talk Track

1. Show `test_metrics.json`: "The model reliably separates normal endpoint behavior from security-sensitive request behavior."
2. Show `predictions/test.csv`: "The raw model output has attack-type routing keys, but the SOC sees root cause."
3. Pick one `possible_*_exposure`: "A suspicious payload returned 2xx, so this is likely misconfiguration."
4. Pick one `attack_attempt_blocked_by_client_error`: "A suspicious payload returned 4xx, so this is blocked abuse telemetry."
5. Show the Zero Trust action: "Every alert has an enforcement action and a concrete fix."

## One-Slide Summary

```text
Logs -> normalized request/response features -> endpoint-aware retrieval model
     -> attack-shaped signal -> misconfiguration root cause
     -> Zero Trust action: block, alert, recommend fix

What changed:
Attack label: "SQL Injection"
Demo output: "Input validation misconfiguration: /orders/get/country accepted SQL syntax with 200. Use parameterized query and allowlisted country input."
```

from __future__ import annotations

import argparse
import json
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import unquote_plus

if TYPE_CHECKING:
    from src.domains.api_traffic.training.model import APIRetrievalModel


APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
DEFAULT_LOG_PATH = APP_DIR / "logs" / "api_requests.jsonl"
DEFAULT_ALERT_PATH = APP_DIR / "alerts" / "alerts.jsonl"
DEFAULT_MODEL_DIR = REPO_ROOT / "experiments" / "api_traffic_d1_d2_d3_d4_improved"

SQL_RE = re.compile(
    r"("
    r"\bunion\b(?:\s+all)?\s+\bselect\b|"
    r"\bselect\b\s+.+\bfrom\b|"
    r"\b(?:drop|insert|update|delete)\b\s+\b(?:table|into|from|set)\b|"
    r"\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|"
    r"\bor\s+1\s*=\s*1\b|"
    r"(?<!\*)/\*|--"
    r")",
    re.IGNORECASE,
)
TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)
XSS_RE = re.compile(
    r"(<script|<svg|java\s*script\s*:|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|confirm\s*\()",
    re.IGNORECASE,
)
LOG4J_RE = re.compile(r"\$\{\s*jndi\s*:|jndi\s*:\s*(ldap|rmi|dns)\s*:", re.IGNORECASE)
RCE_RE = re.compile(
    r"(__import__|__mro__|__subclasses__|\$\{ifs\}|/bin/sh|/etc/passwd|cmd=|exec\s*\(|system\s*\(|[`;&|]\s*(id|cat|uname|whoami)\b)",
    re.IGNORECASE,
)
LOG_FORGING_RE = re.compile(r"(%0a|%0d|\\n|\\r|\n|\r|\u2028|\u2029)", re.IGNORECASE)


def _decode_repeated(value: str, max_rounds: int = 3) -> str:
    """Decode URL-encoded text a few times while preserving the original shape."""
    decoded = str(value or "")
    for _ in range(max_rounds):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _deobfuscate_log4j(text: str) -> str:
    """Normalize common Log4J lookup obfuscation such as ${::-j}${::-n}."""
    normalized = re.sub(r"\$\{\s*::-\s*([a-zA-Z])\s*\}", r"\1", text)
    normalized = re.sub(r"\$\{\s*lower\s*:\s*([a-zA-Z])\s*\}", r"\1", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\$\{\s*upper\s*:\s*([a-zA-Z])\s*\}", r"\1", normalized, flags=re.IGNORECASE)
    return normalized


def _canonical_request_text(event: dict[str, Any]) -> str:
    """Return original plus decoded/deobfuscated request text for detection."""
    raw = _combined_request_text(event)
    decoded = _decode_repeated(raw)
    deobfuscated = _deobfuscate_log4j(decoded)
    compact = re.sub(r"/\*.*?\*/", "", deobfuscated)
    compact = re.sub(r"\s+", "", compact)
    return " ".join([raw, decoded, deobfuscated, compact])


@lru_cache(maxsize=1)
def load_model(model_dir: str = str(DEFAULT_MODEL_DIR)) -> "APIRetrievalModel":
    from src.domains.api_traffic.training.model import APIRetrievalModel

    return APIRetrievalModel.load(Path(model_dir))


def _combined_request_text(event: dict[str, Any]) -> str:
    return " ".join(
        str(event.get(key, ""))
        for key in ("path", "path_template", "query", "user_agent", "content_type")
    )


def _regex_signal(event: dict[str, Any]) -> tuple[str | None, list[str]]:
    text = _canonical_request_text(event)
    evidence: list[str] = []
    path = str(event.get("path", ""))
    query = _decode_repeated(str(event.get("query", "")))

    if LOG4J_RE.search(text):
        evidence.append("request_contains_log4j")
        if LOG4J_RE.search(str(event.get("user_agent", ""))):
            evidence.append("request_header_contains_log4j")
        return "LOG4J", evidence

    if TRAVERSAL_RE.search(text) or re.search(r"\.\.[/\\]", text):
        evidence.append("request_contains_traversal")
        return "Directory Traversal", evidence

    if XSS_RE.search(text):
        evidence.append("request_contains_xss")
        return "XSS", evidence

    if RCE_RE.search(text):
        evidence.append("request_contains_rce")
        return "RCE", evidence

    if LOG_FORGING_RE.search(text):
        evidence.append("request_contains_log_forging")
        return "Log Forging", evidence

    if SQL_RE.search(text):
        if path.startswith("/docs/") and not re.search(r"('|--|/\*|\bor\s+\d+\s*=\s*\d+\b)", query, re.IGNORECASE):
            return None, []
        evidence.append("request_contains_sql_keywords")
        return "SQL Injection", evidence

    query = query.lower()
    has_cookie = bool(event.get("request_has_cookie"))
    if has_cookie and (
        path == "/cookielogin"
        or path.startswith("/login/")
        or "role=admin" in query
        or "next=/admin" in query
    ):
        evidence.append("request_has_cookie")
        return "Cookie Injection", evidence

    return None, evidence


def _model_path_template(path: str) -> str:
    if path.startswith("/static/download_txt/"):
        return "/static/download_txt/{num}"
    if path.startswith("/forgot-password"):
        return "/forgot-password/bookstore/api/swagger.json/{num}"
    if path.startswith("/orders/get/country"):
        return "/orders/get/country/{num}"
    return path


def _semantic_tokens(attack_type: str | None) -> str:
    mapping = {
        "SQL Injection": "attack_sql",
        "Directory Traversal": "attack_traversal",
        "XSS": "attack_xss",
        "LOG4J": "attack_log4j",
        "RCE": "attack_rce",
        "Log Forging": "attack_log_forging",
    }
    return mapping.get(attack_type or "", "")


def _event_to_model_frame(event: dict[str, Any], attack_type_hint: str | None) -> pd.DataFrame:
    import pandas as pd

    path = str(event.get("path", ""))
    method = str(event.get("method", "GET")).upper()
    status_code = int(event.get("status_code", 0) or 0)
    host = "127.0.0.1:5000"
    path_template = _model_path_template(path)
    query = str(event.get("query", ""))
    user_agent = str(event.get("user_agent", ""))
    content_type = str(event.get("content_type", ""))
    request_has_cookie = int(bool(event.get("request_has_cookie")))
    request_has_authorization = int(bool(event.get("request_has_authorization")))
    regex_attack_type, regex_evidence = _regex_signal(event)

    request_contains_sql = int("request_contains_sql_keywords" in regex_evidence)
    request_contains_traversal = int("request_contains_traversal" in regex_evidence)
    request_contains_xss = int("request_contains_xss" in regex_evidence)
    request_contains_log4j = int("request_contains_log4j" in regex_evidence)
    request_header_contains_log4j = int("request_header_contains_log4j" in regex_evidence)
    request_contains_rce = int("request_contains_rce" in regex_evidence)
    request_contains_log_forging = int("request_contains_log_forging" in regex_evidence)
    suspicious_request = any(
        [
            request_contains_sql,
            request_contains_traversal,
            request_contains_xss,
            request_contains_log4j,
            request_header_contains_log4j,
            request_contains_rce,
            request_contains_log_forging,
        ]
    )
    accepted = 200 <= status_code < 300
    rejected = 400 <= status_code < 500
    server_error = 500 <= status_code < 600

    headers = []
    if request_has_authorization:
        headers.append('"authorization": "present"')
    if content_type:
        headers.append('"content-type": "present"')

    row = {
        "event_id": event.get("event_id", f"demo:{event.get('event_timestamp', '')}"),
        "dataset_id": "live_demo",
        "source_file": "demo_misconfig/logs/api_requests.jsonl",
        "record_index": 0,
        "event_timestamp": event.get("event_timestamp"),
        "endpoint_key": f"{method} {host} {path_template}",
        "path_template": path_template,
        "method": method,
        "host": host,
        "path": path,
        "url": f"http://{host}{path}" + (f"?{query}" if query else ""),
        "query_string": query,
        "query_key_set": " ".join(sorted(part.split("=", 1)[0] for part in query.split("&") if part)),
        "request_text": f"{method} {path} {query} {user_agent}",
        "response_text": f"HTTP {status_code}",
        "combined_text": f"{method} {path} {query} {user_agent} HTTP {status_code}",
        "request_body": "",
        "body_raw": "",
        "body_normalized": "",
        "cookie": "present" if request_has_cookie else "",
        "user_agent": user_agent,
        "content_type": content_type,
        "headers_filtered": " ".join(headers),
        "request_header_names": " ".join(["authorization"] if request_has_authorization else []),
        "request_header_values": user_agent,
        "response_body": "",
        "response_header_values": "",
        "status": str(status_code),
        "status_code": status_code,
        "semantic_tokens": _semantic_tokens(attack_type_hint or regex_attack_type),
        "request_method_is_get": int(method == "GET"),
        "request_method_is_post": int(method == "POST"),
        "request_method_is_put": int(method == "PUT"),
        "request_method_is_delete": int(method == "DELETE"),
        "request_method_is_patch": int(method == "PATCH"),
        "request_method_is_options": int(method == "OPTIONS"),
        "request_method_is_uncommon": int(method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}),
        "request_host_is_ip": 1,
        "request_path_has_template_num": int("{num}" in path_template),
        "request_path_has_template_hex": int("{hex}" in path_template),
        "request_path_has_template_token": int("{token}" in path_template),
        "request_has_cookie": request_has_cookie,
        "request_has_authorization": request_has_authorization,
        "request_has_forwarded_for": 0,
        "request_has_content_type": int(bool(content_type)),
        "request_has_json_content_type": int("json" in content_type.lower()),
        "parse_status_ok": 1,
        "path_percent_decoded": int("%" in path),
        "body_percent_decoded": 0,
        "body_multiline": 0,
        "request_contains_sql_keywords": request_contains_sql,
        "request_contains_traversal": request_contains_traversal,
        "request_contains_xss": request_contains_xss,
        "request_contains_log4j": request_contains_log4j,
        "request_header_contains_log4j": request_header_contains_log4j,
        "request_contains_rce": request_contains_rce,
        "request_contains_log_forging": request_contains_log_forging,
        "response_status_is_2xx": int(accepted),
        "response_status_is_3xx": int(300 <= status_code < 400),
        "response_status_is_4xx": int(rejected),
        "response_status_is_5xx": int(server_error),
        "response_has_error_keyword": int(rejected or server_error),
        "response_is_json_like": 1,
        "response_has_body": int(bool(event.get("response_body_size", 0))),
        "response_content_type_is_json": 1,
        "response_contains_log4j": 0,
        "response_header_contains_log4j": 0,
        "response_body_contains_log4j": 0,
        "suspicious_request_got_2xx": int(suspicious_request and accepted),
        "suspicious_request_got_4xx": int(suspicious_request and rejected),
        "suspicious_request_got_5xx": int(suspicious_request and server_error),
        "sql_request_got_2xx": int(request_contains_sql and accepted),
        "traversal_request_got_2xx": int(request_contains_traversal and accepted),
        "xss_request_got_2xx": int(request_contains_xss and accepted),
        "log4j_request_got_2xx": int((request_contains_log4j or request_header_contains_log4j) and accepted),
        "rce_request_got_2xx": int(request_contains_rce and accepted),
        "log_forging_request_got_2xx": int(request_contains_log_forging and accepted),
        "auth_or_cookie_request_got_2xx": int((request_has_cookie or request_has_authorization) and accepted),
    }
    return pd.DataFrame([row])


def detect_signal(event: dict[str, Any], model_dir: Path = DEFAULT_MODEL_DIR) -> tuple[str | None, list[str]]:
    fallback_attack_type, fallback_evidence = _regex_signal(event)

    try:
        model = load_model(str(model_dir))
        model_input = _event_to_model_frame(event, fallback_attack_type)
        prediction = model.predict_dataframe(model_input).iloc[0].to_dict()
    except Exception as exc:
        event["model_error"] = str(exc)
        return fallback_attack_type, fallback_evidence

    event["model_prediction"] = {
        "model_dir": str(model_dir),
        "y_score": float(prediction["y_score"]),
        "nearest_benign_similarity": float(prediction["nearest_benign_similarity"]),
        "y_pred": int(prediction["y_pred"]),
        "predicted_attack_type": str(prediction["predicted_attack_type"]),
        "attack_similarity": float(prediction["attack_similarity"]),
        "security_finding": str(prediction["security_finding"]),
        "explanation": str(prediction["explanation"]),
    }

    if not fallback_evidence:
        return None, []

    if int(prediction["y_pred"]) != 1 or str(prediction["predicted_attack_type"]) == "Benign":
        return None, []

    return fallback_attack_type or str(prediction["predicted_attack_type"]), fallback_evidence


def _status_evidence(status_code: int) -> tuple[str, str]:
    if 200 <= status_code < 300:
        return "accepted", "suspicious_request_got_2xx"
    if 400 <= status_code < 500:
        return "blocked", "suspicious_request_got_4xx"
    if 500 <= status_code < 600:
        return "errored", "suspicious_request_got_5xx"
    return "observed", "suspicious_request_got_other"


def build_alert(event: dict[str, Any], model_dir: Path = DEFAULT_MODEL_DIR) -> dict[str, Any] | None:
    attack_type, evidence = detect_signal(event, model_dir=model_dir)
    if attack_type is None:
        return None

    status_code = int(event.get("status_code", 0))
    outcome, status_signal = _status_evidence(status_code)
    evidence.extend([f"response_status_is_{status_code // 100}xx", status_signal])

    accepted = outcome == "accepted"
    blocked = outcome == "blocked"

    if attack_type == "SQL Injection":
        title = "Input validation misconfiguration"
        root_cause = "SQL-shaped input reached an API parameter."
        fix = "Use parameterized queries and allowlisted input types."
    elif attack_type == "Directory Traversal":
        title = "File path validation misconfiguration"
        root_cause = "A path breakout sequence reached a file-serving endpoint."
        fix = "Canonicalize paths and enforce an allowlisted base directory."
    elif attack_type == "LOG4J":
        title = "Dependency/logging misconfiguration risk"
        root_cause = "JNDI lookup syntax reached a logged request surface."
        fix = "Patch Log4J, disable lookup expansion, and restrict egress."
    elif attack_type == "Cookie Injection":
        title = "Authentication/session misconfiguration"
        root_cause = "Abnormal client-controlled cookie context was accepted."
        fix = "Use signed server-side sessions and strict cookie flags."
    elif attack_type == "XSS":
        title = "Output encoding misconfiguration"
        root_cause = "Script-capable input reached a rendered or redirecting flow."
        fix = "Apply output encoding, template escaping, and CSP."
    elif attack_type == "RCE":
        title = "Unsafe execution design"
        root_cause = "Execution-shaped input reached an interpreter-facing surface."
        fix = "Remove shell/template execution from untrusted input paths."
    else:
        title = "Log integrity misconfiguration"
        root_cause = "Log-control characters reached request handling."
        fix = "Use structured logging and sanitize newline/control characters."

    if accepted and attack_type in {"SQL Injection", "LOG4J", "RCE"}:
        severity = "critical"
    elif accepted:
        severity = "high"
    elif blocked:
        severity = "medium"
        title = f"Blocked suspicious request: {attack_type}"
        root_cause = "Control rejected the suspicious request; keep as abuse telemetry."
        fix = "Aggregate by source and tune controls if volume increases."
    else:
        severity = "high"
        title = f"Unsafe handling: {attack_type}"
        root_cause = "Suspicious input produced an unsafe or unexpected response."

    path = event.get("path", "")
    summary_outcome = "accepted" if accepted else outcome

    return {
        "timestamp": event.get("event_timestamp"),
        "severity": severity,
        "title": title,
        "source_ip": event.get("client_ip"),
        "endpoint": f"{event.get('method')} {path}",
        "status_code": status_code,
        "security_finding": attack_type,
        "summary": f"{path} {summary_outcome} suspicious {attack_type} shaped input with HTTP {status_code}.",
        "root_cause": root_cause if not accepted else f"{root_cause} The endpoint returned 2xx, so this is likely a misconfiguration.",
        "evidence": evidence,
        "model": event.get("model_prediction", {"mode": "fallback_rules", "error": event.get("model_error")}),
        "zero_trust_action": "Block or step-up matching requests, alert the API owner, and open a root-cause fix ticket.",
        "recommended_fix": fix,
    }


def _print_soc_alert(alert: dict[str, Any]) -> None:
    print()
    print(f"{alert['severity'].upper()} - {alert['title']}")
    print(f"Endpoint: {alert['endpoint']}")
    print(f"Status: HTTP {alert['status_code']}")
    print(f"Finding: {alert['security_finding']}")
    print(f"Summary: {alert['summary']}")
    print(f"Root cause: {alert['root_cause']}")
    print(f"Evidence: {', '.join(alert['evidence'])}")
    model_info = alert.get("model", {})
    if "y_score" in model_info:
        print(
            "Model: "
            f"y_pred={model_info['y_pred']}, "
            f"y_score={model_info['y_score']:.3f}, "
            f"nearest_benign_similarity={model_info['nearest_benign_similarity']:.3f}, "
            f"predicted_attack_type={model_info['predicted_attack_type']}"
        )
    print(f"Zero Trust action: {alert['zero_trust_action']}")
    print(f"Recommended fix: {alert['recommended_fix']}")


def follow_logs(log_path: Path, alert_path: Path, interval_seconds: float, model_dir: Path) -> None:
    seen_lines = 0
    alert_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Watching {log_path}")
    print(f"Writing alerts to {alert_path}")

    while True:
        if not log_path.exists():
            time.sleep(interval_seconds)
            continue

        lines = log_path.read_text(encoding="utf-8").splitlines()
        for line in lines[seen_lines:]:
            event = json.loads(line)
            alert = build_alert(event, model_dir=model_dir)
            if alert is None:
                continue

            _print_soc_alert(alert)
            with alert_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(alert, sort_keys=True) + "\n")

        seen_lines = len(lines)
        time.sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local SOC alert loop for the demo API logs.")
    parser.add_argument("--log-path", type=Path, default=DEFAULT_LOG_PATH)
    parser.add_argument("--alert-path", type=Path, default=DEFAULT_ALERT_PATH)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()

    follow_logs(args.log_path, args.alert_path, args.interval, args.model_dir)


if __name__ == "__main__":
    main()

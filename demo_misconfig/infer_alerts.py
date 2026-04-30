from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_PATH = APP_DIR / "logs" / "api_requests.jsonl"
DEFAULT_ALERT_PATH = APP_DIR / "alerts" / "alerts.jsonl"

SQL_RE = re.compile(r"('|--|\bor\b|\bunion\b|\bselect\b|\bdrop\b|=)", re.IGNORECASE)
TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)
XSS_RE = re.compile(r"(<script|javascript:|onerror=|onload=)", re.IGNORECASE)
LOG4J_RE = re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE)
RCE_RE = re.compile(r"(__import__|/bin/sh|cmd=|exec\(|system\()", re.IGNORECASE)
LOG_FORGING_RE = re.compile(r"(%0a|%0d|\\n|\\r)", re.IGNORECASE)


def _combined_request_text(event: dict[str, Any]) -> str:
    return " ".join(
        str(event.get(key, ""))
        for key in ("path", "path_template", "query", "user_agent", "content_type")
    )


def detect_signal(event: dict[str, Any]) -> tuple[str | None, list[str]]:
    text = _combined_request_text(event)
    evidence: list[str] = []

    if LOG4J_RE.search(text):
        evidence.append("request_contains_log4j")
        if LOG4J_RE.search(str(event.get("user_agent", ""))):
            evidence.append("request_header_contains_log4j")
        return "LOG4J", evidence

    if TRAVERSAL_RE.search(text):
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
        evidence.append("request_contains_sql_keywords")
        return "SQL Injection", evidence

    if event.get("path") == "/cookielogin" and event.get("request_has_cookie"):
        evidence.append("request_has_cookie")
        return "Cookie Injection", evidence

    return None, evidence


def _status_evidence(status_code: int) -> tuple[str, str]:
    if 200 <= status_code < 300:
        return "accepted", "suspicious_request_got_2xx"
    if 400 <= status_code < 500:
        return "blocked", "suspicious_request_got_4xx"
    if 500 <= status_code < 600:
        return "errored", "suspicious_request_got_5xx"
    return "observed", "suspicious_request_got_other"


def build_alert(event: dict[str, Any]) -> dict[str, Any] | None:
    attack_type, evidence = detect_signal(event)
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
    print(f"Zero Trust action: {alert['zero_trust_action']}")
    print(f"Recommended fix: {alert['recommended_fix']}")


def follow_logs(log_path: Path, alert_path: Path, interval_seconds: float) -> None:
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
            alert = build_alert(event)
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
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()

    follow_logs(args.log_path, args.alert_path, args.interval)


if __name__ == "__main__":
    main()

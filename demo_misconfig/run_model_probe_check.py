from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl


APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
DEFAULT_DATASET_PATH = APP_DIR / "datasets" / "api_model_probe_cases.jsonl"
DEFAULT_MODEL_DIR = REPO_ROOT / "experiments" / "api_traffic_d1_d2_d3_d4_improved"
DEFAULT_REPORT_PATH = APP_DIR / "alerts" / "model_probe_report.csv"

STATIC_SIGNAL_COLUMNS = [
    "request_method_is_get",
    "request_method_is_post",
    "request_method_is_put",
    "request_method_is_delete",
    "request_method_is_patch",
    "request_method_is_options",
    "request_method_is_uncommon",
    "request_host_is_ip",
    "request_path_has_template_num",
    "request_path_has_template_hex",
    "request_path_has_template_token",
    "request_has_cookie",
    "request_has_authorization",
    "request_has_forwarded_for",
    "request_has_content_type",
    "request_has_json_content_type",
    "parse_status_ok",
    "path_percent_decoded",
    "body_percent_decoded",
    "body_multiline",
    "request_contains_sql_keywords",
    "request_contains_traversal",
    "request_contains_xss",
    "request_contains_log4j",
    "request_header_contains_log4j",
    "request_contains_rce",
    "request_contains_log_forging",
    "response_status_is_2xx",
    "response_status_is_3xx",
    "response_status_is_4xx",
    "response_status_is_5xx",
    "response_has_error_keyword",
    "response_is_json_like",
    "response_has_body",
    "response_content_type_is_json",
    "response_contains_log4j",
    "response_header_contains_log4j",
    "response_body_contains_log4j",
    "suspicious_request_got_2xx",
    "suspicious_request_got_4xx",
    "suspicious_request_got_5xx",
    "sql_request_got_2xx",
    "traversal_request_got_2xx",
    "xss_request_got_2xx",
    "log4j_request_got_2xx",
    "rce_request_got_2xx",
    "log_forging_request_got_2xx",
    "auth_or_cookie_request_got_2xx",
]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load model probe cases from JSONL."""
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            item.setdefault("event_id", f"{path.name}:{line_number}")
            rows.append(item)
    return rows


def _query_key_set(query: str) -> str:
    """Extract only query keys, matching the retrieval model's current input style."""
    pairs = parse_qsl(query or "", keep_blank_values=True)
    return " ".join(sorted({key for key, _ in pairs}))


def event_to_model_row(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a probe event to the dataframe row consumed by APIRetrievalModel."""
    method = str(event.get("method", "GET")).upper()
    host = "127.0.0.1:5000"
    path = str(event.get("path", ""))
    query = str(event.get("query", ""))
    path_template = str(event.get("path_template") or path)
    status_code = int(event.get("status_code", 0) or 0)
    content_type = str(event.get("content_type", ""))
    has_auth = int(bool(event.get("request_has_authorization")))
    has_cookie = int(bool(event.get("request_has_cookie")))

    row = {
        "event_id": event.get("event_id"),
        "dataset_id": "model_probe",
        "source_file": "demo_misconfig/datasets/api_model_probe_cases.jsonl",
        "record_index": 0,
        "event_timestamp": event.get("event_timestamp"),
        "endpoint_key": f"{method} {host} {path_template}",
        "path_template": path_template,
        "method": method,
        "host": host,
        "path": path,
        "url": f"http://{host}{path}" + (f"?{query}" if query else ""),
        "query_string": query,
        "query_key_set": _query_key_set(query),
        "request_text": f"{method} {path} {query} {event.get('user_agent', '')}",
        "response_text": f"HTTP {status_code}",
        "combined_text": f"{method} {path} {query} HTTP {status_code}",
        "content_type": content_type,
        "request_header_names": "authorization" if has_auth else "",
        "status_code": status_code,
        "semantic_tokens": str(event.get("semantic_tokens", "")),
        "label_binary": 1 if event.get("label_expected") == "attack" else 0,
        "attack_type": event.get("attack_type_expected", "Benign"),
    }

    defaults = {
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
        "request_has_cookie": has_cookie,
        "request_has_authorization": has_auth,
        "request_has_forwarded_for": 0,
        "request_has_content_type": int(bool(content_type)),
        "request_has_json_content_type": int("json" in content_type.lower()),
        "parse_status_ok": 1,
        "path_percent_decoded": int("%" in path),
        "body_percent_decoded": int("%" in query),
        "body_multiline": 0,
        "response_status_is_2xx": int(200 <= status_code < 300),
        "response_status_is_3xx": int(300 <= status_code < 400),
        "response_status_is_4xx": int(400 <= status_code < 500),
        "response_status_is_5xx": int(500 <= status_code < 600),
        "response_has_error_keyword": int(400 <= status_code < 600),
        "response_is_json_like": 1,
        "response_has_body": int(bool(event.get("response_body_size", 0))),
        "response_content_type_is_json": 1,
        "response_contains_log4j": 0,
        "response_header_contains_log4j": 0,
        "response_body_contains_log4j": 0,
        "suspicious_request_got_2xx": 0,
        "suspicious_request_got_4xx": 0,
        "suspicious_request_got_5xx": 0,
        "sql_request_got_2xx": 0,
        "traversal_request_got_2xx": 0,
        "xss_request_got_2xx": 0,
        "log4j_request_got_2xx": 0,
        "rce_request_got_2xx": 0,
        "log_forging_request_got_2xx": 0,
        "auth_or_cookie_request_got_2xx": int((has_cookie or has_auth) and 200 <= status_code < 300),
    }
    for column in STATIC_SIGNAL_COLUMNS:
        row[column] = defaults.get(column, 0)

    for key, value in dict(event.get("probe_flags", {})).items():
        row[key] = int(value)

    return row


def score_events(events: list[dict[str, Any]], model_dir: Path) -> list[dict[str, Any]]:
    """Score events directly with APIRetrievalModel, without infer_alerts fallback logic."""
    import pandas as pd

    from src.domains.api_traffic.training.model import APIRetrievalModel

    model = APIRetrievalModel.load(model_dir)
    frame = pd.DataFrame([event_to_model_row(event) for event in events])
    predictions = model.predict_dataframe(frame)

    rows = []
    for event, prediction in zip(events, predictions.to_dict(orient="records")):
        expected_label = event.get("label_expected")
        expected_attack = event.get("attack_type_expected", "Benign")
        y_pred = int(prediction["y_pred"])
        predicted_attack = str(prediction["predicted_attack_type"])
        binary_pass = (expected_label == "attack" and y_pred == 1) or (expected_label == "benign" and y_pred == 0)
        type_pass = expected_label == "benign" or predicted_attack == expected_attack
        strict_pass = binary_pass and type_pass

        if strict_pass:
            failure_type = ""
        elif not binary_pass and expected_label == "attack":
            failure_type = "false_negative_binary"
        elif not binary_pass:
            failure_type = "false_positive_binary"
        else:
            failure_type = "wrong_attack_type"

        rows.append(
            {
                "event_id": event.get("event_id"),
                "label_expected": expected_label,
                "attack_type_expected": expected_attack,
                "probe_goal": event.get("probe_goal", ""),
                "difficulty": event.get("difficulty", ""),
                "status_code": event.get("status_code"),
                "path": event.get("path", ""),
                "query": event.get("query", ""),
                "probe_flags": " ".join(sorted(dict(event.get("probe_flags", {})).keys())),
                "y_pred": y_pred,
                "y_score": round(float(prediction["y_score"]), 6),
                "nearest_benign_similarity": round(float(prediction["nearest_benign_similarity"]), 6),
                "predicted_attack_type": predicted_attack,
                "attack_similarity": round(float(prediction["attack_similarity"]), 6),
                "security_finding": prediction["security_finding"],
                "binary_pass": int(binary_pass),
                "type_pass": int(type_pass),
                "strict_pass": int(strict_pass),
                "failure_type": failure_type,
            }
        )
    return rows


def write_report(rows: list[dict[str, Any]], output_path: Path) -> None:
    """Write model probe report as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: list[dict[str, Any]]) -> None:
    """Print model-focused summary."""
    total = len(rows)
    print(f"Model probe strict pass: {sum(row['strict_pass'] for row in rows)}/{total}")
    print(f"Binary pass: {sum(row['binary_pass'] for row in rows)}/{total}")
    print(f"Attack-type pass: {sum(row['type_pass'] for row in rows)}/{total}")
    print(f"Failures: {dict(Counter(row['failure_type'] or 'passed' for row in rows))}")

    print()
    print("By probe goal:")
    by_goal = defaultdict(list)
    for row in rows:
        by_goal[row["probe_goal"]].append(row)
    for goal in sorted(by_goal):
        group = by_goal[goal]
        failures = Counter(row["failure_type"] or "passed" for row in group)
        print(f"- {goal}: strict={sum(row['strict_pass'] for row in group)}/{len(group)}; {dict(failures)}")

    print()
    print("Failed cases:")
    for row in rows:
        if row["strict_pass"]:
            continue
        print(
            f"- {row['event_id']} {row['attack_type_expected']} {row['difficulty']}: "
            f"{row['failure_type']}; y_pred={row['y_pred']} score={row['y_score']} "
            f"pred_type={row['predicted_attack_type']} flags=[{row['probe_flags']}]"
        )

    print()
    print("Training improvements to prioritize:")
    print("- Add payload value tokens to APIRetrievalModel._row_tokens; query_key_set alone hides attacks in parameter values.")
    print("- Train/evaluate an ablation with semantic_tokens and static attack flags removed to measure true payload generalization.")
    print("- Add hard benign negatives with attack-like words but safe context, especially docs/tutorial/search endpoints.")
    print("- Add attack-type balanced references plus type calibration; binary anomaly can pass while nearest attack type is wrong.")
    print("- Persist probe_goal metrics as a first-class eval report before promoting a model.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run direct model probes without infer_alerts gating.")
    parser.add_argument("--dataset-path", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--summary-only", action="store_true", help="Only summarize dataset composition")
    args = parser.parse_args()

    events = load_jsonl(args.dataset_path)
    if args.summary_only:
        print(f"Model probe rows: {len(events)}")
        print(f"Labels: {dict(Counter(event['label_expected'] for event in events))}")
        print(f"Attack types: {dict(sorted(Counter(event['attack_type_expected'] for event in events).items()))}")
        print(f"Probe goals: {dict(sorted(Counter(event['probe_goal'] for event in events).items()))}")
        return

    try:
        rows = score_events(events, model_dir=args.model_dir)
    except ModuleNotFoundError as exc:
        missing = exc.name or str(exc)
        raise SystemExit(
            f"Missing dependency '{missing}'. Install project requirements before scoring the model, "
            "or run with --summary-only to inspect the probe dataset."
        ) from exc

    write_report(rows, args.report_path)
    print_summary(rows)
    print()
    print(f"Report: {args.report_path}")


if __name__ == "__main__":
    main()

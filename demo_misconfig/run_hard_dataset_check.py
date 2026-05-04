from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
DEFAULT_MODEL_DIR = REPO_ROOT / "experiments" / "api_traffic_d1_d2_d3_d4_improved"
DEFAULT_DATASET_PATH = APP_DIR / "datasets" / "api_hard_cases.jsonl"
DEFAULT_REPORT_PATH = APP_DIR / "alerts" / "hard_dataset_report.csv"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load hard test cases from JSONL."""
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


def score_case(event: dict[str, Any], model_dir: Path) -> dict[str, Any]:
    """Run one event through the model-backed detector and collect verdicts."""
    from demo_misconfig.infer_alerts import build_alert, detect_signal

    item = dict(event)
    signal, evidence = detect_signal(item, model_dir=model_dir)
    alert = build_alert(item, model_dir=model_dir)
    model = item.get("model_prediction", {})
    expected_label = item.get("label_expected", "attack")
    expected_attack = item.get("attack_type_expected", "Unknown")
    model_y_pred = model.get("y_pred")
    model_attack = model.get("predicted_attack_type")

    model_detected = model_y_pred == 1
    alert_detected = alert is not None
    if expected_label == "attack":
        passed = alert_detected
        failure_type = "" if passed else "missed_attack"
    else:
        passed = not alert_detected
        failure_type = "" if passed else "false_positive_alert"

    if expected_label == "attack" and model_detected and model_attack not in {expected_attack, "Unknown", None}:
        failure_type = "wrong_attack_type" if passed else "missed_alert_wrong_model_type"

    return {
        "event_id": item.get("event_id"),
        "label_expected": expected_label,
        "attack_type_expected": expected_attack,
        "difficulty": item.get("difficulty", ""),
        "status_code": item.get("status_code"),
        "path": item.get("path", ""),
        "query": item.get("query", ""),
        "signal": signal or "",
        "evidence": " ".join(evidence),
        "alert": alert["severity"] if alert else "",
        "model_y_pred": "" if model_y_pred is None else model_y_pred,
        "model_y_score": "" if model.get("y_score") is None else round(float(model["y_score"]), 6),
        "model_attack": model_attack or "",
        "model_error": item.get("model_error", ""),
        "passed": int(passed),
        "failure_type": failure_type,
    }


def write_report(rows: list[dict[str, Any]], output_path: Path) -> None:
    """Write scored hard-test report as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "event_id",
        "label_expected",
        "attack_type_expected",
        "difficulty",
        "status_code",
        "path",
        "query",
        "signal",
        "evidence",
        "alert",
        "model_y_pred",
        "model_y_score",
        "model_attack",
        "model_error",
        "passed",
        "failure_type",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def improvement_hints(rows: list[dict[str, Any]]) -> list[str]:
    """Map hard-test failures to concrete model/data improvements."""
    failed = [row for row in rows if not row["passed"]]
    hints = []
    difficulties = " ".join(row["difficulty"] for row in failed)

    if any(token in difficulties for token in ["encoded", "double_encoded", "url_encoded"]):
        hints.append("Add recursive URL decoding features and keep decoded-depth indicators before regex/model vectorization.")
    if any(token in difficulties for token in ["split", "fragmented", "mixed_case"]):
        hints.append("Add canonicalized payload tokens that remove comments, normalize case, and join fragmented keywords.")
    if any(row["failure_type"] == "false_positive_alert" for row in failed):
        hints.append("Add hard benign negatives during training: documentation pages, security tutorials, and safe encoded filenames.")
    if any(row["attack_type_expected"] == "Cookie Injection" for row in failed):
        hints.append("Generalize cookie/session features beyond /cookielogin; model signed-cookie, auth-cookie, and endpoint context separately.")
    if any(row["attack_type_expected"] == "RCE" for row in failed):
        hints.append("Expand RCE features for shell metacharacters, ${IFS}, backticks, Jinja MRO/subclasses, and command separators.")
    if any(row["attack_type_expected"] == "LOG4J" for row in failed):
        hints.append("Add Log4J deobfuscation for nested ${::-x} fragments and encoded JNDI payloads.")
    if any(row["attack_type_expected"] == "Log Forging" for row in failed):
        hints.append("Detect double-encoded CR/LF and Unicode line separators in query, header, and user-agent fields.")

    return hints


def print_summary(rows: list[dict[str, Any]]) -> None:
    """Print compact hard-test summary."""
    total = len(rows)
    passed = sum(row["passed"] for row in rows)
    attacks = [row for row in rows if row["label_expected"] == "attack"]
    benign = [row for row in rows if row["label_expected"] == "benign"]
    attack_hits = sum(row["passed"] for row in attacks)
    benign_hits = sum(row["passed"] for row in benign)

    print(f"Hard cases: {passed}/{total} passed")
    print(f"Attack detection: {attack_hits}/{len(attacks)}")
    print(f"Benign non-alerts: {benign_hits}/{len(benign)}")
    print()
    print("By expected attack type:")

    grouped = defaultdict(list)
    for row in rows:
        grouped[row["attack_type_expected"]].append(row)

    for attack_type in sorted(grouped):
        group = grouped[attack_type]
        group_passed = sum(row["passed"] for row in group)
        failures = [row["failure_type"] for row in group if row["failure_type"]]
        print(f"- {attack_type}: {group_passed}/{len(group)} passed; failures={failures or '-'}")

    hints = improvement_hints(rows)
    if hints:
        print()
        print("Improvement directions:")
        for hint in hints:
            print(f"- {hint}")


def print_dataset_summary(events: list[dict[str, Any]]) -> None:
    """Print dataset composition without model scoring."""
    grouped = defaultdict(list)
    labels = defaultdict(int)
    for event in events:
        grouped[event.get("attack_type_expected", "Unknown")].append(event)
        labels[event.get("label_expected", "unknown")] += 1

    print(f"Hard dataset rows: {len(events)}")
    print(f"Labels: {dict(sorted(labels.items()))}")
    print("By expected attack type:")
    for attack_type in sorted(grouped):
        group = grouped[attack_type]
        attacks = sum(1 for event in group if event.get("label_expected") == "attack")
        benign = sum(1 for event in group if event.get("label_expected") == "benign")
        difficulties = ", ".join(event.get("difficulty", "") for event in group)
        print(f"- {attack_type}: {len(group)} rows ({attacks} attack, {benign} benign); {difficulties}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run hard API security cases against the demo model.")
    parser.add_argument("--dataset-path", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only summarize dataset composition; does not import model dependencies",
    )
    args = parser.parse_args()

    events = load_jsonl(args.dataset_path)
    if args.summary_only:
        print_dataset_summary(events)
        return

    try:
        rows = [score_case(event, model_dir=args.model_dir) for event in events]
    except ModuleNotFoundError as exc:
        missing = exc.name or str(exc)
        raise SystemExit(
            f"Missing dependency '{missing}'. Install project requirements before scoring the model, "
            "or run with --summary-only to inspect the hard dataset."
        ) from exc

    write_report(rows, args.report_path)
    print_summary(rows)
    print()
    print(f"Report: {args.report_path}")


if __name__ == "__main__":
    main()

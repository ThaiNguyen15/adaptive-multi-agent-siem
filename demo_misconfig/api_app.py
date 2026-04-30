from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request


APP_DIR = Path(__file__).resolve().parent
LOG_PATH = APP_DIR / "logs" / "api_requests.jsonl"

app = FastAPI(title="Misconfiguration Detection Demo API")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _append_access_log(
    request: Request,
    *,
    status_code: int,
    auth_present: bool,
    response_body_size: int = 0,
) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    event = {
        "event_timestamp": _utc_now(),
        "method": request.method,
        "host": request.url.hostname or "localhost",
        "path": request.url.path,
        "path_template": request.scope.get("route").path
        if request.scope.get("route")
        else request.url.path,
        "query": request.url.query,
        "status_code": status_code,
        "client_ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "request_has_authorization": auth_present,
        "request_has_cookie": bool(request.headers.get("cookie")),
        "content_type": request.headers.get("content-type", ""),
        "response_body_size": response_body_size,
    }

    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


@app.get("/health")
async def health(request: Request) -> dict[str, str]:
    _append_access_log(request, status_code=200, auth_present=False, response_body_size=15)
    return {"status": "ok"}


@app.get("/api/profile")
async def profile(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    auth_present = authorization is not None
    _append_access_log(request, status_code=200, auth_present=auth_present, response_body_size=43)
    return {"user": "demo-user", "role": "analyst"}


@app.get("/orders/get/country")
async def orders_by_country(request: Request, country: str = "US") -> dict[str, object]:
    # Intentional demo misconfiguration: SQL-shaped input is accepted with 200.
    _append_access_log(request, status_code=200, auth_present=False, response_body_size=58)
    return {
        "country": country,
        "orders": [
            {"id": "ord-1001", "total": 120.50},
            {"id": "ord-1002", "total": 75.00},
        ],
    }


@app.get("/static/download_txt/{file_path:path}")
async def download_txt(request: Request, file_path: str) -> dict[str, str]:
    # Intentional demo misconfiguration: path breakout is accepted with 200.
    _append_access_log(request, status_code=200, auth_present=False, response_body_size=64)
    return {"file": file_path, "content": "demo file content"}


@app.get("/api/search")
async def search(request: Request, q: str = "") -> dict[str, list[object]]:
    attack_markers = ["'", " or ", "--", "union", "select", "../", "${jndi:"]

    if any(marker in q.lower() for marker in attack_markers):
        _append_access_log(request, status_code=403, auth_present=False, response_body_size=20)
        raise HTTPException(status_code=403, detail="blocked")

    _append_access_log(request, status_code=200, auth_present=False, response_body_size=15)
    return {"results": []}


@app.get("/forgot-password")
async def forgot_password(request: Request) -> dict[str, str]:
    # This endpoint is used to demo suspicious header acceptance, for example Log4J/JNDI.
    _append_access_log(request, status_code=200, auth_present=False, response_body_size=25)
    return {"message": "email queued"}

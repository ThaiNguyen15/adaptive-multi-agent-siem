"""
API traffic domain normalizer.

Normalizes nested JSON request/response events from the ATRDF challenge into a
flat event-level schema with modality-separated text fields.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

import pandas as pd

from src.core.base_normalizer import BaseNormalizer


class APITrafficNormalizer(BaseNormalizer):
    """Normalize ATRDF API traffic events to a flat schema."""

    STANDARD_COLUMNS = [
        "event_id",
        "source_file",
        "record_index",
        "event_timestamp",
        "method",
        "host",
        "url",
        "path",
        "query_string",
        "request_body",
        "request_header_names",
        "request_header_values",
        "request_header_count",
        "response_header_names",
        "response_header_values",
        "response_header_count",
        "user_agent",
        "cookie",
        "content_type",
        "status",
        "status_code",
        "response_body",
        "request_text",
        "response_text",
        "combined_text",
        "label_known",
        "is_benign_reference",
        "label_binary",
        "attack_type",
    ]

    ATTACK_TYPE_MAP = {
        "benign": "Benign",
        "cookie injection": "Cookie Injection",
        "directory traversal": "Directory Traversal",
        "log4j": "LOG4J",
        "log forging": "Log Forging",
        "rce": "RCE",
        "sql injection": "SQL Injection",
        "xss": "XSS",
    }

    def validate_raw_schema(self, df: pd.DataFrame) -> bool:
        """Validate the normalized dataframe schema."""
        missing = set(self.STANDARD_COLUMNS) - set(df.columns)
        if missing:
            raise ValueError(f"Missing normalized columns: {missing}")
        return True

    def normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize already-flattened event dictionaries."""
        df = df.copy()
        df = df[self.STANDARD_COLUMNS]

        text_columns = [
            "source_file",
            "method",
            "host",
            "url",
            "path",
            "query_string",
            "request_body",
            "request_header_names",
            "request_header_values",
            "response_header_names",
            "response_header_values",
            "user_agent",
            "cookie",
            "content_type",
            "status",
            "response_body",
            "request_text",
            "response_text",
            "combined_text",
            "attack_type",
        ]

        df["event_id"] = df["event_id"].astype(str)
        df["record_index"] = pd.to_numeric(df["record_index"], errors="coerce").fillna(0).astype(int)
        df["event_timestamp"] = pd.to_datetime(df["event_timestamp"], errors="coerce", utc=True)

        for column in text_columns:
            df[column] = df[column].fillna("").astype(str)

        df["method"] = df["method"].replace("", "UNKNOWN").str.upper()
        df["host"] = df["host"].replace("", "unknown")
        df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce").fillna(-1).astype(int)
        df["request_header_count"] = (
            pd.to_numeric(df["request_header_count"], errors="coerce").fillna(0).astype(int)
        )
        df["response_header_count"] = (
            pd.to_numeric(df["response_header_count"], errors="coerce").fillna(0).astype(int)
        )
        df["label_known"] = pd.to_numeric(df["label_known"], errors="coerce").fillna(0).astype(int)
        df["is_benign_reference"] = (
            pd.to_numeric(df["is_benign_reference"], errors="coerce").fillna(0).astype(int)
        )
        df["label_binary"] = pd.to_numeric(df["label_binary"], errors="coerce").astype("Int64")
        df["attack_type"] = df["attack_type"].replace("", "Unknown")

        df = df.sort_values(["event_timestamp", "record_index", "event_id"]).reset_index(drop=True)
        return df

    def get_output_schema(self) -> dict:
        """Return normalized schema."""
        return {
            "event_id": "object",
            "source_file": "object",
            "record_index": "int64",
            "event_timestamp": "datetime64[ns, UTC]",
            "method": "object",
            "host": "object",
            "url": "object",
            "path": "object",
            "query_string": "object",
            "request_body": "object",
            "request_header_names": "object",
            "request_header_values": "object",
            "request_header_count": "int64",
            "response_header_names": "object",
            "response_header_values": "object",
            "response_header_count": "int64",
            "user_agent": "object",
            "cookie": "object",
            "content_type": "object",
            "status": "object",
            "status_code": "int64",
            "response_body": "object",
            "request_text": "object",
            "response_text": "object",
            "combined_text": "object",
            "label_known": "int64",
            "is_benign_reference": "int64",
            "label_binary": "Int64",
            "attack_type": "object",
        }

    def process_file(self, input_path: Path) -> pd.DataFrame:
        """Load and normalize a single JSON or 7z archive."""
        records = self._load_records(input_path)
        normalized_df = self.normalize(pd.DataFrame(records))
        self.validate_raw_schema(normalized_df)
        self.logger.info(f"Normalized {len(normalized_df)} records from {input_path.name}")
        return normalized_df

    def process_batch(self, input_dir: Path, pattern: str = "*") -> pd.DataFrame:
        """Process all supported API traffic files in a directory."""
        input_dir = Path(input_dir)
        file_paths = sorted(
            [
                path
                for path in input_dir.iterdir()
                if path.is_file() and path.suffix.lower() in {".json", ".7z"}
            ]
        )

        if not file_paths:
            self.logger.warning(f"No JSON or 7z files found in {input_dir}")
            return pd.DataFrame(columns=self.STANDARD_COLUMNS)

        dfs = [self.process_file(file_path) for file_path in file_paths]
        return pd.concat(dfs, ignore_index=True)

    def _load_records(self, input_path: Path) -> List[Dict[str, Any]]:
        """Load raw records from a JSON file or 7z archive."""
        source_name = input_path.name
        is_validation = self._is_validation_file(input_path)

        if input_path.suffix.lower() == ".json":
            with open(input_path, "r", encoding="utf-8") as file_obj:
                payload = json.load(file_obj)
        elif input_path.suffix.lower() == ".7z":
            payload = self._load_json_from_7z(input_path)
        else:
            raise ValueError(f"Unsupported file format: {input_path.suffix}")

        if not isinstance(payload, list):
            raise ValueError(f"Expected list payload in {input_path.name}")

        return [
            self._flatten_event(
                raw_event,
                source_name=source_name,
                record_index=index,
                is_validation=is_validation,
            )
            for index, raw_event in enumerate(payload)
        ]

    def _load_json_from_7z(self, archive_path: Path) -> Any:
        """Stream the first JSON file from a 7z archive."""
        list_result = subprocess.run(
            ["7z", "l", str(archive_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        json_names = [
            line.rsplit(None, 1)[-1]
            for line in list_result.stdout.splitlines()
            if line.strip().endswith(".json")
        ]
        if not json_names:
            raise ValueError(f"No JSON member found in archive {archive_path}")

        extract_result = subprocess.run(
            ["7z", "x", "-so", str(archive_path), json_names[0]],
            check=True,
            capture_output=True,
        )
        return json.loads(extract_result.stdout.decode("utf-8"))

    def _flatten_event(
        self,
        raw_event: Dict[str, Any],
        source_name: str,
        record_index: int,
        is_validation: bool,
    ) -> Dict[str, Any]:
        """Flatten a nested ATRDF request/response event."""
        request = raw_event.get("request", {}) or {}
        response = raw_event.get("response", {}) or {}
        request_headers = self._normalize_headers(request.get("headers", {}))
        response_headers = self._normalize_headers(response.get("headers", {}))

        parsed_url = urlsplit(str(request.get("url", "")))
        attack_type = self._normalize_attack_type(request.get("Attack_Tag"))

        if is_validation:
            label_binary = pd.NA
            attack_type = "Unknown"
            label_known = 0
            is_benign_reference = 0
        else:
            label_binary = 0 if attack_type == "Benign" else 1
            label_known = 1
            is_benign_reference = int(label_binary == self.config.anomaly_reference_label)

        timestamp_value = request_headers.get("date") or response_headers.get("date")

        request_header_names = " ".join(sorted(request_headers.keys()))
        request_header_values = " ".join(str(value) for value in request_headers.values())
        response_header_names = " ".join(sorted(response_headers.keys()))
        response_header_values = " ".join(str(value) for value in response_headers.values())

        request_text = " ".join(
            part
            for part in [
                str(request.get("method", "UNKNOWN")),
                request_headers.get("host", parsed_url.netloc),
                parsed_url.path,
                parsed_url.query,
                request_header_names,
                request_header_values,
                str(request.get("body", "")),
            ]
            if part
        )
        response_text = " ".join(
            part
            for part in [
                str(response.get("status", "")),
                str(response.get("status_code", -1)),
                response_headers.get("content-type", request_headers.get("content-type", "")),
                response_header_names,
                response_header_values,
                str(response.get("body", "")),
            ]
            if part
        )

        return {
            "event_id": f"{Path(source_name).stem}:{record_index}",
            "source_file": source_name,
            "record_index": record_index,
            "event_timestamp": timestamp_value,
            "method": request.get("method", "UNKNOWN"),
            "host": request_headers.get("host", parsed_url.netloc),
            "url": request.get("url", ""),
            "path": parsed_url.path,
            "query_string": parsed_url.query,
            "request_body": request.get("body", ""),
            "request_header_names": request_header_names,
            "request_header_values": request_header_values,
            "request_header_count": len(request_headers),
            "response_header_names": response_header_names,
            "response_header_values": response_header_values,
            "response_header_count": len(response_headers),
            "user_agent": request_headers.get("user-agent", ""),
            "cookie": request_headers.get("cookie", ""),
            "content_type": response_headers.get(
                "content-type",
                request_headers.get("content-type", ""),
            ),
            "status": response.get("status", ""),
            "status_code": response.get("status_code", -1),
            "response_body": response.get("body", ""),
            "request_text": request_text,
            "response_text": response_text,
            "combined_text": " ".join(part for part in [request_text, response_text] if part),
            "label_known": label_known,
            "is_benign_reference": is_benign_reference,
            "label_binary": label_binary,
            "attack_type": attack_type,
        }

    @staticmethod
    def _normalize_headers(headers: Any) -> Dict[str, str]:
        """Normalize request/response headers to lowercase string keys."""
        if not isinstance(headers, dict):
            return {}

        normalized = {}
        for key, value in headers.items():
            normalized[str(key).strip().lower()] = "" if value is None else str(value)
        return normalized

    def _normalize_attack_type(self, value: Any) -> str:
        """Map challenge-specific attack tags into a stable label space."""
        lowered = str(value or "Benign").strip().lower()
        for token, label in self.ATTACK_TYPE_MAP.items():
            if token == lowered:
                return label
        return self.ATTACK_TYPE_MAP.get(lowered, "Unknown")

    def _is_validation_file(self, input_path: Path) -> bool:
        """Detect whether a file comes from the unlabeled validation split."""
        lowered = input_path.name.lower()
        return any(marker in lowered for marker in self.config.validation_name_markers)


__all__ = ["APITrafficNormalizer"]

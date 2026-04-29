"""
API traffic domain normalizer.

Normalizes nested JSON request/response events from the ATRDF challenge into a
flat event-level schema with modality-separated text fields.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qsl, unquote, urlsplit

import pandas as pd

from src.core.base_normalizer import BaseNormalizer


class APITrafficNormalizer(BaseNormalizer):
    """Normalize ATRDF API traffic events to a flat schema."""

    STANDARD_COLUMNS = [
        "event_id",
        "dataset_id",
        "data_split",
        "source_file",
        "record_index",
        "event_timestamp",
        "method",
        "host",
        "url",
        "path_raw",
        "path",
        "path_normalized",
        "path_template",
        "query_string",
        "query_pairs",
        "query_key_set",
        "headers_filtered",
        "request_body",
        "body_raw",
        "body_normalized",
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
        "endpoint_key",
        "semantic_tokens",
        "normalization_flags",
        "parse_status",
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
            "dataset_id",
            "data_split",
            "source_file",
            "method",
            "host",
            "url",
            "path_raw",
            "path",
            "path_normalized",
            "path_template",
            "query_string",
            "query_pairs",
            "query_key_set",
            "headers_filtered",
            "request_body",
            "body_raw",
            "body_normalized",
            "request_header_names",
            "request_header_values",
            "response_header_names",
            "response_header_values",
            "user_agent",
            "cookie",
            "content_type",
            "status",
            "response_body",
            "endpoint_key",
            "semantic_tokens",
            "normalization_flags",
            "parse_status",
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
            "dataset_id": "object",
            "data_split": "object",
            "record_index": "int64",
            "event_timestamp": "datetime64[ns, UTC]",
            "method": "object",
            "host": "object",
            "url": "object",
            "path_raw": "object",
            "path": "object",
            "path_normalized": "object",
            "path_template": "object",
            "query_string": "object",
            "query_pairs": "object",
            "query_key_set": "object",
            "headers_filtered": "object",
            "request_body": "object",
            "body_raw": "object",
            "body_normalized": "object",
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
            "endpoint_key": "object",
            "semantic_tokens": "object",
            "normalization_flags": "object",
            "parse_status": "object",
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
        if input_dir.is_file():
            return self.process_file(input_dir)

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
        combined_df = pd.concat(dfs, ignore_index=True)
        duplicate_count = int(combined_df["event_id"].duplicated().sum())
        if duplicate_count:
            self.logger.warning(f"Dropping {duplicate_count} duplicate API events by event_id")
            combined_df = combined_df.drop_duplicates(subset=["event_id"], keep="first")
        return combined_df.reset_index(drop=True)

    def _load_records(self, input_path: Path) -> List[Dict[str, Any]]:
        """Load raw records from a JSON file or 7z archive."""
        source_name = input_path.name
        is_validation = self._is_validation_file(input_path)
        dataset_id = self._derive_dataset_id(input_path)
        data_split = "validation" if is_validation else "train"

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
                dataset_id=dataset_id,
                data_split=data_split,
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
        dataset_id: str,
        data_split: str,
        record_index: int,
        is_validation: bool,
    ) -> Dict[str, Any]:
        """Flatten a nested ATRDF request/response event."""
        request = raw_event.get("request", {}) or {}
        response = raw_event.get("response", {}) or {}
        request_headers = self._normalize_headers(request.get("headers", {}))
        response_headers = self._normalize_headers(response.get("headers", {}))
        filtered_headers = self._filter_headers(request_headers)

        parsed_url = urlsplit(str(request.get("url", "")))
        attack_type = self._normalize_attack_type(request.get("Attack_Tag"))
        method = str(request.get("method", "UNKNOWN") or "UNKNOWN").strip().upper()
        host = str(request_headers.get("host", parsed_url.netloc) or "unknown").strip().lower()
        path_raw = parsed_url.path or "/"
        path_normalized = self._normalize_path(path_raw)
        path_template = self._template_path(path_normalized)
        query_string = parsed_url.query
        query_pairs = self._normalize_query_pairs(query_string)
        query_key_set = sorted({key for key, _ in query_pairs})
        body_raw = "" if request.get("body") is None else str(request.get("body", ""))
        body_normalized = self._normalize_body(body_raw)
        endpoint_key = f"{method} {host} {path_template}"
        normalization_flags = self._build_normalization_flags(
            path_raw=path_raw,
            path_normalized=path_normalized,
            body_raw=body_raw,
            body_normalized=body_normalized,
            headers=request_headers,
        )
        semantic_tokens = self._build_semantic_tokens(
            method=method,
            host=host,
            path_template=path_template,
            query_pairs=query_pairs,
            query_key_set=query_key_set,
            filtered_headers=filtered_headers,
            content_type=response_headers.get("content-type", request_headers.get("content-type", "")),
            body_normalized=body_normalized,
        )
        parse_status = "ok" if method != "UNKNOWN" and path_raw else "partial"

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
                method,
                host,
                path_template,
                " ".join(f"{key}={value}" for key, value in query_pairs),
                request_header_names,
                " ".join(filtered_headers.values()),
                body_normalized,
                " ".join(semantic_tokens),
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
            "dataset_id": dataset_id,
            "data_split": data_split,
            "source_file": source_name,
            "record_index": record_index,
            "event_timestamp": timestamp_value,
            "method": method,
            "host": host,
            "url": request.get("url", ""),
            "path_raw": path_raw,
            "path": path_normalized,
            "path_normalized": path_normalized,
            "path_template": path_template,
            "query_string": query_string,
            "query_pairs": json.dumps(query_pairs, ensure_ascii=True),
            "query_key_set": " ".join(query_key_set),
            "headers_filtered": json.dumps(filtered_headers, sort_keys=True, ensure_ascii=True),
            "request_body": body_normalized,
            "body_raw": body_raw,
            "body_normalized": body_normalized,
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
            "endpoint_key": endpoint_key,
            "semantic_tokens": " ".join(semantic_tokens),
            "normalization_flags": json.dumps(normalization_flags, sort_keys=True, ensure_ascii=True),
            "parse_status": parse_status,
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

    @staticmethod
    def _filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """Keep a deterministic security-relevant header modeling view."""
        whitelist = {
            "host",
            "content-type",
            "content-length",
            "content-encoding",
            "user-agent",
            "cookie",
            "authorization",
            "x-forwarded-for",
            "x-requested-with",
            "accept",
        }
        return {key: headers[key] for key in sorted(headers) if key in whitelist}

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Percent-decode and lightly normalize a request path."""
        decoded = unquote(str(path or "/")).strip()
        decoded = re.sub(r"/{2,}", "/", decoded)
        return decoded or "/"

    @staticmethod
    def _template_path(path: str) -> str:
        """Replace high-cardinality path segments with stable placeholders."""
        segments = []
        for segment in str(path or "/").split("/"):
            if not segment:
                continue
            lowered = segment.lower()
            if re.fullmatch(r"\d+", lowered):
                segments.append("{num}")
            elif re.fullmatch(r"[0-9a-f]{8,}", lowered) or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f-]{13,}", lowered
            ):
                segments.append("{hex}")
            elif len(segment) >= 24 and re.search(r"\d", segment) and re.search(r"[a-zA-Z]", segment):
                segments.append("{token}")
            else:
                segments.append(lowered)
        return "/" + "/".join(segments) if segments else "/"

    @staticmethod
    def _normalize_query_pairs(query_string: str) -> List[List[str]]:
        """Decode query pairs and sort by key/value for deterministic modeling."""
        pairs = parse_qsl(str(query_string or ""), keep_blank_values=True)
        normalized = [[unquote(str(key)).lower().strip(), unquote(str(value)).strip()] for key, value in pairs]
        return sorted(normalized, key=lambda item: (item[0], item[1]))

    @staticmethod
    def _normalize_body(body: str) -> str:
        """Normalize body text without erasing payload evidence."""
        value = unquote(str(body or ""))
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        return value.strip()

    @staticmethod
    def _build_normalization_flags(
        path_raw: str,
        path_normalized: str,
        body_raw: str,
        body_normalized: str,
        headers: Dict[str, str],
    ) -> Dict[str, int]:
        """Describe important transformations for audit and features."""
        return {
            "path_percent_decoded": int(path_raw != path_normalized),
            "body_percent_decoded": int(body_raw != body_normalized),
            "body_multiline": int("\n" in body_normalized),
            "has_cookie": int("cookie" in headers),
            "has_authorization": int("authorization" in headers),
            "has_forwarded_for": int("x-forwarded-for" in headers),
        }

    @staticmethod
    def _build_semantic_tokens(
        method: str,
        host: str,
        path_template: str,
        query_pairs: List[List[str]],
        query_key_set: List[str],
        filtered_headers: Dict[str, str],
        content_type: str,
        body_normalized: str,
    ) -> List[str]:
        """Build endpoint-aware semantic tokens for downstream text/vector models."""
        query_text = " ".join(f"{key}={value}" for key, value in query_pairs)
        text = " ".join([path_template, query_text, body_normalized]).lower()
        host_is_ip = int(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", host)))
        tokens = [
            f"method:{method.lower()}",
            f"host_is_ip:{host_is_ip}",
            f"path_depth:{max(path_template.count('/') - 1, 0)}",
        ]
        tokens.extend(f"path:{segment}" for segment in path_template.split("/") if segment)
        tokens.extend(f"query_key:{key}" for key in query_key_set)
        for key, value in query_pairs:
            value_shape = APITrafficNormalizer._value_shape(value)
            if value_shape:
                tokens.append(f"query_value_shape:{key}:{value_shape}")
        tokens.extend(f"header:{key}" for key in sorted(filtered_headers))

        content_type_lower = str(content_type or "").lower()
        if "json" in content_type_lower:
            tokens.append("content_type:json")
        elif "xml" in content_type_lower:
            tokens.append("content_type:xml")
        elif "form" in content_type_lower:
            tokens.append("content_type:form")
        elif content_type_lower:
            tokens.append("content_type:other")

        pattern_tokens = {
            "attack_sql": (
                r"\bunion\b(?:\s+all)?\s+\bselect\b|"
                r"\bselect\b\s+.+\bfrom\b|"
                r"\b(?:drop|insert|update|delete)\b\s+\b(?:table|into|from|set)\b|"
                r"\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|"
                r"\bor\s+1\s*=\s*1\b|"
                r"(?<!\*)/\*|--"
            ),
            "attack_traversal": r"(\.\./|\.\.\\)",
            "attack_xss": r"(<script|javascript:|onerror=|onload=|alert\()",
            "attack_log4j": r"(\$\{jndi:|ldap:|rmi:|dns:)",
            "attack_rce": r"(__globals__|__builtins__|exec\(|system\(|cmd=|powershell|/bin/sh)",
            "attack_log_forging": r"(%0a|%0d|\\n|\\r|\n|\r)",
        }
        for token, pattern in pattern_tokens.items():
            if re.search(pattern, text, flags=re.IGNORECASE):
                tokens.append(token)

        return tokens

    @staticmethod
    def _value_shape(value: str) -> str:
        """Bucket query values without storing high-cardinality raw payloads."""
        value = str(value or "")
        lowered = value.lower()
        if not value:
            return "empty"
        if re.search(r"(%0a|%0d|\\n|\\r|\n|\r)", lowered):
            return "newline"
        if re.search(r"(<script|javascript:|onerror=|onload=|alert\()", lowered):
            return "script"
        if re.search(r"(\.\./|\.\.\\|%2e%2e|%252e%252e)", lowered):
            return "traversal"
        if re.search(r"(\$\{jndi:|ldap:|rmi:|dns:)", lowered):
            return "lookup"
        if re.search(r"(__globals__|__builtins__|exec\(|system\(|cmd=|powershell|/bin/sh)", lowered):
            return "command"
        if re.search(
            r"\bunion\b(?:\s+all)?\s+\bselect\b|"
            r"\bselect\b\s+.+\bfrom\b|"
            r"\b(?:drop|insert|update|delete)\b\s+\b(?:table|into|from|set)\b|"
            r"\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|"
            r"\bor\s+1\s*=\s*1\b|"
            r"(?<!\*)/\*|--",
            lowered,
        ):
            return "sql"
        if len(value) >= 32:
            return "long"
        if re.fullmatch(r"\d+", value):
            return "number"
        if re.fullmatch(r"[0-9a-fA-F-]{16,}", value):
            return "hex"
        return "plain"

    @staticmethod
    def _derive_dataset_id(input_path: Path) -> str:
        """Derive a stable dataset identifier from Cisco Ariel archive names."""
        match = re.search(r"dataset[_-]?(\d+)", input_path.name, flags=re.IGNORECASE)
        if match:
            return f"dataset_{match.group(1)}"
        return Path(input_path).stem

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

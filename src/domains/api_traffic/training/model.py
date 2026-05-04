"""
Endpoint-aware semantic retrieval model for API traffic.

The model uses hashed token vectors and cosine nearest-neighbor scoring so the
API domain can be tested without adding new dependencies.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Tuple
from urllib.parse import parse_qsl, unquote_plus

import numpy as np

if TYPE_CHECKING:
    import pandas as pd


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

RESPONSE_CONTEXT_COLUMNS = {
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
}


ATTACK_FINDING_MAP = {
    "SQL Injection": "possible_sql_injection_exposure",
    "Directory Traversal": "possible_path_traversal_exposure",
    "LOG4J": "possible_log4j_lookup_exposure",
    "Log Forging": "possible_log_integrity_issue",
    "RCE": "possible_remote_code_execution_exposure",
    "XSS": "possible_xss_exposure",
    "Cookie Injection": "possible_session_cookie_integrity_issue",
}


SECURITY_SIGNAL_WEIGHTS = {
    "request_contains_sql_keywords": 6,
    "request_contains_traversal": 6,
    "request_contains_xss": 6,
    "request_contains_log4j": 6,
    "request_header_contains_log4j": 6,
    "request_contains_rce": 6,
    "request_contains_log_forging": 8,
    "sql_request_got_2xx": 3,
    "traversal_request_got_2xx": 3,
    "xss_request_got_2xx": 3,
    "log4j_request_got_2xx": 3,
    "rce_request_got_2xx": 3,
    "log_forging_request_got_2xx": 3,
}


SEMANTIC_SIGNAL_WEIGHTS = {
    "attack_sql": 10,
    "attack_log_forging": 10,
    "attack_traversal": 8,
    "attack_xss": 8,
    "attack_log4j": 8,
    "attack_rce": 8,
}


PAYLOAD_TOKEN_COLUMNS = [
    "path",
    "url",
    "query_string",
    "request_body",
    "body_raw",
    "body_normalized",
    "request_header_values",
    "headers_filtered",
    "user_agent",
]

PAYLOAD_FAMILY_PATTERNS = {
    "payload_sql": re.compile(
        r"(?:\bunion\b\s+\bselect\b|\bselect\b.+\bfrom\b|\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|\bor\b\s+1\s*=\s*1|--|/\*)",
        re.IGNORECASE,
    ),
    "payload_traversal": re.compile(r"(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|windows\\win\.ini)", re.IGNORECASE),
    "payload_xss": re.compile(
        r"(?:<script|<svg|java\s*script\s*:|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|confirm\s*\()",
        re.IGNORECASE,
    ),
    "payload_log4j": re.compile(r"(?:\$\{\s*jndi\s*:|jndi\s*:\s*(?:ldap|rmi|dns)\s*:)", re.IGNORECASE),
    "payload_rce": re.compile(
        r"(?:__globals__|__builtins__|__mro__|__subclasses__|\$\{ifs\}|/bin/sh|/etc/passwd|cmd=|powershell|exec\s*\(|system\s*\(|[`;&|]\s*(?:id|cat|uname|whoami)\b)",
        re.IGNORECASE,
    ),
    "payload_log_forging": re.compile(r"(?:%0a|%0d|\\n|\\r|\n|\r|\u2028|\u2029)", re.IGNORECASE),
}

PAYLOAD_FAMILY_WEIGHTS = {
    "payload_sql": 8,
    "payload_traversal": 8,
    "payload_xss": 8,
    "payload_log4j": 8,
    "payload_rce": 8,
    "payload_log_forging": 8,
}


@dataclass
class APIRetrievalModel:
    """Hashed-vector endpoint-aware retrieval model."""

    dimension: int = 512
    threshold: float = 0.5
    benign_vectors: np.ndarray = field(default_factory=lambda: np.zeros((0, 512), dtype=np.float32))
    benign_endpoint_keys: List[str] = field(default_factory=list)
    attack_vectors: np.ndarray = field(default_factory=lambda: np.zeros((0, 512), dtype=np.float32))
    attack_types: List[str] = field(default_factory=list)
    attack_endpoint_keys: List[str] = field(default_factory=list)
    use_response_context: bool = False

    def fit(
        self,
        train_df: pd.DataFrame,
        max_benign_refs: int = 20000,
        max_attack_refs: int = 20000,
        random_seed: int = 42,
        reference_sampling: str = "balanced",
    ) -> None:
        """Build benign and attack reference indexes from the training split."""
        import pandas as pd

        labeled = train_df[pd.to_numeric(train_df["label_known"], errors="coerce").fillna(0).astype(int) == 1]
        benign_df = labeled[pd.to_numeric(labeled["label_binary"], errors="coerce").fillna(1).astype(int) == 0]
        attack_df = labeled[pd.to_numeric(labeled["label_binary"], errors="coerce").fillna(0).astype(int) == 1]

        if reference_sampling == "balanced":
            benign_df = self._sample_balanced(benign_df, max_benign_refs, "endpoint_key", random_seed)
            attack_df = self._sample_balanced(attack_df, max_attack_refs, "attack_type", random_seed + 1)
        elif reference_sampling == "random":
            benign_df = self._sample_rows(benign_df, max_benign_refs, random_seed)
            attack_df = self._sample_rows(attack_df, max_attack_refs, random_seed + 1)
        else:
            raise ValueError("reference_sampling must be 'balanced' or 'random'")

        self.benign_vectors = self.vectorize(benign_df)
        self.benign_endpoint_keys = benign_df["endpoint_key"].fillna("").astype(str).tolist()

        self.attack_vectors = self.vectorize(attack_df)
        self.attack_types = attack_df["attack_type"].fillna("Unknown").astype(str).tolist()
        self.attack_endpoint_keys = attack_df["endpoint_key"].fillna("").astype(str).tolist()

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score rows and return predictions with thesis-friendly explanations."""
        import pandas as pd

        vectors = self.vectorize(df)
        anomaly_scores, nearest_benign_similarity = self._score_against_benign(
            vectors=vectors,
            endpoint_keys=df["endpoint_key"].fillna("").astype(str).tolist(),
        )
        predicted_binary = (anomaly_scores >= self.threshold).astype(int)
        predicted_attack_type, attack_similarity = self._predict_attack_type(
            vectors=vectors,
            predicted_binary=predicted_binary,
        )

        predictions = self._metadata_frame(df)
        predictions["y_score"] = anomaly_scores
        predictions["nearest_benign_similarity"] = nearest_benign_similarity
        predictions["y_pred"] = predicted_binary
        predictions["predicted_attack_type"] = predicted_attack_type
        predictions["attack_similarity"] = attack_similarity
        predictions["security_finding"] = [
            self._security_finding(row, attack_type, is_anomaly)
            for (_, row), attack_type, is_anomaly in zip(df.iterrows(), predicted_attack_type, predicted_binary)
        ]
        predictions["explanation"] = [
            self._explain(row, score, similarity, attack_type, finding, is_anomaly)
            for (_, row), score, similarity, attack_type, finding, is_anomaly in zip(
                df.iterrows(),
                anomaly_scores,
                nearest_benign_similarity,
                predicted_attack_type,
                predictions["security_finding"],
                predicted_binary,
            )
        ]

        if "label_binary" in df.columns:
            predictions["y_true"] = pd.to_numeric(df["label_binary"], errors="coerce").astype("Int64")
        if "attack_type" in df.columns:
            predictions["attack_type_true"] = df["attack_type"].fillna("Unknown").astype(str).to_numpy()

        return predictions

    def vectorize(self, df: pd.DataFrame) -> np.ndarray:
        """Convert API semantic/static fields to normalized hashed vectors."""
        matrix = np.zeros((len(df), self.dimension), dtype=np.float32)
        if df.empty:
            return matrix

        for row_idx, (_, row) in enumerate(df.iterrows()):
            for token in self._row_tokens(row):
                index = self._hash_token(token) % self.dimension
                matrix[row_idx, index] += 1.0

        norms = np.linalg.norm(matrix, axis=1)
        norms[norms == 0.0] = 1.0
        return matrix / norms[:, None]

    def save(self, output_dir: Path) -> None:
        """Persist model arrays and metadata."""
        output_dir.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            output_dir / "retrieval_model.npz",
            benign_vectors=self.benign_vectors,
            attack_vectors=self.attack_vectors,
        )
        with open(output_dir / "retrieval_model_meta.json", "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "dimension": self.dimension,
                    "threshold": self.threshold,
                    "benign_endpoint_keys": self.benign_endpoint_keys,
                    "attack_types": self.attack_types,
                    "attack_endpoint_keys": self.attack_endpoint_keys,
                    "use_response_context": self.use_response_context,
                },
                handle,
                indent=2,
            )

    @classmethod
    def load(cls, model_dir: Path) -> "APIRetrievalModel":
        """Load a persisted retrieval model."""
        arrays = np.load(model_dir / "retrieval_model.npz")
        with open(model_dir / "retrieval_model_meta.json", "r", encoding="utf-8") as handle:
            meta = json.load(handle)
        return cls(
            dimension=int(meta["dimension"]),
            threshold=float(meta["threshold"]),
            benign_vectors=arrays["benign_vectors"],
            benign_endpoint_keys=list(meta["benign_endpoint_keys"]),
            attack_vectors=arrays["attack_vectors"],
            attack_types=list(meta["attack_types"]),
            attack_endpoint_keys=list(meta["attack_endpoint_keys"]),
            use_response_context=bool(meta.get("use_response_context", False)),
        )

    def _score_against_benign(
        self,
        vectors: np.ndarray,
        endpoint_keys: List[str],
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Score anomaly as distance from nearest benign endpoint/global neighbor."""
        if len(self.benign_vectors) == 0:
            return np.ones(len(vectors), dtype=float), np.zeros(len(vectors), dtype=float)

        endpoint_to_indices: Dict[str, List[int]] = {}
        for index, endpoint_key in enumerate(self.benign_endpoint_keys):
            endpoint_to_indices.setdefault(endpoint_key, []).append(index)

        nearest_similarity = np.zeros(len(vectors), dtype=float)
        for row_idx, endpoint_key in enumerate(endpoint_keys):
            candidate_indices = endpoint_to_indices.get(endpoint_key)
            candidates = self.benign_vectors[candidate_indices] if candidate_indices else self.benign_vectors
            similarities = candidates @ vectors[row_idx]
            nearest_similarity[row_idx] = float(similarities.max()) if len(similarities) else 0.0

        anomaly_scores = np.clip(1.0 - nearest_similarity, 0.0, 1.0)
        return anomaly_scores, nearest_similarity

    def _predict_attack_type(
        self,
        vectors: np.ndarray,
        predicted_binary: np.ndarray,
    ) -> Tuple[List[str], np.ndarray]:
        """Predict attack type by weighted voting over nearest malicious references."""
        if len(self.attack_vectors) == 0:
            return ["Unknown" if value else "Benign" for value in predicted_binary], np.zeros(len(vectors))

        voted_types: List[str] = ["Benign"] * len(vectors)
        voted_scores = np.zeros(len(vectors), dtype=float)
        batch_size = 4096
        attack_vectors_t = self.attack_vectors.T
        top_k = min(15, len(self.attack_vectors))
        for start in range(0, len(vectors), batch_size):
            end = min(start + batch_size, len(vectors))
            similarities = vectors[start:end] @ attack_vectors_t
            if top_k == 1:
                top_indices = similarities.argmax(axis=1)[:, None]
            else:
                top_indices = np.argpartition(similarities, -top_k, axis=1)[:, -top_k:]

            for local_idx, candidate_indices in enumerate(top_indices):
                row_idx = start + local_idx
                if not predicted_binary[row_idx]:
                    continue

                type_scores: Dict[str, float] = {}
                for candidate_index in candidate_indices:
                    attack_type = self.attack_types[int(candidate_index)]
                    score = float(similarities[local_idx, candidate_index])
                    type_scores[attack_type] = type_scores.get(attack_type, 0.0) + max(score, 0.0)

                if not type_scores:
                    voted_types[row_idx] = "Unknown"
                    voted_scores[row_idx] = 0.0
                    continue

                best_type, best_score = max(type_scores.items(), key=lambda item: item[1])
                voted_types[row_idx] = best_type
                voted_scores[row_idx] = best_score

        return voted_types, voted_scores

    def _row_tokens(self, row: pd.Series) -> List[str]:
        """Collect stable API tokens from one row."""
        tokens = []
        for column in ["method", "host", "path_template", "query_key_set", "request_header_names", "content_type"]:
            value = str(row.get(column, "") or "").strip().lower()
            if not value:
                continue
            if column in {"query_key_set", "request_header_names"}:
                tokens.extend(f"{column}:{item}" for item in value.split())
            else:
                tokens.append(f"{column}:{value}")

        tokens.extend(self._payload_context_tokens(row))
        tokens.extend(self._payload_value_tokens(row))
        if self.use_response_context:
            tokens.extend(self._response_context_tokens(row))

        for token in str(row.get("semantic_tokens", "") or "").split():
            weight = SEMANTIC_SIGNAL_WEIGHTS.get(token, 1)
            tokens.extend([token] * weight)
        for column in STATIC_SIGNAL_COLUMNS:
            if not self.use_response_context and column in RESPONSE_CONTEXT_COLUMNS:
                continue
            if int(row.get(column, 0) or 0) == 1:
                weight = SECURITY_SIGNAL_WEIGHTS.get(column, 1)
                tokens.extend([f"flag:{column}"] * weight)

        return tokens

    @staticmethod
    def _response_context_tokens(row: pd.Series) -> List[str]:
        """Encode response/outcome context for misconfiguration-oriented models."""
        tokens = []
        status_code = int(row.get("status_code", -1) or -1)
        if 200 <= status_code <= 599:
            status_family = f"{status_code // 100}xx"
            tokens.append(f"response_status_family:{status_family}")
            if 200 <= status_code < 300:
                tokens.append("outcome:accepted")
            elif 400 <= status_code < 500:
                tokens.append("outcome:blocked")
            elif 500 <= status_code < 600:
                tokens.append("outcome:errored")

        for column in [
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
        ]:
            if int(row.get(column, 0) or 0) == 1:
                tokens.extend([f"impact:{column}"] * 4)
        return tokens

    @classmethod
    def _payload_value_tokens(cls, row: pd.Series) -> List[str]:
        """Collect canonical payload value tokens, not only query/header names."""
        payload = cls._canonical_payload_text(row)
        if not payload:
            return []

        tokens: List[str] = []
        for family, pattern in PAYLOAD_FAMILY_PATTERNS.items():
            if pattern.search(payload):
                tokens.extend([f"family:{family}"] * PAYLOAD_FAMILY_WEIGHTS.get(family, 1))

        for key, value in cls._query_pairs(str(row.get("query_string", "") or "")):
            if not value:
                continue
            value_text = cls._canonical_text(value).lower()
            for token in cls._lexical_tokens(value_text):
                tokens.append(f"query_value:{key}:{token}")
                tokens.append(f"payload_token:{token}")

        for column in ["path", "request_body", "body_raw", "body_normalized", "request_header_values", "user_agent"]:
            value = cls._canonical_text(str(row.get(column, "") or "")).lower()
            for token in cls._lexical_tokens(value):
                tokens.append(f"{column}:{token}")
                tokens.append(f"payload_token:{token}")

        return tokens[:256]

    @staticmethod
    def _payload_context_tokens(row: pd.Series) -> List[str]:
        """Encode coarse context to separate docs/search/static/auth from exploit surfaces."""
        path = str(row.get("path", "") or "").lower()
        path_template = str(row.get("path_template", "") or "").lower()
        query = str(row.get("query_string", "") or "").lower()
        tokens = []
        if path.startswith("/docs/") or "/docs/" in path_template:
            tokens.append("context:docs")
        if "/search" in path or "q=" in query:
            tokens.append("context:search")
        if path.startswith("/static/"):
            tokens.append("context:static")
        if "/login" in path or "auth" in path or "profile" in path:
            tokens.append("context:auth")
        if path.startswith("/api/"):
            tokens.append("context:api")
        return tokens

    @classmethod
    def _canonical_payload_text(cls, row: pd.Series) -> str:
        values = []
        for column in PAYLOAD_TOKEN_COLUMNS:
            value = str(row.get(column, "") or "")
            if value:
                values.append(value)
        return cls._canonical_text(" ".join(values)).lower()

    @classmethod
    def _canonical_text(cls, value: str) -> str:
        decoded = str(value or "")
        for _ in range(3):
            next_value = unquote_plus(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        decoded = cls._deobfuscate_log4j(decoded)
        decoded = re.sub(r"/\*.*?\*/", " ", decoded)
        return decoded

    @staticmethod
    def _deobfuscate_log4j(value: str) -> str:
        value = re.sub(r"\$\{\s*::-\s*([a-zA-Z])\s*\}", r"\1", value)
        value = re.sub(r"\$\{\s*lower\s*:\s*([a-zA-Z])\s*\}", r"\1", value, flags=re.IGNORECASE)
        value = re.sub(r"\$\{\s*upper\s*:\s*([a-zA-Z])\s*\}", r"\1", value, flags=re.IGNORECASE)
        return value

    @staticmethod
    def _query_pairs(query: str) -> List[Tuple[str, str]]:
        try:
            return [(str(key).lower(), str(value)) for key, value in parse_qsl(query, keep_blank_values=True)]
        except ValueError:
            return []

    @staticmethod
    def _lexical_tokens(value: str) -> List[str]:
        raw_tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{1,40}|\d+|[./\\${}:;|&`<>()='\"-]+", value)
        return [token[:48] for token in raw_tokens if token.strip()][:32]

    @staticmethod
    def _hash_token(token: str) -> int:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, byteorder="little", signed=False)

    @staticmethod
    def _sample_rows(df: pd.DataFrame, max_rows: int, random_seed: int) -> pd.DataFrame:
        if max_rows <= 0 or len(df) <= max_rows:
            return df.copy()
        return df.sample(n=max_rows, random_state=random_seed).reset_index(drop=True)

    @classmethod
    def _sample_balanced(
        cls,
        df: pd.DataFrame,
        max_rows: int,
        group_column: str,
        random_seed: int,
    ) -> pd.DataFrame:
        """Sample references with coverage across attack types or endpoints."""
        import pandas as pd

        if max_rows <= 0 or len(df) <= max_rows or group_column not in df.columns:
            return df.copy()

        groups = [(name, group) for name, group in df.groupby(group_column, dropna=False)]
        if not groups:
            return df.head(0).copy()

        rng = np.random.default_rng(random_seed)
        per_group = max(max_rows // len(groups), 1)
        sampled_frames = []
        used_indices = set()

        for _, group in groups:
            take = min(len(group), per_group)
            sampled = group.sample(n=take, random_state=int(rng.integers(0, 2**31 - 1)))
            sampled_frames.append(sampled)
            used_indices.update(sampled.index.tolist())

        sampled_df = pd.concat(sampled_frames, ignore_index=False) if sampled_frames else df.head(0)
        remaining_slots = max_rows - len(sampled_df)
        if remaining_slots > 0:
            remaining = df.loc[~df.index.isin(used_indices)]
            if len(remaining) > 0:
                fill = cls._sample_rows(
                    remaining,
                    min(remaining_slots, len(remaining)),
                    int(rng.integers(0, 2**31 - 1)),
                )
                sampled_df = pd.concat([sampled_df, fill], ignore_index=False)

        return sampled_df.sample(frac=1.0, random_state=random_seed).head(max_rows).reset_index(drop=True)

    @staticmethod
    def _metadata_frame(df: pd.DataFrame) -> pd.DataFrame:
        columns = [
            "event_id",
            "dataset_id",
            "source_file",
            "record_index",
            "event_timestamp",
            "endpoint_key",
            "path_template",
            "method",
            "status_code",
        ]
        return df[[column for column in columns if column in df.columns]].copy()

    @staticmethod
    def _security_finding(row: pd.Series, attack_type: str, is_anomaly: int) -> str:
        if not is_anomaly:
            return "no_static_security_anomaly"
        if int(row.get("suspicious_request_got_4xx", 0) or 0) == 1:
            return "attack_attempt_blocked_by_client_error"
        if int(row.get("suspicious_request_got_5xx", 0) or 0) == 1:
            return "attack_attempt_caused_server_error"
        if int(row.get("suspicious_request_got_2xx", 0) or 0) == 1 and attack_type in ATTACK_FINDING_MAP:
            return ATTACK_FINDING_MAP[attack_type]
        if attack_type in ATTACK_FINDING_MAP:
            return ATTACK_FINDING_MAP[attack_type].replace("possible_", "attempted_")
        if int(row.get("request_has_authorization", 0) or 0) == 0:
            return "authorization_context_absent"
        if int(row.get("request_has_content_type", 0) or 0) == 0 and row.get("method") in {"POST", "PUT", "PATCH"}:
            return "body_content_type_absent"
        if int(row.get("request_method_is_uncommon", 0) or 0) == 1:
            return "uncommon_method_exposure"
        if int(row.get("path_percent_decoded", 0) or 0) == 1 or int(row.get("body_percent_decoded", 0) or 0) == 1:
            return "encoded_payload_requires_validation"
        return "endpoint_behavior_anomaly"

    @staticmethod
    def _explain(
        row: pd.Series,
        score: float,
        nearest_similarity: float,
        attack_type: str,
        finding: str,
        is_anomaly: int,
    ) -> str:
        if not is_anomaly:
            return f"nearest benign similarity={nearest_similarity:.3f}; treated as normal endpoint behavior"

        reasons = [f"anomaly_score={score:.3f}", f"nearest_benign_similarity={nearest_similarity:.3f}"]
        reason_columns = {
            "request_contains_sql_keywords": "SQL keywords",
            "request_contains_traversal": "path traversal marker",
            "request_contains_xss": "XSS marker",
            "request_contains_log4j": "Log4J/JNDI marker",
            "request_header_contains_log4j": "Log4J/JNDI marker in request header",
            "request_contains_rce": "RCE marker",
            "request_contains_log_forging": "log forging newline marker",
            "request_has_authorization": "authorization header present",
            "request_has_cookie": "cookie/session context present",
            "path_percent_decoded": "encoded path normalized",
            "body_percent_decoded": "encoded body normalized",
            "request_method_is_uncommon": "uncommon HTTP method",
            "response_status_is_2xx": "response accepted with 2xx",
            "response_status_is_4xx": "response rejected with 4xx",
            "response_status_is_5xx": "response caused 5xx",
            "response_has_error_keyword": "response contains error keyword",
            "response_contains_log4j": "Log4J/JNDI marker in response",
            "response_header_contains_log4j": "Log4J/JNDI marker in response header",
            "response_body_contains_log4j": "Log4J/JNDI marker in response body",
            "suspicious_request_got_2xx": "suspicious request accepted",
            "suspicious_request_got_4xx": "suspicious request blocked/rejected",
            "suspicious_request_got_5xx": "suspicious request caused server error",
        }
        active = [label for column, label in reason_columns.items() if int(row.get(column, 0) or 0) == 1]
        if active:
            reasons.append("signals=" + ", ".join(active))
        reasons.append(f"predicted_attack_type={attack_type}")
        reasons.append(f"finding={finding}")
        return "; ".join(reasons)


__all__ = ["APIRetrievalModel"]

"""
API traffic feature builder.

This implementation separates request and response modalities so the dataset can
be audited for leakage and modeled in a request-centric way by default.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

import pandas as pd

from src.core.base_feature_builder import BaseFeatureBuilder


SQL_PATTERN = re.compile(r"(?i)(?:union|select|drop|insert|update|delete|or\s+1=1|--|;)")
TRAVERSAL_PATTERN = re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e%252e)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(?i)(?:<script|javascript:|onerror=|onload=|alert\()")
LOG4J_PATTERN = re.compile(r"(?i)(?:\$\{jndi:|ldap:|rmi:|dns:)")
RCE_PATTERN = re.compile(r"(?i)(?:__globals__|__builtins__|exec\(|system\(|cmd=|powershell|/bin/sh)")
LOG_FORGING_PATTERN = re.compile(r"(?i)(?:%0a|%0d|\\n|\\r|\n|\r)")


class APITrafficFeatureBuilder(BaseFeatureBuilder):
    """Build request-centric and leakage-audit features for API traffic."""

    REQUEST_LEXICAL_FEATURES = [
        "request_method_is_get",
        "request_method_is_post",
        "request_method_is_put",
        "request_method_is_delete",
        "request_method_is_patch",
        "request_method_is_options",
        "request_method_is_uncommon",
        "request_host_is_ip",
        "request_url_length",
        "request_path_length",
        "request_path_template_length",
        "request_path_depth",
        "request_path_has_template_num",
        "request_path_has_template_hex",
        "request_path_has_template_token",
        "request_query_length",
        "request_query_param_count",
        "request_query_key_count",
        "request_body_length",
        "request_body_normalized_length",
        "request_cookie_length",
        "request_user_agent_length",
        "request_has_cookie",
        "request_has_authorization",
        "request_has_forwarded_for",
        "request_has_content_type",
        "request_has_json_content_type",
        "request_header_count_filtered",
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
        "request_sql_keyword_count",
        "request_traversal_token_count",
        "request_xss_token_count",
        "request_log4j_token_count",
        "request_rce_token_count",
        "request_newline_token_count",
        "request_percent_encoded_count",
        "request_special_char_count",
        "request_digit_count",
        "request_signal_score",
    ]

    RESPONSE_LEXICAL_FEATURES = [
        "response_body_length",
        "response_status_is_2xx",
        "response_status_is_3xx",
        "response_status_is_4xx",
        "response_status_is_5xx",
        "response_has_error_keyword",
        "response_is_json_like",
        "response_has_body",
        "response_content_type_is_json",
        "response_contains_sql_keywords",
        "response_contains_traversal",
        "response_contains_xss",
        "response_contains_log4j",
        "response_header_contains_log4j",
        "response_body_contains_log4j",
        "response_contains_rce",
        "response_contains_log_forging",
        "response_signal_score",
    ]

    TOKEN_STATS_FEATURES = [
        "request_token_count",
        "request_unique_token_count",
        "request_avg_token_length",
        "response_token_count",
        "response_unique_token_count",
        "response_avg_token_length",
        "combined_token_count",
        "combined_unique_token_count",
        "combined_avg_token_length",
    ]

    COMBINED_ONLY_FEATURES = [
        "request_response_length_ratio",
        "request_response_signal_gap",
        "model_text_length",
    ]

    REQUEST_STATIC_FEATURE_COLUMNS = [
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
    ]

    RESPONSE_STATIC_FEATURE_COLUMNS = [
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

    def get_feature_blocks(self) -> dict:
        """Expose API-specific feature blocks for downstream training."""
        return {
            "static": self.get_static_feature_list(),
            "request_static": self.REQUEST_STATIC_FEATURE_COLUMNS,
            "response_impact_static": self.RESPONSE_STATIC_FEATURE_COLUMNS,
            "endpoint": [
                "request_method_is_get",
                "request_method_is_post",
                "request_method_is_put",
                "request_method_is_delete",
                "request_method_is_patch",
                "request_method_is_options",
                "request_method_is_uncommon",
                "request_host_is_ip",
                "request_path_length",
                "request_path_template_length",
                "request_path_depth",
                "request_path_has_template_num",
                "request_path_has_template_hex",
                "request_path_has_template_token",
                "request_query_length",
                "request_query_param_count",
                "request_query_key_count",
            ],
            "headers": [
                "request_cookie_length",
                "request_user_agent_length",
                "request_has_cookie",
                "request_has_authorization",
                "request_has_forwarded_for",
                "request_has_content_type",
                "request_has_json_content_type",
                "request_header_count",
                "request_header_count_filtered",
            ],
            "body": [
                "request_body_length",
                "request_body_normalized_length",
                "path_percent_decoded",
                "body_percent_decoded",
                "body_multiline",
                "parse_status_ok",
            ],
            "semantic_signals": [
                "request_contains_sql_keywords",
                "request_contains_traversal",
                "request_contains_xss",
                "request_contains_log4j",
                "request_header_contains_log4j",
                "request_contains_rce",
                "request_contains_log_forging",
                "request_sql_keyword_count",
                "request_traversal_token_count",
                "request_xss_token_count",
                "request_log4j_token_count",
                "request_rce_token_count",
                "request_newline_token_count",
                "request_percent_encoded_count",
                "request_special_char_count",
                "request_digit_count",
                "request_signal_score",
            ],
            "response": self.RESPONSE_LEXICAL_FEATURES,
            "impact": [
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
            ],
            "token_stats": self.TOKEN_STATS_FEATURES,
            "combined": self.COMBINED_ONLY_FEATURES,
        }

    def get_static_feature_list(self) -> list:
        """Return deterministic static features without per-request dynamic metrics."""
        if getattr(self.config, "static_view", "request_response") == "request_only":
            return list(self.REQUEST_STATIC_FEATURE_COLUMNS)
        return list(self.REQUEST_STATIC_FEATURE_COLUMNS + self.RESPONSE_STATIC_FEATURE_COLUMNS)

    def get_feature_list(self) -> list:
        """Return feature names controlled by feature_mode and text_mode."""
        features = []

        if self.config.feature_mode in {"request_only", "combined"}:
            features.extend(self.REQUEST_LEXICAL_FEATURES)
        if self.config.feature_mode in {"response_only", "combined"}:
            features.extend(self.RESPONSE_LEXICAL_FEATURES)
        if self.config.text_mode in {"tokenized", "hybrid"}:
            features.extend(self.TOKEN_STATS_FEATURES)
        if self.config.feature_mode == "combined":
            features.extend(self.COMBINED_ONLY_FEATURES)

        return features

    def build_features(self, shard_df: pd.DataFrame) -> pd.DataFrame:
        """Build event-level features for a shard."""
        df = shard_df.copy()

        if not pd.api.types.is_datetime64_any_dtype(df["event_timestamp"]):
            df["event_timestamp"] = pd.to_datetime(df["event_timestamp"], errors="coerce", utc=True)

        request_text = df["request_text"].fillna("")
        response_text = df["response_text"].fillna("")
        combined_text = df["combined_text"].fillna("")
        request_scan_text = self._join_scan_columns(
            df,
            [
                "request_text",
                "url",
                "path_raw",
                "query_string",
                "request_body",
                "body_raw",
                "body_normalized",
                "headers_filtered",
                "request_header_values",
            ],
        )
        response_scan_text = self._join_scan_columns(
            df,
            [
                "response_text",
                "response_body",
                "response_header_values",
                "status",
                "content_type",
            ],
        )

        if self.config.text_mode in {"lexical", "hybrid"}:
            if self.config.feature_mode in {"request_only", "combined"}:
                self._build_request_features(df, request_text, request_scan_text)
            if self.config.feature_mode in {"response_only", "combined"}:
                self._build_response_features(df, response_text, response_scan_text)
            if self.config.feature_mode == "request_only":
                self._build_response_features(df, response_text, response_scan_text)
            if self.config.feature_mode in {"request_only", "combined"}:
                self._build_impact_features(df)

        if self.config.text_mode in {"tokenized", "hybrid"}:
            self._build_token_stats(df, request_text, response_text, combined_text)

        df["model_text"] = self._select_model_text(df)
        df["modeling_view"] = self.config.feature_mode

        if self.config.feature_mode == "combined":
            request_lengths = df["request_text"].fillna("").str.len().replace(0, 1)
            response_lengths = df["response_text"].fillna("").str.len()
            df["request_response_length_ratio"] = response_lengths / request_lengths
            df["request_response_signal_gap"] = (
                df.get("request_signal_score", 0) - df.get("response_signal_score", 0)
            )
            df["model_text_length"] = df["model_text"].fillna("").str.len()

        feature_columns = [column for column in self.get_feature_list() if column in df.columns]
        df[feature_columns] = df[feature_columns].fillna(0)

        return df

    def _build_request_features(
        self,
        df: pd.DataFrame,
        request_text: pd.Series,
        request_scan_text: pd.Series,
    ) -> None:
        """Build request-centric lexical features."""
        df["request_method_is_get"] = (df["method"] == "GET").astype(int)
        df["request_method_is_post"] = (df["method"] == "POST").astype(int)
        df["request_method_is_put"] = (df["method"] == "PUT").astype(int)
        df["request_method_is_delete"] = (df["method"] == "DELETE").astype(int)
        df["request_method_is_patch"] = (df["method"] == "PATCH").astype(int)
        df["request_method_is_options"] = (df["method"] == "OPTIONS").astype(int)
        df["request_method_is_uncommon"] = (
            ~df["method"].isin(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        ).astype(int)
        df["request_host_is_ip"] = (
            df["host"]
            .fillna("")
            .str.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")
            .fillna(False)
            .astype(int)
        )
        df["request_url_length"] = df["url"].fillna("").str.len()
        df["request_path_length"] = df["path"].fillna("").str.len()
        path_template = df.get("path_template", df["path"]).fillna("")
        df["request_path_template_length"] = path_template.str.len()
        df["request_path_depth"] = (
            df["path"].fillna("").str.count("/") - df["path"].fillna("").str.startswith("/").astype(int)
        ).clip(lower=0)
        df["request_path_has_template_num"] = path_template.str.contains("{num}", regex=False).astype(int)
        df["request_path_has_template_hex"] = path_template.str.contains("{hex}", regex=False).astype(int)
        df["request_path_has_template_token"] = path_template.str.contains("{token}", regex=False).astype(int)
        df["request_query_length"] = df["query_string"].fillna("").str.len()
        df["request_query_param_count"] = df["query_string"].fillna("").apply(
            lambda value: len(parse_qsl(value, keep_blank_values=True))
        )
        df["request_query_key_count"] = df.get("query_key_set", "").fillna("").str.split().apply(len)
        df["request_body_length"] = df["request_body"].fillna("").str.len()
        df["request_body_normalized_length"] = df.get("body_normalized", df["request_body"]).fillna("").str.len()
        df["request_cookie_length"] = df["cookie"].fillna("").str.len()
        df["request_user_agent_length"] = df["user_agent"].fillna("").str.len()
        headers_filtered = df.get("headers_filtered", "").fillna("")
        content_type = df["content_type"].fillna("")
        df["request_has_cookie"] = (df["cookie"].fillna("").str.len() > 0).astype(int)
        df["request_has_authorization"] = headers_filtered.str.contains('"authorization"', regex=False).astype(int)
        df["request_has_forwarded_for"] = headers_filtered.str.contains('"x-forwarded-for"', regex=False).astype(int)
        df["request_has_content_type"] = headers_filtered.str.contains('"content-type"', regex=False).astype(int)
        df["request_has_json_content_type"] = content_type.str.contains("json", case=False, regex=False).astype(int)
        df["request_header_count_filtered"] = headers_filtered.apply(
            lambda value: len(re.findall(r'"[^"]+":', value))
        )
        df["parse_status_ok"] = (df.get("parse_status", "ok").fillna("ok") == "ok").astype(int)
        normalization_flags = df.get("normalization_flags", "").fillna("")
        df["path_percent_decoded"] = normalization_flags.str.contains(
            '"path_percent_decoded": 1', regex=False
        ).astype(int)
        df["body_percent_decoded"] = normalization_flags.str.contains(
            '"body_percent_decoded": 1', regex=False
        ).astype(int)
        df["body_multiline"] = normalization_flags.str.contains('"body_multiline": 1', regex=False).astype(int)
        df["request_contains_sql_keywords"] = request_scan_text.str.contains(SQL_PATTERN, regex=True).astype(int)
        df["request_contains_traversal"] = request_scan_text.str.contains(TRAVERSAL_PATTERN, regex=True).astype(int)
        df["request_contains_xss"] = request_scan_text.str.contains(XSS_PATTERN, regex=True).astype(int)
        df["request_contains_log4j"] = request_scan_text.str.contains(LOG4J_PATTERN, regex=True).astype(int)
        df["request_header_contains_log4j"] = (
            df["request_header_values"].fillna("").str.contains(LOG4J_PATTERN, regex=True).astype(int)
        )
        df["request_contains_rce"] = request_scan_text.str.contains(RCE_PATTERN, regex=True).astype(int)
        df["request_contains_log_forging"] = request_text.str.contains(
            LOG_FORGING_PATTERN, regex=True
        ).astype(int)
        df["request_sql_keyword_count"] = request_scan_text.str.count(SQL_PATTERN)
        df["request_traversal_token_count"] = request_scan_text.str.count(TRAVERSAL_PATTERN)
        df["request_xss_token_count"] = request_scan_text.str.count(XSS_PATTERN)
        df["request_log4j_token_count"] = request_scan_text.str.count(LOG4J_PATTERN)
        df["request_rce_token_count"] = request_scan_text.str.count(RCE_PATTERN)
        df["request_newline_token_count"] = request_text.str.count(LOG_FORGING_PATTERN)
        df["request_percent_encoded_count"] = request_text.str.count(r"%[0-9a-fA-F]{2}")
        df["request_special_char_count"] = request_text.str.count(r"['\";<>{}\[\]\(\)$]")
        df["request_digit_count"] = request_text.str.count(r"\d")

        signal_columns = [
            "request_contains_sql_keywords",
            "request_contains_traversal",
            "request_contains_xss",
            "request_contains_log4j",
            "request_header_contains_log4j",
            "request_contains_rce",
            "request_contains_log_forging",
        ]
        df["request_signal_score"] = df[signal_columns].sum(axis=1)

    def _build_response_features(
        self,
        df: pd.DataFrame,
        response_text: pd.Series,
        response_scan_text: pd.Series,
    ) -> None:
        """Build response-only features for leakage auditing."""
        response_lower = df["response_body"].fillna("").str.lower()
        df["response_body_length"] = df["response_body"].fillna("").str.len()
        df["response_status_is_2xx"] = df["status_code"].between(200, 299).astype(int)
        df["response_status_is_3xx"] = df["status_code"].between(300, 399).astype(int)
        df["response_status_is_4xx"] = df["status_code"].between(400, 499).astype(int)
        df["response_status_is_5xx"] = df["status_code"].between(500, 599).astype(int)
        df["response_has_error_keyword"] = response_lower.str.contains(
            r"(?:error|not found|access denied|unauthorized|failed|forbidden)",
            regex=True,
        ).astype(int)
        df["response_is_json_like"] = (
            df["response_body"].fillna("").str.startswith("{")
            | df["response_body"].fillna("").str.startswith("[")
        ).astype(int)
        df["response_has_body"] = (df["response_body"].fillna("").str.len() > 0).astype(int)
        df["response_content_type_is_json"] = df["content_type"].fillna("").str.contains(
            "json",
            case=False,
            regex=False,
        ).astype(int)
        df["response_contains_sql_keywords"] = response_scan_text.str.contains(SQL_PATTERN, regex=True).astype(int)
        df["response_contains_traversal"] = response_scan_text.str.contains(
            TRAVERSAL_PATTERN, regex=True
        ).astype(int)
        df["response_contains_xss"] = response_scan_text.str.contains(XSS_PATTERN, regex=True).astype(int)
        df["response_contains_log4j"] = response_scan_text.str.contains(LOG4J_PATTERN, regex=True).astype(int)
        df["response_header_contains_log4j"] = (
            df["response_header_values"].fillna("").str.contains(LOG4J_PATTERN, regex=True).astype(int)
        )
        df["response_body_contains_log4j"] = (
            df["response_body"].fillna("").str.contains(LOG4J_PATTERN, regex=True).astype(int)
        )
        df["response_contains_rce"] = response_scan_text.str.contains(RCE_PATTERN, regex=True).astype(int)
        df["response_contains_log_forging"] = response_text.str.contains(
            LOG_FORGING_PATTERN, regex=True
        ).astype(int)

        signal_columns = [
            "response_has_error_keyword",
            "response_contains_sql_keywords",
            "response_contains_traversal",
            "response_contains_xss",
            "response_contains_log4j",
            "response_header_contains_log4j",
            "response_body_contains_log4j",
            "response_contains_rce",
            "response_contains_log_forging",
        ]
        df["response_signal_score"] = df[signal_columns].sum(axis=1)

    def _build_impact_features(self, df: pd.DataFrame) -> None:
        """Build request-response acceptance features for impact/misconfiguration analysis."""
        suspicious_columns = [
            "request_contains_sql_keywords",
            "request_contains_traversal",
            "request_contains_xss",
            "request_contains_log4j",
            "request_header_contains_log4j",
            "request_contains_rce",
            "request_contains_log_forging",
        ]
        for column in suspicious_columns:
            if column not in df.columns:
                df[column] = 0

        suspicious_request = df[suspicious_columns].sum(axis=1) > 0
        accepted = df["response_status_is_2xx"] == 1
        rejected = df["response_status_is_4xx"] == 1
        server_error = df["response_status_is_5xx"] == 1

        df["suspicious_request_got_2xx"] = (suspicious_request & accepted).astype(int)
        df["suspicious_request_got_4xx"] = (suspicious_request & rejected).astype(int)
        df["suspicious_request_got_5xx"] = (suspicious_request & server_error).astype(int)
        df["sql_request_got_2xx"] = ((df["request_contains_sql_keywords"] == 1) & accepted).astype(int)
        df["traversal_request_got_2xx"] = ((df["request_contains_traversal"] == 1) & accepted).astype(int)
        df["xss_request_got_2xx"] = ((df["request_contains_xss"] == 1) & accepted).astype(int)
        request_log4j = (df["request_contains_log4j"] == 1) | (df["request_header_contains_log4j"] == 1)
        df["log4j_request_got_2xx"] = (request_log4j & accepted).astype(int)
        df["rce_request_got_2xx"] = ((df["request_contains_rce"] == 1) & accepted).astype(int)
        df["log_forging_request_got_2xx"] = (
            (df["request_contains_log_forging"] == 1) & accepted
        ).astype(int)
        df["auth_or_cookie_request_got_2xx"] = (
            ((df["request_has_authorization"] == 1) | (df["request_has_cookie"] == 1)) & accepted
        ).astype(int)

    def _build_token_stats(
        self,
        df: pd.DataFrame,
        request_text: pd.Series,
        response_text: pd.Series,
        combined_text: pd.Series,
    ) -> None:
        """Build token statistics while leaving raw text for downstream vectorizers."""
        for prefix, series in [
            ("request", request_text),
            ("response", response_text),
            ("combined", combined_text),
        ]:
            tokens = series.str.split()
            df[f"{prefix}_token_count"] = tokens.apply(len)
            df[f"{prefix}_unique_token_count"] = tokens.apply(lambda values: len(set(values)))
            df[f"{prefix}_avg_token_length"] = tokens.apply(
                lambda values: (sum(len(value) for value in values) / len(values)) if values else 0
            )

    @staticmethod
    def _join_scan_columns(df: pd.DataFrame, columns: list) -> pd.Series:
        """Build a broad scan string for pattern indicators without changing model text."""
        parts = []
        for column in columns:
            if column in df.columns:
                parts.append(df[column].fillna("").astype(str))
        if not parts:
            return pd.Series([""] * len(df), index=df.index)
        result = parts[0]
        for part in parts[1:]:
            result = result + " " + part
        return result

    def _select_model_text(self, df: pd.DataFrame) -> pd.Series:
        """Select the text stream used by downstream vectorizers/models."""
        if self.config.feature_mode == "request_only":
            return df["request_text"].fillna("")
        if self.config.feature_mode == "response_only":
            return df["response_text"].fillna("")
        return df["combined_text"].fillna("")


__all__ = ["APITrafficFeatureBuilder"]

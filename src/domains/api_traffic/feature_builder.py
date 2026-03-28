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


SQL_PATTERN = re.compile(r"(?i)(union|select|drop|insert|update|delete|or\s+1=1|--|;)")
TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e%252e)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(?i)(<script|javascript:|onerror=|onload=|alert\()")
LOG4J_PATTERN = re.compile(r"(?i)(\$\{jndi:|ldap:|rmi:|dns:)")
RCE_PATTERN = re.compile(r"(?i)(__globals__|__builtins__|exec\(|system\(|cmd=|powershell|/bin/sh)")
LOG_FORGING_PATTERN = re.compile(r"(?i)(%0a|%0d|\\n|\\r|\n|\r)")


class APITrafficFeatureBuilder(BaseFeatureBuilder):
    """Build request-centric and leakage-audit features for API traffic."""

    REQUEST_LEXICAL_FEATURES = [
        "request_method_is_get",
        "request_method_is_post",
        "request_method_is_put",
        "request_method_is_delete",
        "request_host_is_ip",
        "request_url_length",
        "request_path_length",
        "request_path_depth",
        "request_query_length",
        "request_query_param_count",
        "request_body_length",
        "request_cookie_length",
        "request_user_agent_length",
        "request_contains_sql_keywords",
        "request_contains_traversal",
        "request_contains_xss",
        "request_contains_log4j",
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

        if self.config.text_mode in {"lexical", "hybrid"}:
            if self.config.feature_mode in {"request_only", "combined"}:
                self._build_request_features(df, request_text)
            if self.config.feature_mode in {"response_only", "combined"}:
                self._build_response_features(df, response_text)

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

    def _build_request_features(self, df: pd.DataFrame, request_text: pd.Series) -> None:
        """Build request-centric lexical features."""
        df["request_method_is_get"] = (df["method"] == "GET").astype(int)
        df["request_method_is_post"] = (df["method"] == "POST").astype(int)
        df["request_method_is_put"] = (df["method"] == "PUT").astype(int)
        df["request_method_is_delete"] = (df["method"] == "DELETE").astype(int)
        df["request_host_is_ip"] = (
            df["host"]
            .fillna("")
            .str.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")
            .fillna(False)
            .astype(int)
        )
        df["request_url_length"] = df["url"].fillna("").str.len()
        df["request_path_length"] = df["path"].fillna("").str.len()
        df["request_path_depth"] = (
            df["path"].fillna("").str.count("/") - df["path"].fillna("").str.startswith("/").astype(int)
        ).clip(lower=0)
        df["request_query_length"] = df["query_string"].fillna("").str.len()
        df["request_query_param_count"] = df["query_string"].fillna("").apply(
            lambda value: len(parse_qsl(value, keep_blank_values=True))
        )
        df["request_body_length"] = df["request_body"].fillna("").str.len()
        df["request_cookie_length"] = df["cookie"].fillna("").str.len()
        df["request_user_agent_length"] = df["user_agent"].fillna("").str.len()
        df["request_contains_sql_keywords"] = request_text.str.contains(SQL_PATTERN, regex=True).astype(int)
        df["request_contains_traversal"] = request_text.str.contains(TRAVERSAL_PATTERN, regex=True).astype(int)
        df["request_contains_xss"] = request_text.str.contains(XSS_PATTERN, regex=True).astype(int)
        df["request_contains_log4j"] = request_text.str.contains(LOG4J_PATTERN, regex=True).astype(int)
        df["request_contains_rce"] = request_text.str.contains(RCE_PATTERN, regex=True).astype(int)
        df["request_contains_log_forging"] = request_text.str.contains(
            LOG_FORGING_PATTERN, regex=True
        ).astype(int)
        df["request_sql_keyword_count"] = request_text.str.count(SQL_PATTERN)
        df["request_traversal_token_count"] = request_text.str.count(TRAVERSAL_PATTERN)
        df["request_xss_token_count"] = request_text.str.count(XSS_PATTERN)
        df["request_log4j_token_count"] = request_text.str.count(LOG4J_PATTERN)
        df["request_rce_token_count"] = request_text.str.count(RCE_PATTERN)
        df["request_newline_token_count"] = request_text.str.count(LOG_FORGING_PATTERN)
        df["request_percent_encoded_count"] = request_text.str.count(r"%[0-9a-fA-F]{2}")
        df["request_special_char_count"] = request_text.str.count(r"['\";<>{}\[\]\(\)$]")
        df["request_digit_count"] = request_text.str.count(r"\d")

        signal_columns = [
            "request_contains_sql_keywords",
            "request_contains_traversal",
            "request_contains_xss",
            "request_contains_log4j",
            "request_contains_rce",
            "request_contains_log_forging",
        ]
        df["request_signal_score"] = df[signal_columns].sum(axis=1)

    def _build_response_features(self, df: pd.DataFrame, response_text: pd.Series) -> None:
        """Build response-only features for leakage auditing."""
        response_lower = df["response_body"].fillna("").str.lower()
        df["response_body_length"] = df["response_body"].fillna("").str.len()
        df["response_status_is_2xx"] = df["status_code"].between(200, 299).astype(int)
        df["response_status_is_3xx"] = df["status_code"].between(300, 399).astype(int)
        df["response_status_is_4xx"] = df["status_code"].between(400, 499).astype(int)
        df["response_status_is_5xx"] = df["status_code"].between(500, 599).astype(int)
        df["response_has_error_keyword"] = response_lower.str.contains(
            r"(error|not found|access denied|unauthorized|failed|forbidden)",
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
        df["response_contains_sql_keywords"] = response_text.str.contains(SQL_PATTERN, regex=True).astype(int)
        df["response_contains_traversal"] = response_text.str.contains(
            TRAVERSAL_PATTERN, regex=True
        ).astype(int)
        df["response_contains_xss"] = response_text.str.contains(XSS_PATTERN, regex=True).astype(int)
        df["response_contains_log4j"] = response_text.str.contains(LOG4J_PATTERN, regex=True).astype(int)
        df["response_contains_rce"] = response_text.str.contains(RCE_PATTERN, regex=True).astype(int)
        df["response_contains_log_forging"] = response_text.str.contains(
            LOG_FORGING_PATTERN, regex=True
        ).astype(int)

        signal_columns = [
            "response_has_error_keyword",
            "response_contains_sql_keywords",
            "response_contains_traversal",
            "response_contains_xss",
            "response_contains_log4j",
            "response_contains_rce",
            "response_contains_log_forging",
        ]
        df["response_signal_score"] = df[signal_columns].sum(axis=1)

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

    def _select_model_text(self, df: pd.DataFrame) -> pd.Series:
        """Select the text stream used by downstream vectorizers/models."""
        if self.config.feature_mode == "request_only":
            return df["request_text"].fillna("")
        if self.config.feature_mode == "response_only":
            return df["response_text"].fillna("")
        return df["combined_text"].fillna("")

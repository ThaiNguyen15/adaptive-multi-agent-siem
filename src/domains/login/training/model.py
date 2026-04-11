"""
Block-based unsupervised risk model for the login domain.
"""

from dataclasses import dataclass
from pathlib import Path
import json

import numpy as np
import pandas as pd


@dataclass
class BlockProfile:
    """Robust baseline profile for one behavior block."""

    name: str
    feature_columns: list
    median: np.ndarray
    scale: np.ndarray
    weight: float


class LoginBlockRiskModel:
    """Compute risk from block-level deviation scores."""

    def __init__(self, block_profiles: list, risk_threshold: float, score_clip: float):
        """Initialize a fitted risk model."""
        self.block_profiles = block_profiles
        self.risk_threshold = float(risk_threshold)
        self.score_clip = float(score_clip)

    @staticmethod
    def _to_matrix(df: pd.DataFrame, columns: list) -> np.ndarray:
        """Convert feature columns to a clean numeric matrix."""
        return (
            df[columns]
            .apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .astype(float)
            .to_numpy()
        )

    @classmethod
    def fit(
        cls,
        train_df: pd.DataFrame,
        block_columns: dict,
        score_clip: float,
        min_scale: float,
        risk_threshold: float,
    ) -> "LoginBlockRiskModel":
        """Fit robust profiles for each feature block."""
        block_profiles = []
        equal_weight = 1.0 / max(len(block_columns), 1)

        for block_name, columns in block_columns.items():
            X = cls._to_matrix(train_df, columns)
            median = np.median(X, axis=0)
            q75 = np.percentile(X, 75, axis=0)
            q25 = np.percentile(X, 25, axis=0)
            scale = q75 - q25
            scale[scale < min_scale] = 1.0

            block_profiles.append(
                BlockProfile(
                    name=block_name,
                    feature_columns=list(columns),
                    median=median,
                    scale=scale,
                    weight=equal_weight,
                )
            )

        return cls(
            block_profiles=block_profiles,
            risk_threshold=risk_threshold,
            score_clip=score_clip,
        )

    def score_block(self, df: pd.DataFrame, block_profile: BlockProfile) -> np.ndarray:
        """Score a block by robust deviation from the train baseline."""
        X = self._to_matrix(df, block_profile.feature_columns)
        z = np.abs((X - block_profile.median) / block_profile.scale)
        z = np.clip(z, 0.0, self.score_clip)
        raw_score = z.mean(axis=1)
        return 1.0 - np.exp(-raw_score)

    def score(self, df: pd.DataFrame) -> tuple:
        """Return fused risk score and per-block component scores."""
        block_scores = {}
        fused = np.zeros(len(df), dtype=float)

        for block_profile in self.block_profiles:
            score = self.score_block(df, block_profile)
            block_scores[block_profile.name] = score
            fused += block_profile.weight * score

        fused = np.clip(fused, 0.0, 1.0)
        return fused, block_scores

    def predict(self, df: pd.DataFrame) -> tuple:
        """Return risk scores, block scores, and alert decisions."""
        risk_score, block_scores = self.score(df)
        alerts = (risk_score >= self.risk_threshold).astype(int)
        return risk_score, block_scores, alerts

    def save(self, output_dir: Path) -> None:
        """Persist model parameters as JSON + NumPy arrays."""
        output_dir.mkdir(parents=True, exist_ok=True)
        np.savez(
            output_dir / "login_block_risk_model.npz",
            risk_threshold=self.risk_threshold,
            score_clip=self.score_clip,
            **{
                f"{profile.name}_median": profile.median
                for profile in self.block_profiles
            },
            **{
                f"{profile.name}_scale": profile.scale
                for profile in self.block_profiles
            },
        )

        metadata = {
            "risk_threshold": self.risk_threshold,
            "score_clip": self.score_clip,
            "block_profiles": [
                {
                    "name": profile.name,
                    "feature_columns": profile.feature_columns,
                    "weight": profile.weight,
                }
                for profile in self.block_profiles
            ],
        }
        with open(output_dir / "login_block_risk_model.json", "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)

    @classmethod
    def load(cls, model_dir: Path) -> "LoginBlockRiskModel":
        """Load a persisted block risk model."""
        arrays = np.load(model_dir / "login_block_risk_model.npz")
        with open(model_dir / "login_block_risk_model.json", "r", encoding="utf-8") as handle:
            metadata = json.load(handle)

        block_profiles = []
        for item in metadata["block_profiles"]:
            block_profiles.append(
                BlockProfile(
                    name=item["name"],
                    feature_columns=item["feature_columns"],
                    median=arrays[f"{item['name']}_median"],
                    scale=arrays[f"{item['name']}_scale"],
                    weight=float(item["weight"]),
                )
            )

        return cls(
            block_profiles=block_profiles,
            risk_threshold=float(metadata["risk_threshold"]),
            score_clip=float(metadata["score_clip"]),
        )

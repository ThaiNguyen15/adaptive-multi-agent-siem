"""
Configuration objects for model training experiments.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import json


@dataclass
class ExperimentConfig:
    """Configuration for a single tabular experiment run."""

    processed_data_dir: Path
    experiment_dir: Path
    label_col: str
    feature_blocks: list = field(
        default_factory=lambda: [
            "temporal",
            "novelty",
            "continuity",
            "familiarity",
            "outcome_pressure",
            "diversity",
        ]
    )
    include_columns: list = field(default_factory=list)
    exclude_columns: list = field(default_factory=list)
    train_split: str = "train"
    val_split: str = "val"
    test_split: str = "test"
    learning_rate: float = 0.1
    max_epochs: int = 300
    l2_reg: float = 1e-4
    classification_threshold: float = 0.5
    tune_threshold_on_val: bool = True
    threshold_grid: list = field(
        default_factory=lambda: [0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7]
    )
    threshold_metric: str = "f1"
    ablation_mode: str = "off"  # off | per_block
    max_rows_per_split: int = 0
    standardize: bool = True
    random_seed: int = 42

    def __post_init__(self) -> None:
        """Normalize path values."""
        self.processed_data_dir = Path(self.processed_data_dir)
        self.experiment_dir = Path(self.experiment_dir)

    def ensure_dirs(self) -> None:
        """Create directories used by the experiment."""
        self.experiment_dir.mkdir(parents=True, exist_ok=True)
        (self.experiment_dir / "reports").mkdir(parents=True, exist_ok=True)
        (self.experiment_dir / "predictions").mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict:
        """Serialize config to a JSON-friendly dictionary."""
        data = asdict(self)
        data["processed_data_dir"] = str(self.processed_data_dir)
        data["experiment_dir"] = str(self.experiment_dir)
        return data

    def save(self, path: Path = None) -> Path:
        """Save config JSON to disk."""
        output_path = path or (self.experiment_dir / "config.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
        return output_path

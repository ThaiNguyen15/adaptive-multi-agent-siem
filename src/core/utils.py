"""
Shared utility functions for all domains.
"""

from pathlib import Path
import json
import yaml
import logging
from typing import Any, Dict


logger = logging.getLogger(__name__)


def ensure_dir(dirpath: Path) -> Path:
    """Ensure directory exists, create if needed.

    Args:
        dirpath: Path to ensure

    Returns:
        Pathlib Path object
    """
    dirpath = Path(dirpath)
    dirpath.mkdir(parents=True, exist_ok=True)
    return dirpath


def load_config_yaml(filepath: Path) -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        filepath: Path to YAML config file

    Returns:
        Configuration dict
    """
    with open(filepath, "r") as f:
        config = yaml.safe_load(f)
    return config


def save_config_yaml(config: Dict[str, Any], filepath: Path) -> None:
    """Save configuration to YAML file.

    Args:
        config: Configuration dict
        filepath: Path to save YAML file
    """
    ensure_dir(filepath.parent)
    with open(filepath, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def load_config_json(filepath: Path) -> Dict[str, Any]:
    """Load configuration from JSON file.

    Args:
        filepath: Path to JSON config file

    Returns:
        Configuration dict
    """
    with open(filepath, "r") as f:
        config = json.load(f)
    return config


def save_config_json(config: Dict[str, Any], filepath: Path) -> None:
    """Save configuration to JSON file.

    Args:
        config: Configuration dict
        filepath: Path to save JSON file
    """
    ensure_dir(filepath.parent)
    with open(filepath, "w") as f:
        json.dump(config, f, indent=2, default=str)


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Setup logger with console handler.

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))

    # Console handler
    chan = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    chan.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(chan)

    return logger

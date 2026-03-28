"""
Base normalizer class for schema normalization.

Each domain normalizer inherits and implements:
- raw_schema validation
- normalization logic
- output schema definition
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd
import logging


logger = logging.getLogger(__name__)


class BaseNormalizer(ABC):
    """Abstract base class for log normalization.

    Implement for each domain:
    - validate_raw_schema()
    - normalize()
    """

    def __init__(self, config):
        """Initialize with domain config.

        Args:
            config: Domain-specific configuration (inherits from BaseConfig)
        """
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")

    @abstractmethod
    def validate_raw_schema(self, df: pd.DataFrame) -> bool:
        """Validate raw data schema.

        Returns:
            True if valid, raises Exception otherwise
        """
        pass

    @abstractmethod
    def normalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize raw dataframe to standard schema.

        Must implement this to:
        - Validate input schema
        - Transform columns
        - Handle missing values
        - Convert types
        - Return normalized dataframe
        """
        pass

    @abstractmethod
    def get_output_schema(self) -> Dict[str, str]:
        """Return normalized schema (column_name -> dtype).

        Returns:
            Dict like {'timestamp': 'datetime64', 'user_id': 'string', ...}
        """
        pass

    def process_file(self, input_path: Path) -> pd.DataFrame:
        """Load, validate, and normalize single file.

        Args:
            input_path: Path to raw data file

        Returns:
            Normalized dataframe
        """
        # Load raw data
        if input_path.suffix == ".csv":
            df = pd.read_csv(input_path)
        elif input_path.suffix in [".parquet", ".pq"]:
            df = pd.read_parquet(input_path)
        else:
            raise ValueError(f"Unsupported file format: {input_path.suffix}")

        self.logger.info(f"Loaded {len(df)} records from {input_path.name}")

        # Validate
        self.validate_raw_schema(df)

        # Normalize
        normalized_df = self.normalize(df)

        self.logger.info(f"Normalized to {len(normalized_df)} records")

        return normalized_df

    def process_batch(self, input_dir: Path, pattern: str = "*.csv") -> pd.DataFrame:
        """Process all matching files in directory.

        Args:
            input_dir: Directory containing raw files
            pattern: File pattern (e.g., "*.csv")

        Returns:
            Concatenated normalized dataframe
        """
        input_dir = Path(input_dir)
        files = sorted(input_dir.glob(pattern))

        if not files:
            self.logger.warning(f"No files matching '{pattern}' in {input_dir}")
            return pd.DataFrame()

        self.logger.info(f"Processing {len(files)} files from {input_dir}")

        dfs = []
        for file_path in files:
            try:
                df = self.process_file(file_path)
                dfs.append(df)
            except Exception as e:
                self.logger.error(f"Error processing {file_path.name}: {e}")
                raise

        result = pd.concat(dfs, ignore_index=True)
        self.logger.info(f"Total records: {len(result)}")

        return result

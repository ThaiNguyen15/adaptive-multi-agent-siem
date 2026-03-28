"""
EXAMPLE: End-to-end usage of multi-domain architecture

This script demonstrates how to:
1. Process multiple domains
2. Load and inspect output data
3. Prepare data for training
"""

from pathlib import Path
import pandas as pd
from src.domains.login import LoginConfig, LoginPipeline
from src.domains.cicids2018 import CICIDS2018Config, CICIDS2018Pipeline


def example_1_process_single_domain():
    """Example 1: Process login domain end-to-end."""
    print("\n" + "=" * 60)
    print("EXAMPLE 1: Process single domain (Login)")
    print("=" * 60 + "\n")

    # Create config
    config = LoginConfig(
        raw_data_dir=Path("data/raw/login"),
        processed_data_dir=Path("data/processed/login"),
        num_shards=256,
        batch_size=10000,
    )

    # Run pipeline
    pipeline = LoginPipeline(config)
    pipeline.run(config.raw_data_dir)

    print("\n✓ Login domain processed and ready for training\n")


def example_2_process_multiple_domains():
    """Example 2: Process multiple domains in sequence."""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Process multiple domains")
    print("=" * 60 + "\n")

    domains = [
        (
            "LOGIN",
            LoginConfig(
                raw_data_dir=Path("data/raw/login"),
                processed_data_dir=Path("data/processed/login"),
            ),
            LoginPipeline,
        ),
        (
            "NETWORK",
            CICIDS2018Config(
                raw_data_dir=Path("data/raw/cicids2018"),
                processed_data_dir=Path("data/processed/cicids2018"),
            ),
            CICIDS2018Pipeline,
        ),
    ]

    for domain_name, config, PipelineClass in domains:
        print(f"\nProcessing {domain_name} domain...")
        pipeline = PipelineClass(config)
        pipeline.run(config.raw_data_dir)

    print("\n✓ All domains processed\n")


def example_3_load_training_data():
    """Example 3: Load processed data for ML training."""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Load processed data for training")
    print("=" * 60 + "\n")

    def load_split(split_dir, split_name="train"):
        """Load all shards for a specific split."""
        split_path = Path(split_dir) / split_name
        dfs = []
        for shard_file in sorted(split_path.glob("shard_*.parquet")):
            dfs.append(pd.read_parquet(shard_file))
            if len(dfs) % 50 == 0:
                print(f"  Loaded {len(dfs)} shards...")
        return pd.concat(dfs, ignore_index=True)

    # Load login data
    print("Loading login domain data...")
    login_splits_dir = Path("data/processed/login/splits")

    train_df = load_split(login_splits_dir, "train")
    val_df = load_split(login_splits_dir, "val")
    test_df = load_split(login_splits_dir, "test")

    print(f"\nLogin Domain:")
    print(f"  Train: {len(train_df):,} records, {len(train_df.columns)} features")
    print(f"  Val:   {len(val_df):,} records")
    print(f"  Test:  {len(test_df):,} records")

    # Show columns
    print(f"\nColumns ({len(train_df.columns)}):")
    for i, col in enumerate(train_df.columns[:10], 1):
        print(f"  {i}. {col}")
    if len(train_df.columns) > 10:
        print(f"  ... + {len(train_df.columns) - 10} more features")

    # Show sample data
    print(f"\nSample train data:")
    print(train_df.head(3).to_string())

    print("\n✓ Data loaded and ready for training\n")

    return train_df, val_df, test_df


def example_4_prepare_ml_dataset():
    """Example 4: Prepare features and labels for ML model."""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Prepare ML dataset")
    print("=" * 60 + "\n")

    def load_split(split_dir, split_name="train"):
        split_path = Path(split_dir) / split_name
        dfs = [pd.read_parquet(f) for f in sorted(split_path.glob("shard_*.parquet"))]
        return pd.concat(dfs, ignore_index=True)

    # Load login data
    splits_dir = Path("data/processed/login/splits")
    train_df = load_split(splits_dir, "train")
    val_df = load_split(splits_dir, "val")
    test_df = load_split(splits_dir, "test")

    # Prepare features and labels
    def prepare_dataset(df):
        # Drop non-feature columns
        drop_cols = ["timestamp", "user_id", "source_ip", "device", "location"]
        X = df.drop(columns=drop_cols)

        # Create binary labels (success=0, failure=1)
        y = (df["result"] == "failure").astype(int)

        return X, y

    X_train, y_train = prepare_dataset(train_df)
    X_val, y_val = prepare_dataset(val_df)
    X_test, y_test = prepare_dataset(test_df)

    print(f"Train set: {X_train.shape[0]:,} samples, {X_train.shape[1]} features")
    print(f"Val set:   {X_val.shape[0]:,} samples")
    print(f"Test set:  {X_test.shape[0]:,} samples")

    print(f"\nFeature types:")
    print(X_train.dtypes.value_counts().to_string())

    print(f"\nLabel distribution (train):")
    print(f"  Normal (0): {(y_train == 0).sum():,} ({100*(y_train==0).sum()/len(y_train):.1f}%)")
    print(f"  Failure (1): {(y_train == 1).sum():,} ({100*(y_train==1).sum()/len(y_train):.1f}%)")

    # Check for missing values
    missing = X_train.isnull().sum()
    if missing.sum() > 0:
        print(f"\nMissing values: {missing.sum()}")
    else:
        print(f"\n✓ No missing values")

    # Show feature statistics
    print(f"\nFeature statistics (first 5 features):")
    print(X_train.iloc[:, :5].describe().to_string())

    print("\n✓ ML dataset prepared\n")

    return X_train, y_train, X_val, y_val, X_test, y_test


def example_5_inspect_shards():
    """Example 5: Inspect individual shards for debugging."""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Inspect individual shards")
    print("=" * 60 + "\n")

    from src.core.sharding import HashSharding

    sharding = HashSharding(256, "user_id")
    shards_dir = Path("data/processed/login/shards")

    # Load a specific shard
    shard_id = 42
    shard_df = sharding.load_shard(shard_id, shards_dir)

    print(f"Shard {shard_id}:")
    print(f"  Records: {len(shard_df)}")
    print(f"  Users: {shard_df['user_id'].nunique()}")
    print(f"  Date range: {shard_df['timestamp'].min()} to {shard_df['timestamp'].max()}")

    # Show sample records
    print(f"\nSample records from shard {shard_id}:")
    print(shard_df.head(5)[["timestamp", "user_id", "source_ip", "result"]].to_string())

    print("\n✓ Shard inspection complete\n")


def example_6_verify_no_data_leakage():
    """Example 6: Verify time-based split (no temporal leakage)."""
    print("\n" + "=" * 60)
    print("EXAMPLE 6: Verify no data leakage")
    print("=" * 60 + "\n")

    def load_sample(split_name):
        """Load one sample shard from split."""
        split_dir = Path("data/processed/login/splits") / split_name
        shard_file = next(split_dir.glob("shard_*.parquet"))
        return pd.read_parquet(shard_file)

    # Load sample shards from each split
    train_sample = load_sample("train")
    val_sample = load_sample("val")
    test_sample = load_sample("test")

    # Get timestamp boundaries
    train_max = train_sample["timestamp"].max()
    val_min = val_sample["timestamp"].min()
    val_max = val_sample["timestamp"].max()
    test_min = test_sample["timestamp"].min()

    print("Time boundaries across splits:")
    print(f"  Train: ... → {train_max}")
    print(f"  Val:   {val_min} → {val_max}")
    print(f"  Test:  {test_min} → ...")

    # Verify no overlap
    assert train_max <= val_min, "Data leakage: train → val"
    assert val_max <= test_min, "Data leakage: val → test"

    print("\n✓ No temporal data leakage detected\n")


def example_7_compare_domains():
    """Example 7: Compare features across domains."""
    print("\n" + "=" * 60)
    print("EXAMPLE 7: Compare domains")
    print("=" * 60 + "\n")

    from src.domains.login import LoginFeatureBuilder, LoginConfig
    from src.domains.cicids2018 import CICIDS2018FeatureBuilder, CICIDS2018Config

    # Get feature lists
    login_config = LoginConfig()
    net_config = CICIDS2018Config()

    login_fb = LoginFeatureBuilder(login_config)
    net_fb = CICIDS2018FeatureBuilder(net_config)

    login_features = set(login_fb.get_feature_list())
    net_features = set(net_fb.get_feature_list())

    print(f"Login features: {len(login_features)}")
    print(f"  Examples: {list(sorted(login_features))[:5]}")

    print(f"\nNetwork features: {len(net_features)}")
    print(f"  Examples: {list(sorted(net_features))[:5]}")

    # Common patterns
    count_features_login = [f for f in login_features if "count" in f]
    rate_features_login = [f for f in login_features if "rate" in f]

    print(f"\nLogin domain breakdown:")
    print(f"  Count features: {len(count_features_login)}")
    print(f"  Rate features: {len(rate_features_login)}")
    print(f"  Other: {len(login_features) - len(count_features_login) - len(rate_features_login)}")

    print("\n✓ Domain comparison complete\n")


if __name__ == "__main__":
    print("\n" + "🔧 " * 20)
    print("MULTI-DOMAIN PROCESSING ARCHITECTURE - EXAMPLES")
    print("🔧 " * 20)

    # Run examples
    # example_1_process_single_domain()
    # example_2_process_multiple_domains()
    # example_3_load_training_data()
    example_4_prepare_ml_dataset()
    example_5_inspect_shards()
    example_6_verify_no_data_leakage()
    example_7_compare_domains()

    print("\n" + "✓ " * 20)
    print("ALL EXAMPLES COMPLETED")
    print("✓ " * 20 + "\n")

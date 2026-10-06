import json
import logging
from pathlib import Path
from secureshield.common.config import load_config
from secureshield.data.loader import load_raw_dataset
from secureshield.preprocessing.pipeline import MalMemPreprocessor
from secureshield.detection.trainer import DetectionTrainer

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

def train_all():
    config = load_config("configs/experiment.yaml")
    
    # 1. Load Data
    df, _ = load_raw_dataset(config.data.raw_csv)
    
    # 2. Preprocess (split, scale)
    # 2. Preprocess (split, scale)
    preprocessor = MalMemPreprocessor(
        test_size=config.data.test_size,
        val_size=config.data.val_size,
        random_state=config.data.random_state,
        feature_subset=config.data.selected_features,
    )
    
    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.fit_transform(df)
    preprocessor.save("models")
    
    # 3. Train models
    trainer = DetectionTrainer(
        seed=config.seed,
        cv_folds=5,
        include_stacking=False,
        models_dir=config.models_dir
    )
    
    trainer.train_and_evaluate(X_train, y_train, X_val, y_val, X_test, y_test)
    trainer.save_results("models")
    
if __name__ == "__main__":
    train_all()

"""
Phishing Detection Model Training
===================================
Training script using Random Forest and XGBoost classifiers
for URL, Certificate, and Domain phishing detection.

Datasets sourced from:
- UCI Machine Learning Repository
- Kaggle Datasets
"""

import os
import sys
import json
import pickle
import warnings
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

# ML Libraries
from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold, GridSearchCV
)
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier, VotingClassifier,
    StackingClassifier
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, roc_curve
)
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif

# XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("XGBoost not available. Install with: pip install xgboost")

# Local imports
from dataset_loader import (
    CombinedDatasetLoader, UCIDatasetLoader, KaggleDatasetLoader,
    DatasetPreprocessor
)

warnings.filterwarnings('ignore')


@dataclass
class ModelConfig:
    """Configuration for model training."""
    
    # Random Forest parameters
    rf_n_estimators: int = 200
    rf_max_depth: Optional[int] = None
    rf_min_samples_split: int = 2
    rf_min_samples_leaf: int = 1
    rf_max_features: str = 'sqrt'
    rf_class_weight: str = 'balanced'
    rf_random_state: int = 42
    
    # XGBoost parameters
    xgb_n_estimators: int = 200
    xgb_max_depth: int = 6
    xgb_learning_rate: float = 0.1
    xgb_subsample: float = 0.8
    xgb_colsample_bytree: float = 0.8
    xgb_scale_pos_weight: float = 1.0
    xgb_random_state: int = 42
    xgb_use_label_encoder: bool = False
    xgb_eval_metric: str = 'logloss'
    
    # Training parameters
    test_size: float = 0.2
    cv_folds: int = 5
    random_state: int = 42


@dataclass
class TrainingResults:
    """Results from model training."""
    
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    confusion_matrix: np.ndarray
    classification_report: str
    feature_importance: Dict[str, float]
    training_time: float
    cross_val_scores: np.ndarray
    best_params: Dict[str, Any]


class PhishingModelTrainer:
    """
    Main class for training phishing detection models using
    Random Forest and XGBoost.
    """
    
    def __init__(self, config: Optional[ModelConfig] = None, model_dir: str = 'models'):
        """
        Initialize the trainer.
        
        Args:
            config: ModelConfig with training parameters
            model_dir: Directory to save trained models
        """
        self.config = config or ModelConfig()
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        # Initialize data loaders
        self.data_loader = CombinedDatasetLoader('datasets')
        self.preprocessor = DatasetPreprocessor()
        
        # Storage for trained models
        self.models: Dict[str, Dict] = {}
        self.scalers: Dict[str, StandardScaler] = {}
        self.feature_names: Dict[str, List[str]] = {}
        
        # Results storage
        self.results: Dict[str, TrainingResults] = {}
    
    def load_or_generate_data(self, data_type: str = 'url',
                              force_generate: bool = False) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Load dataset or generate synthetic data for training.
        
        Args:
            data_type: 'url', 'certificate', or 'domain'
            force_generate: Force generation of synthetic data
            
        Returns:
            Tuple of (features, labels)
        """
        print(f"\n{'='*60}")
        print(f"Loading/Generating {data_type.upper()} Dataset")
        print(f"{'='*60}")
        
        # Try to load real dataset first
        dataset_path = f'datasets/{data_type}_features.csv'
        
        if os.path.exists(dataset_path) and not force_generate:
            print(f"Loading existing dataset: {dataset_path}")
            df = pd.read_csv(dataset_path)
        else:
            # Generate synthetic data based on type
            print(f"Generating synthetic {data_type} data...")
            df = self._generate_synthetic_data(data_type)
            # Save for future use
            df.to_csv(dataset_path, index=False)
            print(f"Saved synthetic data to: {dataset_path}")
        
        # Preprocess
        if data_type == 'url':
            df = self.preprocessor.preprocess_url_dataset(df)
        elif data_type == 'certificate':
            df = self.preprocessor.preprocess_certificate_dataset(df)
        elif data_type == 'domain':
            df = self.preprocessor.preprocess_domain_dataset(df)
        
        # Balance dataset
        df = self.preprocessor.balance_dataset(df, method='random_undersample')
        
        # Split features and labels
        X, y = self.preprocessor.split_features_labels(df)
        
        print(f"Dataset shape: {X.shape}")
        print(f"Label distribution: {y.value_counts().to_dict()}")
        
        return X, y
    
    def _generate_synthetic_data(self, data_type: str) -> pd.DataFrame:
        """Generate synthetic phishing dataset."""
        np.random.seed(42)
        n_samples = 5000
        
        if data_type == 'url':
            # Generate URL features
            data = []
            for _ in range(n_samples):
                is_phishing = np.random.random() < 0.4
                
                if is_phishing:
                    features = {
                        'url_length': np.random.randint(60, 200),
                        'hostname_length': np.random.randint(20, 80),
                        'path_length': np.random.randint(20, 150),
                        'num_dots': np.random.randint(3, 8),
                        'num_hyphens': np.random.randint(2, 6),
                        'num_underscores': np.random.randint(0, 5),
                        'num_slashes': np.random.randint(4, 12),
                        'num_digits': np.random.randint(5, 30),
                        'num_special': np.random.randint(3, 10),
                        'has_ip': np.random.randint(0, 2),
                        'has_at_symbol': np.random.randint(0, 2),
                        'has_https': np.random.randint(0, 2),
                        'has_port': np.random.randint(0, 2),
                        'is_suspicious_tld': np.random.randint(0, 2),
                        'has_suspicious_keyword': np.random.randint(0, 2),
                        'has_double_extension': np.random.randint(0, 2),
                        'has_encoded_chars': np.random.randint(0, 2),
                        'subdomain_count': np.random.randint(3, 8),
                        'long_subdomain': np.random.randint(0, 2),
                        'query_length': np.random.randint(20, 100),
                        'has_email_in_url': np.random.randint(0, 2),
                        'label': 1
                    }
                else:
                    features = {
                        'url_length': np.random.randint(20, 80),
                        'hostname_length': np.random.randint(10, 30),
                        'path_length': np.random.randint(5, 40),
                        'num_dots': np.random.randint(1, 3),
                        'num_hyphens': np.random.randint(0, 2),
                        'num_underscores': 0,
                        'num_slashes': np.random.randint(2, 5),
                        'num_digits': np.random.randint(0, 3),
                        'num_special': np.random.randint(0, 2),
                        'has_ip': 0,
                        'has_at_symbol': 0,
                        'has_https': 1,
                        'has_port': 0,
                        'is_suspicious_tld': 0,
                        'has_suspicious_keyword': 0,
                        'has_double_extension': 0,
                        'has_encoded_chars': 0,
                        'subdomain_count': np.random.randint(0, 2),
                        'long_subdomain': 0,
                        'query_length': np.random.randint(0, 20),
                        'has_email_in_url': 0,
                        'label': 0
                    }
                data.append(features)
            
            return pd.DataFrame(data)
        
        elif data_type == 'certificate':
            # Generate certificate features
            data = []
            for _ in range(n_samples):
                is_valid = np.random.random() < 0.7
                
                if is_valid:
                    features = {
                        'days_until_expiry': np.random.randint(30, 730),
                        'has_issuer': 1,
                        'has_subject': 1,
                        'is_extended_validation': np.random.randint(0, 2),
                        'has_weak_signature': 0,
                        'key_size': np.random.choice([2048, 4096]),
                        'has_large_key': 1,
                        'has_chain': 1,
                        'san_count': np.random.randint(1, 10),
                        'has_wildcard': np.random.randint(0, 2),
                        'label': 1
                    }
                else:
                    features = {
                        'days_until_expiry': np.random.randint(-30, 30),
                        'has_issuer': np.random.randint(0, 2),
                        'has_subject': np.random.randint(0, 2),
                        'is_extended_validation': 0,
                        'has_weak_signature': np.random.randint(0, 2),
                        'key_size': np.random.choice([512, 1024, 2048]),
                        'has_large_key': np.random.randint(0, 2),
                        'has_chain': np.random.randint(0, 2),
                        'san_count': 0,
                        'has_wildcard': 0,
                        'label': 0
                    }
                data.append(features)
            
            return pd.DataFrame(data)
        
        elif data_type == 'domain':
            # Generate domain features
            data = []
            for _ in range(n_samples):
                is_suspicious = np.random.random() < 0.35
                
                if is_suspicious:
                    features = {
                        'domain_age_days': np.random.randint(1, 60),
                        'days_until_expiry': np.random.randint(30, 200),
                        'has_registrar': 1,
                        'is_known_registrar': np.random.randint(0, 2),
                        'is_high_risk_country': np.random.randint(0, 2),
                        'has_privacy_protection': 1,
                        'nameserver_count': np.random.randint(1, 3),
                        'has_minimal_ns': np.random.randint(0, 2),
                        'has_whois': np.random.randint(0, 2),
                        'has_dnssec': 0,
                        'domain_length': np.random.randint(15, 40),
                        'has_numbers': 1,
                        'is_parked': np.random.randint(0, 2),
                        'is_for_sale': np.random.randint(0, 2),
                        'label': 1
                    }
                else:
                    features = {
                        'domain_age_days': np.random.randint(180, 3650),
                        'days_until_expiry': np.random.randint(200, 730),
                        'has_registrar': 1,
                        'is_known_registrar': 1,
                        'is_high_risk_country': 0,
                        'has_privacy_protection': np.random.randint(0, 2),
                        'nameserver_count': np.random.randint(2, 5),
                        'has_minimal_ns': 0,
                        'has_whois': 1,
                        'has_dnssec': 1,
                        'domain_length': np.random.randint(5, 20),
                        'has_numbers': np.random.randint(0, 2),
                        'is_parked': 0,
                        'is_for_sale': 0,
                        'label': 0
                    }
                data.append(features)
            
            return pd.DataFrame(data)
        
        else:
            raise ValueError(f"Unknown data type: {data_type}")
    
    def train_random_forest(self, X: pd.DataFrame, y: pd.Series,
                            model_name: str = 'rf_model'
                           ) -> TrainingResults:
        """
        Train a Random Forest classifier.
        
        Args:
            X: Feature matrix
            y: Labels
            model_name: Name for the model
            
        Returns:
            TrainingResults object
        """
        import time
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"Training Random Forest: {model_name}")
        print(f"{'='*60}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config.test_size,
            random_state=self.config.random_state, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Create and train model
        rf = RandomForestClassifier(
            n_estimators=self.config.rf_n_estimators,
            max_depth=self.config.rf_max_depth,
            min_samples_split=self.config.rf_min_samples_split,
            min_samples_leaf=self.config.rf_min_samples_leaf,
            max_features=self.config.rf_max_features,
            class_weight=self.config.rf_class_weight,
            random_state=self.config.rf_random_state,
            n_jobs=-1
        )
        
        print("Training Random Forest...")
        rf.fit(X_train_scaled, y_train)
        
        # Predictions
        y_pred = rf.predict(X_test_scaled)
        y_prob = rf.predict_proba(X_test_scaled)[:, 1]
        
        # Metrics
        training_time = time.time() - start_time
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        
        # Cross-validation
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True,
                            random_state=self.config.random_state)
        cv_scores = cross_val_score(rf, X_train_scaled, y_train, cv=cv, scoring='accuracy')
        
        # Feature importance
        feature_importance = dict(zip(X.columns, rf.feature_importances_))
        
        # Results
        results = TrainingResults(
            model_name=model_name,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_test, y_pred),
            classification_report=classification_report(y_test, y_pred),
            feature_importance=feature_importance,
            training_time=training_time,
            cross_val_scores=cv_scores,
            best_params=rf.get_params()
        )
        
        self.results[model_name] = results
        self.models[model_name] = {'rf': rf}
        self.scalers[model_name] = scaler
        self.feature_names[model_name] = list(X.columns)
        
        # Print results
        self._print_results(results, "Random Forest")
        
        # Save model
        self._save_model(model_name, rf, scaler)
        
        return results
    
    def train_xgboost(self, X: pd.DataFrame, y: pd.Series,
                      model_name: str = 'xgb_model'
                     ) -> TrainingResults:
        """
        Train an XGBoost classifier.
        
        Args:
            X: Feature matrix
            y: Labels
            model_name: Name for the model
            
        Returns:
            TrainingResults object
        """
        if not XGBOOST_AVAILABLE:
            print("XGBoost not available. Skipping XGBoost training.")
            return None
        
        import time
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"Training XGBoost: {model_name}")
        print(f"{'='*60}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config.test_size,
            random_state=self.config.random_state, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Calculate scale_pos_weight for imbalanced classes
        scale_pos_weight = len(y_train[y_train == 0]) / len(y_train[y_train == 1])
        
        # Create and train model
        xgb_model = xgb.XGBClassifier(
            n_estimators=self.config.xgb_n_estimators,
            max_depth=self.config.xgb_max_depth,
            learning_rate=self.config.xgb_learning_rate,
            subsample=self.config.xgb_subsample,
            colsample_bytree=self.config.xgb_colsample_bytree,
            scale_pos_weight=scale_pos_weight,
            random_state=self.config.xgb_random_state,
            use_label_encoder=False,
            eval_metric=self.config.xgb_eval_metric,
            n_jobs=-1
        )
        
        print("Training XGBoost...")
        xgb_model.fit(X_train_scaled, y_train)
        
        # Predictions
        y_pred = xgb_model.predict(X_test_scaled)
        y_prob = xgb_model.predict_proba(X_test_scaled)[:, 1]
        
        # Metrics
        training_time = time.time() - start_time
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        
        # Cross-validation
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True,
                            random_state=self.config.random_state)
        cv_scores = cross_val_score(xgb_model, X_train_scaled, y_train,
                                   cv=cv, scoring='accuracy')
        
        # Feature importance
        feature_importance = dict(zip(X.columns, xgb_model.feature_importances_))
        
        # Results
        results = TrainingResults(
            model_name=model_name,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_test, y_pred),
            classification_report=classification_report(y_test, y_pred),
            feature_importance=feature_importance,
            training_time=training_time,
            cross_val_scores=cv_scores,
            best_params=xgb_model.get_params()
        )
        
        self.results[model_name] = results
        self.models[model_name] = {'xgb': xgb_model}
        self.scalers[model_name] = scaler
        self.feature_names[model_name] = list(X.columns)
        
        # Print results
        self._print_results(results, "XGBoost")
        
        # Save model
        self._save_model(model_name, xgb_model, scaler)
        
        return results
    
    def train_ensemble(self, X: pd.DataFrame, y: pd.Series,
                       model_name: str = 'ensemble_model'
                      ) -> TrainingResults:
        """
        Train an ensemble of Random Forest and XGBoost.
        
        Args:
            X: Feature matrix
            y: Labels
            model_name: Name for the model
            
        Returns:
            TrainingResults object
        """
        import time
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"Training Ensemble (RF + XGBoost): {model_name}")
        print(f"{'='*60}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config.test_size,
            random_state=self.config.random_state, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Create base models
        rf = RandomForestClassifier(
            n_estimators=self.config.rf_n_estimators,
            max_depth=self.config.rf_max_depth,
            class_weight=self.config.rf_class_weight,
            random_state=self.config.rf_random_state,
            n_jobs=-1
        )
        
        estimators = [
            ('rf', rf)
        ]
        
        # Add XGBoost if available
        if XGBOOST_AVAILABLE:
            scale_pos_weight = len(y_train[y_train == 0]) / len(y_train[y_train == 1])
            xgb_model = xgb.XGBClassifier(
                n_estimators=self.config.xgb_n_estimators,
                max_depth=self.config.xgb_max_depth,
                learning_rate=self.config.xgb_learning_rate,
                scale_pos_weight=scale_pos_weight,
                random_state=self.config.xgb_random_state,
                use_label_encoder=False,
                eval_metric=self.config.xgb_eval_metric,
                n_jobs=-1
            )
            estimators.append(('xgb', xgb_model))
        
        # Voting Classifier (soft voting)
        ensemble = VotingClassifier(
            estimators=estimators,
            voting='soft',
            n_jobs=-1
        )
        
        print("Training Ensemble...")
        ensemble.fit(X_train_scaled, y_train)
        
        # Predictions
        y_pred = ensemble.predict(X_test_scaled)
        y_prob = ensemble.predict_proba(X_test_scaled)[:, 1]
        
        # Metrics
        training_time = time.time() - start_time
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        
        # Cross-validation
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True,
                            random_state=self.config.random_state)
        cv_scores = cross_val_score(ensemble, X_train_scaled, y_train,
                                   cv=cv, scoring='accuracy')
        
        # Feature importance (from Random Forest)
        feature_importance = dict(zip(X.columns, rf.feature_importances_))
        
        # Results
        results = TrainingResults(
            model_name=model_name,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            roc_auc=roc_auc,
            confusion_matrix=confusion_matrix(y_test, y_pred),
            classification_report=classification_report(y_test, y_pred),
            feature_importance=feature_importance,
            training_time=training_time,
            cross_val_scores=cv_scores,
            best_params={'ensemble': 'voting_soft'}
        )
        
        self.results[model_name] = results
        self.models[model_name] = {'ensemble': ensemble}
        self.scalers[model_name] = scaler
        self.feature_names[model_name] = list(X.columns)
        
        # Print results
        self._print_results(results, "Ensemble")
        
        # Save model
        self._save_model(model_name, ensemble, scaler)
        
        return results
    
    def _print_results(self, results: TrainingResults, model_type: str):
        """Print training results."""
        print(f"\n{model_type} Results:")
        print(f"  Accuracy:  {results.accuracy:.4f}")
        print(f"  Precision: {results.precision:.4f}")
        print(f"  Recall:    {results.recall:.4f}")
        print(f"  F1-Score:  {results.f1_score:.4f}")
        print(f"  ROC-AUC:   {results.roc_auc:.4f}")
        print(f"  Training Time: {results.training_time:.2f}s")
        print(f"  Cross-Val Accuracy: {results.cross_val_scores.mean():.4f} "
              f"(+/- {results.cross_val_scores.std()*2:.4f})")
        
        print(f"\nConfusion Matrix:")
        print(results.confusion_matrix)
        
        print(f"\nTop 10 Feature Importance:")
        sorted_features = sorted(results.feature_importance.items(),
                               key=lambda x: x[1], reverse=True)[:10]
        for feat, imp in sorted_features:
            print(f"  {feat}: {imp:.4f}")
    
    def _save_model(self, model_name: str, model, scaler: StandardScaler):
        """Save trained model and scaler."""
        # Save model
        model_path = os.path.join(self.model_dir, f'{model_name}.joblib')
        import joblib
        joblib.dump(model, model_path)
        
        # Save scaler
        scaler_path = os.path.join(self.model_dir, f'{model_name}_scaler.joblib')
        joblib.dump(scaler, scaler_path)
        
        # Save feature names
        if model_name in self.feature_names:
            features_path = os.path.join(self.model_dir, f'{model_name}_features.json')
            with open(features_path, 'w') as f:
                json.dump(self.feature_names[model_name], f)
        
        print(f"\nModel saved to: {model_path}")
        print(f"Scaler saved to: {scaler_path}")
    
    def compare_models(self) -> pd.DataFrame:
        """
        Compare all trained models.
        
        Returns:
            DataFrame with comparison results
        """
        print(f"\n{'='*60}")
        print("Model Comparison")
        print(f"{'='*60}")
        
        comparison_data = []
        for name, results in self.results.items():
            comparison_data.append({
                'Model': name,
                'Accuracy': results.accuracy,
                'Precision': results.precision,
                'Recall': results.recall,
                'F1-Score': results.f1_score,
                'ROC-AUC': results.roc_auc,
                'CV Mean': results.cross_val_scores.mean(),
                'CV Std': results.cross_val_scores.std(),
                'Time (s)': results.training_time
            })
        
        df = pd.DataFrame(comparison_data)
        df = df.sort_values('F1-Score', ascending=False)
        
        print("\n" + df.to_string(index=False))
        
        # Save comparison
        df.to_csv(os.path.join(self.model_dir, 'model_comparison.csv'), index=False)
        
        return df
    
    def get_best_model(self, metric: str = 'f1_score') -> Tuple[str, TrainingResults]:
        """
        Get the best performing model based on specified metric.
        
        Args:
            metric: Metric to optimize ('accuracy', 'precision', 'recall', 'f1_score', 'roc_auc')
            
        Returns:
            Tuple of (model_name, results)
        """
        best_name = None
        best_score = -1
        best_results = None
        
        for name, results in self.results.items():
            score = getattr(results, metric)
            if score > best_score:
                best_score = score
                best_name = name
                best_results = results
        
        return best_name, best_results
    
    def train_all_models(self, data_type: str = 'url'):
        """
        Train all models (Random Forest, XGBoost, Ensemble) for a data type.
        
        Args:
            data_type: Type of data ('url', 'certificate', 'domain')
        """
        print(f"\n{'='*60}")
        print(f"Training All Models for {data_type.upper()} Detection")
        print(f"{'='*60}")
        
        # Load data
        X, y = self.load_or_generate_data(data_type)
        
        # Train models
        self.train_random_forest(X, y, f'{data_type}_rf')
        self.train_xgboost(X, y, f'{data_type}_xgb')
        self.train_ensemble(X, y, f'{data_type}_ensemble')
        
        # Compare models
        self.compare_models()
    
    def hyperparameter_tuning(self, X: pd.DataFrame, y: pd.Series,
                            model_type: str = 'rf'
                           ) -> Dict:
        """
        Perform hyperparameter tuning using GridSearchCV.
        
        Args:
            X: Feature matrix
            y: Labels
            model_type: 'rf' or 'xgb'
            
        Returns:
            Best parameters dictionary
        """
        print(f"\n{'='*60}")
        print(f"Hyperparameter Tuning: {model_type.upper()}")
        print(f"{'='*60}")
        
        # Split data
        X_train, _, y_train, _ = train_test_split(
            X, y, test_size=self.config.test_size,
            random_state=self.config.random_state
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True,
                            random_state=self.config.random_state)
        
        if model_type == 'rf':
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            }
            
            model = RandomForestClassifier(
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
        
        elif model_type == 'xgb' and XGBOOST_AVAILABLE:
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [4, 6, 8],
                'learning_rate': [0.05, 0.1, 0.2],
                'subsample': [0.7, 0.8, 0.9]
            }
            
            model = xgb.XGBClassifier(
                use_label_encoder=False,
                eval_metric='logloss',
                random_state=42,
                n_jobs=-1
            )
        else:
            print(f"Unknown model type: {model_type}")
            return {}
        
        print("Running GridSearchCV...")
        grid_search = GridSearchCV(
            model, param_grid, cv=cv, scoring='f1', n_jobs=-1, verbose=1
        )
        grid_search.fit(X_train_scaled, y_train)
        
        print(f"\nBest Parameters: {grid_search.best_params_}")
        print(f"Best F1-Score: {grid_search.best_score_:.4f}")
        
        return grid_search.best_params_


def download_datasets():
    """Download and prepare datasets from UCI and Kaggle."""
    print("\n" + "="*60)
    print("Downloading Datasets")
    print("="*60)
    
    # UCI Dataset
    print("\nDownloading UCI Phishing Dataset...")
    uci_loader = UCIDatasetLoader('datasets')
    
    # Try to download UCI dataset
    uci_path = uci_loader.download_dataset('phishing_websites')
    if uci_path:
        df = uci_loader.load_arff(uci_path)
        if df is not None:
            df.to_csv('datasets/uci_phishing.csv', index=False)
            print(f"UCI dataset saved: {len(df)} rows")
    
    # Note about Kaggle
    print("\nNote: Kaggle datasets require Kaggle API credentials.")
    print("To download Kaggle datasets:")
    print("1. Get API token from: https://www.kaggle.com/account")
    print("2. Place token at: ~/.kaggle/kaggle.json")
    print("3. Install kaggle: pip install kaggle")
    
    print("\nSample datasets created for testing.")


def main():
    """Main function for training phishing detection models."""
    print("\n" + "="*60)
    print("Phishing Detection Model Training")
    print("="*60)
    print(f"XGBoost Available: {XGBOOST_AVAILABLE}")
    
    # Create trainer
    config = ModelConfig()
    trainer = PhishingModelTrainer(config)
    
    # Download datasets
    download_datasets()
    
    # Train URL detection models
    trainer.train_all_models('url')
    
    # Train Certificate detection models
    trainer.train_all_models('certificate')
    
    # Train Domain detection models
    trainer.train_all_models('domain')
    
    # Get best models
    print("\n" + "="*60)
    print("Best Models Summary")
    print("="*60)
    
    for data_type in ['url', 'certificate', 'domain']:
        best_name, best_results = trainer.get_best_model(f'{data_type}_model')
        print(f"\n{data_type.upper()} Best Model: {best_name}")
        print(f"  F1-Score: {best_results.f1_score:.4f}")
        print(f"  ROC-AUC: {best_results.roc_auc:.4f}")
    
    print("\n" + "="*60)
    print("Training Complete!")
    print(f"Models saved in: {trainer.model_dir}")
    print("="*60)
    
    return trainer


if __name__ == '__main__':
    main()


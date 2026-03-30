"""
Dataset Loader for Kaggle and UCI Phishing Datasets
====================================================
This module provides utilities for downloading and loading
phishing datasets from Kaggle and UCI ML Repository.
"""

import os
import pandas as pd
import numpy as np
import zipfile
import tarfile
import shutil
import requests
import json
from datetime import datetime
from urllib.request import urlretrieve
from typing import Optional, Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')


class UCIDatasetLoader:
    """Loader for UCI ML Repository phishing datasets."""
    
    UCI_BASE_URL = "https://archive.ics.uci.edu"
    
    # UCI Phishing datasets configuration
    UCI_DATASETS = {
        'phishing_websites': {
            'url': UCI_BASE_URL + "/ml/machine-learning-databases/00437/",
            'file': " phishing_website.arff",
            'description': "Phishing Websites Dataset with 30 features",
            'features': [
                'having_IP_Address', 'URL_Length', 'shortining_Service', 'having_At_Symbol',
                'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
                'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
                'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
                'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
                'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
                'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
                'Links_pointing_to_page', 'Statistical_report'
            ]
        },
        'phishing_urls': {
            'url': UCI_BASE_URL + "/ml/machine-learning-databases/00541/",
            'file': " data.csv",
            'description': "Phishing URL Dataset with lexical features",
            'features': [
                'url_length', 'hostname_length', 'path_length', 'num_dots',
                'num_hyphens', 'num_underscores', 'num_slashes', 'num_digits',
                'num_special', 'has_ip', 'has_at', 'has_https', 'has_port',
                'is_suspicious_tld', 'has_suspicious_kw', 'has_double_ext',
                'has_encoded', 'subdomain_count', 'query_length', 'has_email'
            ]
        }
    }
    
    def __init__(self, dataset_dir='datasets'):
        self.dataset_dir = dataset_dir
        os.makedirs(dataset_dir, exist_ok=True)
    
    def download_dataset(self, dataset_name: str, force_download: bool = False) -> Optional[str]:
        """
        Download dataset from UCI repository.
        
        Args:
            dataset_name: Name of the dataset from UCI_DATASETS
            force_download: Force re-download even if exists
            
        Returns:
            Path to downloaded file or None
        """
        if dataset_name not in self.UCI_DATASETS:
            print(f"Unknown dataset: {dataset_name}")
            print(f"Available: {list(self.UCI_DATASETS.keys())}")
            return None
        
        config = self.UCI_DATASETS[dataset_name]
        filename = config['file'].strip()
        filepath = os.path.join(self.dataset_dir, filename)
        
        if os.path.exists(filepath) and not force_download:
            print(f"Dataset already exists: {filepath}")
            return filepath
        
        full_url = config['url'] + filename
        print(f"Downloading {dataset_name} from UCI...")
        print(f"URL: {full_url}")
        
        try:
            urlretrieve(full_url, filepath)
            print(f"Downloaded to: {filepath}")
            return filepath
        except Exception as e:
            print(f"Error downloading: {e}")
            # Try alternative method with requests
            try:
                response = requests.get(full_url, timeout=30)
                if response.status_code == 200:
                    with open(filepath, 'wb') as f:
                        f.write(response.content)
                    print(f"Downloaded to: {filepath}")
                    return filepath
            except Exception as e2:
                print(f"Alternative download also failed: {e2}")
            return None
    
    def load_arff(self, filepath: str) -> Optional[pd.DataFrame]:
        """Load ARFF (Attribute-Relation File Format) file."""
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return None
        
        # Parse ARFF file
        attributes = []
        data = []
        reading_data = False
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('@attribute'):
                    # Extract attribute name and type
                    parts = line.replace('@attribute', '').strip().split()
                    attr_name = parts[0]
                    attr_type = parts[1] if len(parts) > 1 else 'string'
                    attributes.append((attr_name, attr_type))
                elif line.startswith('@data'):
                    reading_data = True
                elif reading_data and line:
                    # Parse data line
                    values = self._parse_arff_values(line)
                    data.append(values)
        
        if not data:
            print("No data found in ARFF file")
            return None
        
        # Create DataFrame
        df = pd.DataFrame(data, columns=[a[0] for a in attributes])
        
        # Convert to numeric where possible
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='ignore')
        
        print(f"Loaded ARFF file: {len(df)} rows, {len(attributes)} columns")
        return df
    
    def _parse_arff_values(self, line: str) -> List:
        """Parse ARFF data line handling quoted strings."""
        values = []
        current = ''
        in_quotes = False
        
        for char in line:
            if char == "'" and not in_quotes:
                in_quotes = True
            elif char == "'" and in_quotes:
                in_quotes = False
            elif char == ',' and not in_quotes:
                values.append(current.strip("'").strip('"'))
                current = ''
            else:
                current += char
        
        values.append(current.strip("'").strip('"'))
        return values
    
    def load_csv(self, filepath: str) -> Optional[pd.DataFrame]:
        """Load CSV file with multiple encoding attempts."""
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return None
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                df = pd.read_csv(filepath, encoding=encoding)
                print(f"Loaded CSV: {len(df)} rows, {len(df.columns)} columns")
                return df
            except UnicodeDecodeError:
                continue
        
        print(f"Could not load file: {filepath}")
        return None
    
    def load_uci_phishing_dataset(self, force_download: bool = False) -> Optional[pd.DataFrame]:
        """
        Load the main UCI Phishing Websites dataset.
        
        Returns:
            DataFrame with features and label column
        """
        # Try to download if not exists
        filepath = self.download_dataset('phishing_websites', force_download)
        
        if filepath is None:
            print("Could not download UCI dataset")
            return None
        
        # Try ARFF first, then CSV
        if filepath.endswith('.arff'):
            df = self.load_arff(filepath)
        else:
            df = self.load_csv(filepath)
        
        if df is not None:
            # Standardize label column
            df = self._standardize_labels(df)
        
        return df
    
    def _standardize_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize label column names and values."""
        label_cols = ['class', 'label', 'target', 'Class', 'Label', 'phishing', 'result']
        
        for col in label_cols:
            if col in df.columns:
                # Rename to 'label'
                df = df.rename(columns={col: 'label'})
                
                # Convert to binary (1=phishing, 0=safe)
                if df['label'].dtype == object:
                    df['label'] = df['label'].map({
                        'phishing': 1, 'legitimate': 0, 'safe': 0, 'benign': 0,
                        'yes': 1, 'no': 0, 'Y': 1, 'N': 0,
                        '1': 1, '0': 0
                    })
                break
        
        return df


class KaggleDatasetLoader:
    """Loader for Kaggle phishing datasets."""
    
    def __init__(self, dataset_dir='datasets'):
        self.dataset_dir = dataset_dir
        os.makedirs(dataset_dir, exist_ok=True)
        self.api_token = None
    
    def set_api_token(self, token_path: str = '~/.kaggle/kaggle.json'):
        """Set Kaggle API token path."""
        expanded_path = os.path.expanduser(token_path)
        if os.path.exists(expanded_path):
            with open(expanded_path, 'r') as f:
                self.api_token = json.load(f)
            print("Kaggle API token loaded")
        else:
            print(f"Kaggle token not found at {expanded_path}")
            print("Please download from: https://www.kaggle.com/account")
    
    def download_with_kaggle(self, dataset_name: str, force_download: bool = False) -> Optional[str]:
        """
        Download dataset using Kaggle API.
        
        Args:
            dataset_name: Kaggle dataset name (e.g., 'shidhuka/urldataset')
            force_download: Force re-download
            
        Returns:
            Path to extracted dataset directory
        """
        try:
            import kaggle
            from kaggle.api.kaggle_api_extended import KaggleApi
            
            api = KaggleApi()
            api.authenticate()
            
            dataset_path = os.path.join(self.dataset_dir, dataset_name)
            
            if os.path.exists(dataset_path) and not force_download:
                print(f"Dataset already exists: {dataset_path}")
                return dataset_path
            
            print(f"Downloading dataset: {dataset_name}")
            api.dataset_download_files(dataset_name, path=self.dataset_dir, unzip=True)
            
            print(f"Downloaded to: {dataset_path}")
            return dataset_path
            
        except ImportError:
            print("Kaggle API not installed. Run: pip install kaggle")
            return None
        except Exception as e:
            print(f"Kaggle API error: {e}")
            return None
    
    def download_direct(self, url: str, filename: str, force_download: bool = False) -> Optional[str]:
        """
        Download dataset directly from URL.
        
        Args:
            url: Direct download URL
            filename: Output filename
            force_download: Force re-download
            
        Returns:
            Path to downloaded file
        """
        filepath = os.path.join(self.dataset_dir, filename)
        
        if os.path.exists(filepath) and not force_download:
            print(f"Dataset already exists: {filepath}")
            return filepath
        
        print(f"Downloading from {url}...")
        
        try:
            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"Downloaded to: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"Error downloading: {e}")
            return None
    
    def extract_zip(self, zip_path: str, extract_to: Optional[str] = None) -> List[str]:
        """Extract ZIP file."""
        if extract_to is None:
            extract_to = os.path.dirname(zip_path)
        
        if not os.path.exists(zip_path):
            print(f"File not found: {zip_path}")
            return []
        
        print(f"Extracting {zip_path}...")
        
        extracted_files = []
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for name in zip_ref.namelist():
                if not name.endswith('/'):  # Skip directories
                    zip_ref.extract(name, extract_to)
                    extracted_files.append(os.path.join(extract_to, name))
        
        print(f"Extracted {len(extracted_files)} files")
        return extracted_files
    
    def load_csv(self, filepath: str) -> Optional[pd.DataFrame]:
        """Load CSV file with encoding handling."""
        if not os.path.exists(filepath):
            # Try to find in dataset directory
            dataset_dir = os.path.dirname(filepath)
            if os.path.exists(dataset_dir):
                for f in os.listdir(dataset_dir):
                    if f.endswith('.csv'):
                        filepath = os.path.join(dataset_dir, f)
                        break
            else:
                print(f"File not found: {filepath}")
                return None
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        
        for encoding in encodings:
            try:
                df = pd.read_csv(filepath, encoding=encoding)
                print(f"Loaded: {len(df)} rows, {len(df.columns)} columns")
                return df
            except UnicodeDecodeError:
                continue
        
        print(f"Could not load: {filepath}")
        return None


class DatasetPreprocessor:
    """Preprocessing utilities for phishing datasets."""
    
    def __init__(self):
        self.label_encoders = {}
        self.feature_stats = {}
    
    def preprocess_url_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess URL phishing dataset."""
        print("Preprocessing URL dataset...")
        
        # Standardize labels
        if 'label' in df.columns:
            df['label'] = df['label'].map({
                'phishing': 1, 'legitimate': 0, 'safe': 0, 'benign': 0,
                'bad': 1, 'malicious': 1, 'suspicious': 1,
                '1': 1, '0': 0, 'yes': 1, 'no': 0
            })
        
        # Remove duplicates
        df = df.drop_duplicates()
        
        # Remove rows with missing URLs
        if 'url' in df.columns:
            df = df.dropna(subset=['url'])
        
        # Convert all feature columns to numeric
        for col in df.columns:
            if col != 'url' and col != 'label':
                df[col] = pd.to_numeric(df[col], errors='coerce')
                df[col] = df[col].fillna(0)
        
        print(f"Preprocessed: {len(df)} rows")
        return df
    
    def preprocess_certificate_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess certificate dataset."""
        print("Preprocessing certificate dataset...")
        
        # Convert date columns
        date_cols = ['not_before', 'not_after', 'valid_from', 'valid_until',
                    'created', 'expires', 'expiry_date']
        
        for col in date_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        # Calculate days until expiry
        if 'not_after' in df.columns:
            df['days_until_expiry'] = (df['not_after'] - datetime.now()).dt.days
        elif 'expiry_date' in df.columns:
            df['days_until_expiry'] = (df['expiry_date'] - datetime.now()).dt.days
        
        # Fill numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)
        
        # Standardize labels
        if 'is_valid' in df.columns:
            df['is_valid'] = df['is_valid'].map({True: 1, False: 0, 'True': 1, 'False': 0})
            df = df.rename(columns={'is_valid': 'label'})
        
        print(f"Preprocessed: {len(df)} rows")
        return df
    
    def preprocess_domain_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess domain dataset."""
        print("Preprocessing domain dataset...")
        
        # Convert date columns
        date_cols = ['creation_date', 'expiry_date', 'created', 'registered',
                    'registered_date', 'domain_age']
        
        for col in date_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        # Calculate domain age in days
        if 'creation_date' in df.columns:
            df['domain_age_days'] = (datetime.now() - df['creation_date']).dt.days
        elif 'created' in df.columns:
            df['domain_age_days'] = (datetime.now() - df['created']).dt.days
        
        # Fill numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)
        
        # Standardize labels
        if 'label' in df.columns:
            df['label'] = df['label'].map({
                'phishing': 1, 'legitimate': 0, 'safe': 0, 'benign': 0,
                'malicious': 1, 'suspicious': 1, 'normal': 0,
                '1': 1, '0': 0, 'yes': 1, 'no': 0
            })
        
        print(f"Preprocessed: {len(df)} rows")
        return df
    
    def balance_dataset(self, df: pd.DataFrame, label_col: str = 'label',
                        method: str = 'random_undersample') -> pd.DataFrame:
        """
        Balance dataset to have equal phishing and legitimate samples.
        
        Args:
            df: Input DataFrame
            label_col: Name of label column
            method: 'random_undersample', 'random_oversample', or 'smote'
            
        Returns:
            Balanced DataFrame
        """
        phishing = df[df[label_col] == 1]
        legitimate = df[df[label_col] == 0]
        
        print(f"Original: Phishing={len(phishing)}, Legitimate={len(legitimate)}")
        
        if method == 'random_undersample':
            # Undersample majority class
            if len(legitimate) > len(phishing):
                legitimate = legitimate.sample(n=len(phishing), random_state=42)
            else:
                phishing = phishing.sample(n=len(legitimate), random_state=42)
        
        elif method == 'random_oversample':
            # Oversample minority class
            if len(phishing) > len(legitimate):
                legitimate = legitimate.sample(n=len(phishing), replace=True, random_state=42)
            else:
                phishing = phishing.sample(n=len(legitimate), replace=True, random_state=42)
        
        elif method == 'smote':
            try:
                from imblearn.over_sampling import SMOTE
                X = df.drop(columns=[label_col])
                y = df[label_col]
                X_resampled, y_resampled = SMOTE(random_state=42).fit_resample(X, y)
                df = pd.concat([X_resampled, y_resampled], axis=1)
                print(f"Balanced using SMOTE: {len(df)} rows")
                return df
            except ImportError:
                print("imbalanced-learn not installed. Using random oversample.")
                return self.balance_dataset(df, label_col, 'random_oversample')
        
        # Combine
        balanced = pd.concat([phishing, legitimate], ignore_index=True)
        balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"Balanced: Phishing={len(balanced[balanced[label_col]==1])}, "
              f"Legitimate={len(balanced[balanced[label_col]==0])}")
        
        return balanced
    
    def split_features_labels(self, df: pd.DataFrame, label_col: str = 'label'
                             ) -> Tuple[pd.DataFrame, pd.Series]:
        """Split DataFrame into features and labels."""
        X = df.drop(columns=[label_col])
        y = df[label_col]
        
        # Remove non-numeric columns
        X = X.select_dtypes(include=[np.number])
        
        return X, y
    
    def normalize_features(self, X_train: pd.DataFrame, X_test: pd.DataFrame
                          ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Normalize features using StandardScaler."""
        from sklearn.preprocessing import StandardScaler
        
        scaler = StandardScaler()
        X_train_scaled = pd.DataFrame(
            scaler.fit_transform(X_train),
            columns=X_train.columns,
            index=X_train.index
        )
        X_test_scaled = pd.DataFrame(
            scaler.transform(X_test),
            columns=X_test.columns,
            index=X_test.index
        )
        
        return X_train_scaled, X_test_scaled
    
    def save_dataset(self, df: pd.DataFrame, filename: str) -> str:
        """Save dataset to CSV."""
        filepath = os.path.join('datasets', filename)
        df.to_csv(filepath, index=False)
        print(f"Saved: {filepath}")
        return filepath
    
    def get_dataset_info(self, df: pd.DataFrame) -> Dict:
        """Get information about dataset."""
        info = {
            'shape': df.shape,
            'columns': list(df.columns),
            'dtypes': df.dtypes.to_dict(),
            'missing_values': df.isnull().sum().to_dict(),
            'label_distribution': df['label'].value_counts().to_dict() if 'label' in df.columns else {}
        }
        
        # Numeric summary
        numeric_df = df.select_dtypes(include=[np.number])
        if len(numeric_df) > 0:
            info['numeric_summary'] = numeric_df.describe().to_dict()
        
        return info


class CombinedDatasetLoader:
    """Combined loader for both UCI and Kaggle datasets."""
    
    def __init__(self, dataset_dir='datasets'):
        self.dataset_dir = dataset_dir
        os.makedirs(dataset_dir, exist_ok=True)
        
        self.uci_loader = UCIDatasetLoader(dataset_dir)
        self.kaggle_loader = KaggleDatasetLoader(dataset_dir)
        self.preprocessor = DatasetPreprocessor()
    
    def load_uci_phishing_data(self, force_download: bool = False) -> Optional[pd.DataFrame]:
        """Load UCI phishing dataset."""
        df = self.uci_loader.load_uci_phishing_dataset(force_download)
        
        if df is not None:
            df = self.preprocessor.preprocess_url_dataset(df)
        
        return df
    
    def load_kaggle_url_data(self, dataset_name: str = None,
                             local_path: str = None) -> Optional[pd.DataFrame]:
        """Load Kaggle URL dataset."""
        if local_path:
            df = self.kaggle_loader.load_csv(local_path)
        elif dataset_name:
            path = self.kaggle_loader.download_with_kaggle(dataset_name)
            if path:
                df = self.kaggle_loader.load_csv(path)
            else:
                df = None
        else:
            print("Please provide dataset_name or local_path")
            df = None
        
        if df is not None:
            df = self.preprocessor.preprocess_url_dataset(df)
        
        return df
    
    def merge_and_prepare(self, datasets: List[pd.DataFrame],
                         label_col: str = 'label') -> Tuple[pd.DataFrame, pd.Series]:
        """
        Merge multiple datasets and prepare for training.
        
        Args:
            datasets: List of DataFrames to merge
            label_col: Name of label column
            
        Returns:
            Tuple of (X, y) for training
        """
        # Find common columns (excluding label)
        all_cols = set()
        for df in datasets:
            all_cols.update(df.columns)
        
        common_cols = list(all_cols)
        if label_col in common_cols:
            common_cols.remove(label_col)
        
        # Add label column to common columns
        common_cols.append(label_col)
        
        # Merge datasets on common columns
        merged = pd.concat(datasets, ignore_index=True, sort=False)
        
        # Keep only common columns
        cols_to_keep = [c for c in common_cols if c in merged.columns]
        merged = merged[cols_to_keep]
        
        # Preprocess
        merged = self.preprocessor.preprocess_url_dataset(merged)
        
        # Balance
        merged = self.preprocessor.balance_dataset(merged, label_col)
        
        # Split
        X, y = self.preprocessor.split_features_labels(merged, label_col)
        
        return X, y


def create_sample_datasets():
    """Create sample datasets for testing."""
    loader = CombinedDatasetLoader()
    
    # Sample URL dataset
    sample_urls = pd.DataFrame({
        'url': [
            "https://www.google.com/search?q=test",
            "http://192.168.1.1/login",
            "https://secure-paypal.com-verify.tk/login.php",
            "https://www.github.com",
            "http://suspicious-site.xyz/login",
            "https://www.facebook.com/profile.php?id=123",
            "http://login-update@secure-bank.com",
            "https://www.microsoft.com",
            "http://phishing-example.tk/account/verify",
            "https://www.amazon.com"
        ],
        'label': [0, 1, 1, 0, 1, 0, 1, 0, 1, 0]
    })
    loader.preprocessor.save_dataset(sample_urls, 'sample_urls.csv')
    
    # Sample URL features (pre-extracted)
    sample_features = pd.DataFrame({
        'url_length': [25, 18, 45, 21, 30, 35, 40, 22, 38, 28],
        'hostname_length': [14, 12, 26, 11, 18, 20, 28, 16, 22, 16],
        'num_dots': [2, 0, 4, 2, 3, 3, 2, 2, 3, 2],
        'num_hyphens': [0, 0, 3, 0, 2, 0, 2, 0, 2, 0],
        'has_https': [1, 0, 1, 1, 0, 1, 0, 1, 0, 1],
        'has_ip': [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        'has_at_symbol': [0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        'is_suspicious_tld': [0, 0, 1, 0, 1, 0, 0, 0, 1, 0],
        'label': [0, 1, 1, 0, 1, 0, 1, 0, 1, 0]
    })
    loader.preprocessor.save_dataset(sample_features, 'sample_url_features.csv')
    
    print("Sample datasets created!")


if __name__ == '__main__':
    # Test sample data creation
    create_sample_datasets()
    
    # Test loading sample data
    loader = CombinedDatasetLoader()
    
    print("\n=== Loading Sample URL Dataset ===")
    df = loader.kaggle_loader.load_csv('datasets/sample_urls.csv')
    if df is not None:
        print(df.head())
        print(f"\nShape: {df.shape}")
        print(f"\nLabel distribution:\n{df['label'].value_counts()}")
    
    print("\n=== Loading Sample Features Dataset ===")
    df = loader.kaggle_loader.load_csv('datasets/sample_url_features.csv')
    if df is not None:
        print(df.head())
        print(f"\nShape: {df.shape}")


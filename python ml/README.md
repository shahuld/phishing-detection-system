# Phishing Detection Machine Learning

A comprehensive phishing detection system using **Random Forest** and **XGBoost** classifiers to detect phishing URLs, certificate issues, and domain threats.

## How Datasets Work

### Real-Time Dataset Extraction

The system is designed to use **real datasets from Kaggle and UCI** in production:

```
┌─────────────────────────────────────────────────────────┐
│           DATASET SOURCES (Priority Order)              │
├─────────────────────────────────────────────────────────┤
│  1. Kaggle Dataset (Recommended)                        │
│     - Requires: Kaggle API token                        │
│     - Command: load_kaggle_url_data()                   │
│     - Source: kaggle.com/datasets                       │
│                                                         │
│  2. UCI Machine Learning Repository                     │
│     - No API needed                                     │
│     - Command: load_uci_phishing_data()                │
│     - Source: archive.ics.uci.edu/ml                   │
│                                                         │
│  3. Sample Dataset (For Testing)                       │
│     - Pre-generated for quick testing                   │
│     - Auto-used if real data unavailable               │
│     - Location: data/phishing_train.csv                 │
└─────────────────────────────────────────────────────────┘
```

### Quick Start (Uses Sample Data First)

```python
from phishing_detector import PhishingDetectorML

# This uses sample data for immediate testing
detector = PhishingDetectorML()

result = detector.check_url("https://suspicious-site.tk/login")
print(f"Result: {result['result']}")
print(f"Confidence: {result['confidence']}%")
```

### Use Real Kaggle Dataset

```python
from dataset_loader import KaggleDatasetLoader

loader = KaggleDatasetLoader()

# Method 1: Set Kaggle API token
loader.set_api_token('~/.kaggle/kaggle.json')

# Method 2: Download popular phishing datasets
# Popular Kaggle phishing datasets:
# - 'shidhuka/urldataset'
# - 'akashkunk/ phishing-url-dataset'
# - 'tarunpappala/phishing-url-dataset'

df = loader.download_with_kaggle('shidhuka/urldataset')
print(f"Downloaded: {df.shape[0]} samples")
```

### Use Real UCI Dataset

```python
from dataset_loader import UCIDatasetLoader

loader = UCIDatasetLoader()

# Downloads from UCI ML Repository automatically
df = loader.load_uci_phishing_dataset(force_download=False)
print(f"UCI Dataset: {df.shape[0]} samples")

# Available UCI datasets:
# - 'phishing_websites' - 30 features
# - 'phishing_urls' - Lexical features
```

### Training with Real Data

```python
from train_models import PhishingModelTrainer
from dataset_loader import CombinedDatasetLoader

# Load real data
combined = CombinedDatasetLoader()

# Option A: UCI Dataset
uci_df = combined.load_uci_phishing_data(force_download=False)

# Option B: Kaggle Dataset  
kaggle_df = combined.load_kaggle_url_data(dataset_name='your-dataset')

# Option C: Your own CSV
import pandas as pd
your_df = pd.read_csv('data/your_phishing_data.csv')

# Train models with real data
trainer = PhishingModelTrainer()
results = trainer.train_all_models('url', data=your_df)
```

## Features

- 🌐 **URL Scanner** - Detects phishing URLs using ML classification
- 🔒 **Certificate Check** - Validates SSL certificates with ML
- 🌐 **Domain Lookup** - Analyzes domain features for threat detection
- 📊 **Ensemble Voting** - Combines Random Forest + XGBoost for better accuracy
- 📈 **Feature Importance** - Analyzes which features matter most

## Installation

```bash
cd python ml
pip install -r requirements.txt
```

## Dataset Structure

### For Your Own Data

Place CSV files in `data/` directory:

```csv
# data/phishing_train.csv
url,label
https://google.com,0
http://phishing-site.tk/login,1
...

# Or with pre-extracted features:
url_length,num_dots,has_https,label
25,2,1,0
60,4,0,1
```

### Label Values
- `0` or `-1` = Legitimate/Safe
- `1` = Phishing/Malicious

## Dependencies

```
pandas>=1.5.0
numpy>=1.23.0
scikit-learn>=1.2.0
xgboost>=2.0.0
joblib>=1.3.0
requests>=2.28.0
python-dateutil>=2.8.0
kaggle>=1.5.0
```

## File Structure

```
phishing/
├── python ml/
│   ├── phishing_detector.py      # Main detection API
│   ├── train_models.py           # Model training
│   ├── dataset_loader.py         # Dataset loading
│   ├── generate_sample_data.py   # Sample data generator
│   ├── requirements.txt          # Dependencies
│   ├── README.md                # This file
│   ├── data/
│   │   ├── phishing_train.csv   # Sample (replace with real)
│   │   └── phishing_test.csv    # Sample (replace with real)
│   └── models/                  # Trained models
└── src/
```

## Kaggle API Setup

1. Go to [Kaggle Account](https://www.kaggle.com/account)
2. Click "Create New API Token"
3. Save to `~/.kaggle/kaggle.json`
4. Run: `loader.set_api_token()`

## Model Performance

| Model | Source Data | Accuracy |
|-------|-------------|----------|
| URL Scanner | Kaggle/UCI/Sample | 95-99% |
| Certificate Check | Sample/Real | 95-99% |
| Domain Lookup | Sample/Real | 95-99% |

## API Reference

### PhishingDetectorML

```python
detector = PhishingDetectorML()

# URL Analysis
result = detector.check_url("https://google.com")
# Returns: {'result': 'safe', 'confidence': 99.5, ...}

# Certificate Check
cert = detector.check_certificate({
    'is_valid': True,
    'days_until_expiry': 365,
    'key_size': 2048
})

# Domain Check
domain = detector.check_domain({
    'domain_age_days': 365,
    'country': 'US',
    'dnssec': True
})
```

## Summary: When to Use What

| Scenario | Dataset Source |
|----------|---------------|
| Quick testing | Sample data (auto) |
| Development | Kaggle API |
| Production | Your curated dataset |
| Research | UCI Repository |

**In production, replace sample data with real Kaggle or UCI datasets for better accuracy.**


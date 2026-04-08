
# PhishGuard - Advanced Phishing Detection System

[![React](https://img.shields.io/badge/React-19-green)](https://reactjs.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-blue)](https://spring.io/projects/spring-boot)
[![Python ML](https://img.shields.io/badge/Python-ML-orange)](https://python.org)

## Overview
PhishGuard is a full-stack phishing detection platform combining:
- **Frontend**: React 19 + Vite for responsive UI (auth, dashboard, URL/cert/domain scanning).
- **Backend**: Spring Boot 3.2 API with authentication, phishing detection services integrating Python ML models.
- **ML Pipeline**: Scikit-learn models trained on UCI/real datasets for URL, domain, certificate phishing analysis.
- **Key Features**: User auth (JWT), real-time scanning, model predictions via Python execution.

## Architecture
```
phishing/
├── backend/          # Spring Boot API (port 8081)
├── src/              # React frontend (port 5173)
├── datasets/         # Training data (UCI/real CSV/ARFF)
├── models/           # Joblib ML models (URL/domain/cert)
├── python ml/        # Training/detection scripts
└── Root configs/docs
```

## Quick Setup & Run
1. **Prerequisites**:
   ```
   Java 17+, Node.js 20+, Python 3.10+, MySQL (optional, H2 default)
   pip install -r python ml/requirements.txt  # scikit-learn, joblib, etc.
   ```

2. **Backend** (in `backend/`):
   ```
   mvn clean install
   mvn spring-boot:run
   ```
   - Config: `backend/src/main/resources/application.properties`
   - Endpoints: `/api/auth/register`, `/api/phishing/scan`, etc.

3. **Frontend** (root):
   ```
   npm install
   npm run dev
   ```

4. **Full Stack** (root):
   ```
   chmod +x run.sh
   ./run.sh
   ```

5. **ML Models** (if retrain):
   ```
   cd python ml/
   python train_with_real_data.py  # Or uci/train_realistic.py
   ```

## API Docs
- **Auth**: POST `/api/auth/register`, `/api/auth/login`
- **Scan**: POST `/api/phishing/url`, `/api/phishing/domain`, `/api/phishing/cert`
- **Swagger**: http://localhost:8081/swagger-ui.html (if enabled)

## Folder Structure
```
├── backend/src/main/java/com/phishguard/
│   ├── controller/    # REST APIs
│   ├── service/       # Business/ML logic
│   ├── security/      # JWT/Spring Security
│   └── entity/dto/    # Models/DTOs
├── src/components/    # UI pages (Login/Dashboard/Services)
├── src/contexts/      # AuthContext
├── models/            # Deployed .joblib files
└── datasets/          # Raw/processed data
```

## Security Notes\n- Copy `application-example.properties` → `application.properties` and set your DB creds.\n- Frontend API base: Set `VITE_API_URL` in `.env`.\n\n## Test Credentials (Development)\n- **Email**: test2@phishguard.com\n- **Password**: password123\n\nUse these to test login/register after backend restart. data.sql seeds test@phishguard.com (may need register for correct hash match).

## Troubleshooting
- CORS: Allowed `*` (prod: restrict).
- Python: Ensure `python3` path correct.
- DB: MySQL optional; uses H2 in-memory by default.

## License
MIT - Open source phishing protection.


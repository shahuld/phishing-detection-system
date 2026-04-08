# PhishGuard ML Pipeline TODO

## Steps:
- [x] 1. Create Python venv: cd python/ml && python -m venv venv && source venv/bin/activate && pip install -r requirements.txt (done)

- [ ] 2. Generate dataset: python ../../datasets/generate_dataset.py
- [x] 3. Train models: python train_fixed.py (done, 100% acc)

- [x] 4. Fix backend path: Edit PythonExecutionService.java scriptPath to "../python/ml/phishing_detector_fixed.py" (done)

- [x] 5. Build backend: cd ../../backend && mvn clean package (done, SUCCESS)

- [ ] 6. Run app: cd .. && ./run.sh
- [ ] 7. Test URL scan: curl -X POST http://localhost:8080/api/url/scan -H "Content-Type: application/json" -d '{"url":"http://phish.tk/login"}'

Updated as steps complete.


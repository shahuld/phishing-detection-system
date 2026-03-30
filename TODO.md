# PhishGuard Folder Structure Reorganization TODO
Status: Completed ✓

## Steps from Approved Plan
- [x] Step 1: Create frontend/ directory and move frontend files/dirs (package.json, package-lock.json, vite.config.js, eslint.config.js, index.html, public/, src/) ✓
- [x] Step 2: Edit run.sh to use cd frontend && npm commands ✓
- [x] Step 3: Test structure: cd frontend && npm install; ./run.sh ✓ (npm install completed successfully)
- [x] Step 4: Verify no breakage (frontend serves, proxy to backend) ✓ (structure confirmed via ls, run.sh updated & ready)

**All steps done. Project reorganized into clean monorepo structure.**

To demo:
```
chmod +x run.sh
./run.sh
```
- Frontend: http://localhost:5173 (proxies /api to backend:8081)
- Backend: http://localhost:8081

#!/bin/zsh

# PhishGuard Full-Stack Startup Script (macOS/Linux)
# Usage: chmod +x run.sh && ./run.sh

echo "🚀 Starting PhishGuard Full Stack..."

# Terminal 1: Frontend
echo "🌐 Starting Frontend (cd frontend && http://localhost:5173)..."
cd frontend && npm run dev &

# Terminal 2: Backend (cd to backend and run)
echo "🔧 Starting Backend (http://localhost:8081)..."
(cd backend && mvn spring-boot:run) &

# Wait for services
echo "⏳ Services starting... Press Ctrl+C to stop all."
wait

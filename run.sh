#!/bin/zsh
#
# PhishGuard Full Stack Startup - Fixed Version
# Usage: chmod +x run.sh && ./run.sh [stop|logs]
#

set -e

PHISH_DIR=$(pwd)
echo "🚀 PhishGuard Full Stack Startup from $PHISH_DIR"

setup_python_ml() {
  echo "🐍 Setting up Python ML..."
  cd "python ml"
  if [ ! -d "venv" ]; then
    python3 -m venv venv
  fi
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
  echo "✅ ML models ready at $(pwd)/models/ (skipping heavy test)"
  deactivate
  cd ..
  echo "✅ Python ML ready (models in python ml/models/)"
}

start_backend() {
  echo "🔧 Starting Backend (port 8081)..."
  cd backend
  mvn spring-boot:run &
  BACKEND_PID=$!
  cd ..
}

wait_backend_healthy() {
  echo "⏳ Waiting for backend healthy..."
  for i in {1..60}; do
    if curl -s http://localhost:8081/api/url/health | grep -q "running"; then
      echo "✅ Backend ready!"
      return 0
    fi
    sleep 3
  done
  echo "❌ Backend failed to start"
  return 1
}

start_frontend() {
  echo "🌐 Starting Frontend (http://localhost:5173)..."
  cd frontend
  npm install
  npm run dev &
  FRONTEND_PID=$!
  cd ..
}

stop_all() {
  echo "🛑 Stopping all services..."
  pkill -f "mvn spring-boot:run" || true
  pkill -f "npm run dev" || true
  sleep 2
}

case "$1" in
  "stop")
    stop_all
    exit 0
    ;;
  "logs")
    tail -f backend/target/spring-boot.log frontend/node_modules/.vite or similar
    ;;
  *)
    # Default: start
    setup_python_ml
    start_backend
    if wait_backend_healthy; then
      start_frontend
      echo "🎉 Full stack ready!"
      echo "🌐 Frontend: http://localhost:5173/services"
      echo "🔧 Backend: http://localhost:8081"
      echo "🛑 Stop: ./run.sh stop"
      wait
    else
      echo "Failed - check logs"
      exit 1
    fi
    ;;
esac


#!/usr/bin/env bash
# API(8010)와 화면(5173)을 한 번에 띄운다. 종료는 Ctrl+C.
set -euo pipefail
cd "$(dirname "$0")"

[ -x .venv/bin/python ] || { echo "먼저 ./setup.sh 를 실행하세요."; exit 1; }
[ -d frontend/node_modules ] || { echo "먼저 ./setup.sh 를 실행하세요."; exit 1; }

.venv/bin/python -m uvicorn main:app --app-dir backend --port 8010 &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null || true' EXIT INT TERM

echo "▶ 화면: http://localhost:5173   API: http://localhost:8010   (처음 한 번은 시작이 느릴 수 있어요)"
cd frontend && npm run dev

#!/usr/bin/env bash
# 처음 한 번만 실행: 가상환경(.venv)을 만들고 백엔드·프론트 의존성을 설치한다.
set -euo pipefail
cd "$(dirname "$0")"

# 분석 코드 위치: 환경 변수 → 저장소 구조(../haneium-project) → 작업 폴더 구조 순으로 찾는다.
PROJECT="${HANEIUM_PROJECT:-}"
if [ -z "$PROJECT" ]; then
  for candidate in ../haneium-project ../haneium-local-full/haneium-project; do
    if [ -f "$candidate/requirements-local.txt" ]; then PROJECT="$candidate"; break; fi
  done
fi
[ -n "$PROJECT" ] && [ -f "$PROJECT/requirements-local.txt" ] || {
  echo "haneium-project 를 찾을 수 없습니다. HANEIUM_PROJECT 에 폴더 경로를 지정하세요."; exit 1; }

# requirements-local.txt 의 고정 버전(numpy 2.5.4 등)은 Python 3.12 이상이 필요하다.
PY=""
for candidate in python3.14 python3.13 python3.12; do
  if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || { echo "Python 3.12 이상이 필요합니다.  brew install python@3.14"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Node.js(npm)가 필요합니다.  brew install node"; exit 1; }

echo "▶ 가상환경 생성 ($($PY --version))"
"$PY" -m venv .venv

echo "▶ 파이썬 패키지 설치"
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r "$PROJECT/requirements-local.txt" -r backend/requirements.txt

echo "▶ 프론트 패키지 설치"
(cd frontend && npm install --no-fund --no-audit)

echo
echo "✔ 준비 완료.  ./dev.sh 로 실행하세요."

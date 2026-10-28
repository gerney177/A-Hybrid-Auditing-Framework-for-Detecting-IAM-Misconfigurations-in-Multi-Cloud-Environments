# Hanium Web — IAM 위험 분석 대시보드 (Vue)

이전 Streamlit 대시보드를 대체하는 별도 프론트엔드입니다.
분석 코드는 그대로 두고, **얇은 API(FastAPI)** 가 결과를 내려주면 **Vue 화면**이 그립니다.

```
hanium-web/
├── backend/    FastAPI — hanium-project 의 분석 결과를 JSON 으로 제공
└── frontend/   Vue 3 + Vite + TypeScript + Tailwind v4 + ECharts
```

## 화면

| 화면 | 내용 |
|---|---|
| 개요 | KPI, 판정 분포, 클라우드별 판정, 위험 점수 순위(300개), 판정 근거·결정 신호, 우선 확인 대상, 개선 시뮬레이션, 분석 이력 |
| 대상 목록 | 검색·클라우드·판정 필터(주소에 저장돼 공유 가능), 정렬, 페이지, CSV |
| 대상 상세 | 판정 이유, **판정 경로**(어느 단계에서 결정됐는지), 점수 레이더, 정책(권한 연결 경로), 분석 근거, 원본 입력, 개선 권고·Terraform 초안 |
| AWS 정책 | 분석한 정책, 와일드카드·PassRole 검토 후보, 대상 유형·연결 방식 필터 |
| 역할 · 그룹 | 그룹 소속 사용자, 역할 전환 가능 사용자, 역할·그룹 정책 |

라이트/다크 모드, 모바일 폭을 지원합니다.

## 실행

`hanium-web` 폴더에서 실행합니다.

### 처음 한 번 — `./setup.sh`

```bash
cd hanium-web
./setup.sh
```

`.venv` 가상환경을 만들고 파이썬·프론트 패키지를 모두 설치합니다.
`hanium-project/requirements-local.txt` 의 고정 버전(numpy 2.5.4 등)이 **Python 3.12 이상**을 요구해서,
스크립트가 `python3.14 → 3.13 → 3.12` 순으로 찾아 씁니다. 시스템 기본 `python`(3.11)로는 설치되지 않아요.

### 실행 — `./dev.sh`

```bash
./dev.sh
```

API(8010)와 화면을 함께 띄웁니다. 브라우저에서 **http://localhost:5173** 을 여세요. 종료는 `Ctrl+C`.
`127.0.0.1:5173` 은 열리지 않으니 `localhost` 로 접속하세요. (첫 실행은 패키지 로딩 때문에 API 시작이 느릴 수 있습니다.)

<details>
<summary>수동으로 실행하려면</summary>

```bash
# 터미널 1 — API (반드시 .venv 의 파이썬으로)
.venv/bin/python -m uvicorn main:app --app-dir backend --port 8010

# 터미널 2 — 화면 (/api 는 8010 으로 프록시)
cd frontend && npm run dev
```
</details>

### 하나로 실행 (빌드 후)

```bash
(cd frontend && npm run build)      # frontend/dist 생성
.venv/bin/python -m uvicorn main:app --app-dir backend --port 8010
# → http://localhost:8010 에서 API 와 화면을 함께 제공
```

### 설정

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `HANIUM_PROJECT` | `../hanium-project` | 분석 코드가 있는 폴더 |
| `API_TARGET` | `http://127.0.0.1:8010` | (프론트 개발 서버) API 주소 |

## API

모든 응답은 JSON이며 키는 `snake_case` 입니다. 대화형 문서: `/api/docs`

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/overview` | 요약·집계·개선 시뮬레이션 |
| GET | `/api/model` | 판정 가중치·임계값(코드의 값을 그대로) |
| GET | `/api/identities` | 300개 대상 목록 |
| GET | `/api/identities/{name}` | 한 대상의 입력·정책·단계별 근거·개선안 |
| GET | `/api/aws` | AWS 정책 분석 결과 |
| GET | `/api/access` | 역할·그룹 |
| GET | `/api/remediations` | 개선 권고와 효과 |
| GET | `/api/runs` | 저장된 분석 이력 |
| POST | `/api/runs` | **분석을 다시 실행하고 DB 에 저장** |
| GET | `/api/export/report.json` · `identities.csv` | 내려받기 |

- 조회(GET)는 `validation/reports/mock300-analysis-report.json` 을 **읽기만** 합니다.
  이 파일이 없으면(저장소를 처음 받은 상태) 첫 조회 때 한 번 분석해서 만들어요. DB 에는 저장하지 않습니다.
- 분석 실행·DB 저장은 `POST /api/runs` 에서만 일어납니다(Streamlit 의 `전체 분석 실행·저장`과 같음). 약 2초.
  `data/iam.db` 는 없으면 이때 만들어집니다.

## 문제 해결

| 증상 | 원인 · 해결 |
|---|---|
| `No module named 'fastapi'` | 시스템 파이썬으로 실행한 경우입니다. `./setup.sh` 후 `./dev.sh` 로 실행하세요. |
| `numpy==2.5.4` 를 찾을 수 없음 | Python 3.11 이하입니다. 3.12 이상을 설치하세요 (`brew install python@3.14`). |
| `127.0.0.1:5173` 이 안 열림 | Vite 는 `localhost` 로만 열립니다. `http://localhost:5173` 으로 접속하세요. |
| 화면에 "API 서버에 연결할 수 없습니다" | API(8010)가 꺼져 있거나 아직 시작 중입니다. 터미널의 uvicorn 로그를 확인하세요. |
| `address already in use` | 8010 또는 5173 을 다른 프로세스가 쓰고 있습니다. `lsof -iTCP:8010 -sTCP:LISTEN` 으로 확인하세요. |

## 알아둘 점

- **TypeScript 5.9 고정**: `vue-tsc` 가 아직 TypeScript 7 과 호환되지 않아 5.9 로 맞췄습니다.
- **Streamlit 에 있었지만 아직 옮기지 않은 것**: AWS 화면의 `AWS 분석 결과 저장`과 `저장된 AWS 분석` 선택.
- 개선 권고 문장과 Terraform 초안은 분석 코드가 만든 영어 원문을 그대로 보여줍니다.
- 모든 데이터는 Mock 이며, 화면에도 그렇게 표시합니다.

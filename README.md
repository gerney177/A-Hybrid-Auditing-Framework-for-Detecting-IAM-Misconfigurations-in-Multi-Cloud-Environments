# Hanium — 멀티 클라우드 IAM 자동 감사 플랫폼

**AI 처리 전 단계 클라우드 에이전트의 계정 및 권한 오류 자동 감사 플랫폼** (한이음 드림업 프로젝트)

AWS·Azure·GCP의 IAM 정책을 하나의 기준으로 정규화하고, **규칙 · 행동 이상 탐지 · 권한 그래프** 세 계층으로 분석합니다.
대상마다 `ALLOW / ALERT / BLOCK` 판정과 그 근거, 최소 권한 개선안을 내놓고, 개선안을 가상으로 적용해 위험도가 얼마나 줄어드는지까지 다시 분석합니다.

![개요 화면](docs/screenshots/overview.png)

<table>
  <tr>
    <td><img src="docs/screenshots/identity-detail.png" alt="대상 상세 — 판정 경로와 정책"></td>
    <td><img src="docs/screenshots/overview-dark.png" alt="개요 — 다크 모드"></td>
  </tr>
</table>

> **데이터 안내** — 화면의 분석 대상 300개는 **Mock 데이터**입니다(AWS·Azure·GCP 각 100개, 시드 42, 논문 실험의 25개 포함).
> 실제 운영 계정의 데이터가 아니며, 결과가 실제 계정의 안전성이나 탐지 정확도를 보증하지 않습니다.

## 왜 만들었나

- **AI는 혼자 움직이지 않습니다.** 데이터를 모으고 정리하는 수많은 자동화 에이전트(서비스 계정, API 키 같은 비인간 식별자)와 함께 동작하고,
  이들의 권한이 필요 이상으로 넓으면 데이터 유출이나 학습 데이터 오염으로 이어집니다. 그래서 **AI가 데이터를 처리하기 전 단계에서** 에이전트의 계정·권한 설정 오류를 먼저 감사합니다.
- **클라우드마다 정책 체계가 다릅니다.** AWS는 JSON 정책 문서, Azure는 역할 정의 기반 RBAC, GCP는 역할 바인딩을 써서 하나의 기준으로 감사하기 어렵습니다.
- **LLM 진단만으로는 조치를 믿기 어렵습니다.** 환각으로 잘못된 권고가 나올 수 있어서, AI가 판단하기 전에 **검증 가능한 사실을 먼저 확정**하는 하이브리드 구조를 택했습니다.

## 접근 방식

정책 정규화 → 세 계층 병렬 분석 → 통합 판정 → 조치 생성·시뮬레이션 → 재분석, 5단계 파이프라인입니다(`hanium-project/pipeline.py`의 `run_pipeline()`).

**① 통합 정규화** — 클라우드별 정책을 주체(`identity`), 행위 의도(`operation`), 자원 범위(`target`), 허용 여부(`effect`), 와일드카드 여부(`is_wildcard`), 클라우드(`source_csp`)로 변환합니다.
`operation`은 READ·CREATE·MANAGE 등 행위 의도로 통일하고, 대응표에 없는 액션은 허용으로 간주하지 않고 `UNKNOWN` 위험 신호로 다룹니다(fail-safe defaults).

**② 세 계층 분석** — 각 점수는 0~1입니다.

| 점수 | 내용 |
|---|---|
| 규칙 **R** | 발동한 규칙의 심각도 합(최대 1.0), 대상별 최댓값. `NO_ROOT_KEY` 1.0 · `NO_WILDCARD` 0.6 · `MFA_REQUIRED` 0.5 · `API_KEY_NO_MFA` 0.4. 단일 규칙으로 1.0이 되는 것은 root 키뿐 |
| 행동 이상 **A** | 로그인 시각·API 호출 수·로그인 실패 수로 Isolation Forest(트리 200개, 오염도 0.08, 시드 42)를 학습하고, 이상 점수를 모집단의 최솟값·최댓값으로 정규화. **모집단 안에서의 상대 점수**라서 모집단이 바뀌면 값도 달라집니다 |
| 권한 그래프 **G** | 정책을 `identity → target` 방향 그래프로 바꿔 와일드카드·`UNKNOWN`·권한 상승 벡터의 개수를 세고 `min(1, 개수/3)`. 권한 상승 벡터는 `iam:PassRole`·`iam:PutRolePolicy`·`iam:CreateAccessKey`(AWS), `roleAssignments/write`(Azure), `setIamPolicy`(GCP) |

**③ 통합 판정** — 위에서부터 차례로 확인하고, 처음 해당하는 단계에서 결정됩니다.

1. `R ≥ 1.0` → **BLOCK**
2. `0.5·R + 0.3·A + 0.2·G ≥ 0.5` → **ALERT**
3. `A ≥ 0.8` → **ALERT** (행동 이상 단독)
4. `G ≥ 0.6` → **ALERT** (권한 그래프 단독 — 2건 이상의 신호)
5. 그 외 → **ALLOW**

가중합에서 묻혀 버리는 한 계층의 강한 신호를 3·4번 단독 승격 경로가 살려 줍니다. 가중치와 임계값은 경험적으로 정한 값입니다.

**④⑤ 조치와 재분석** — BLOCK·ALERT 대상에 정책 조치(액션 제거, 범위 축소)와 MFA 활성화 조치를 만들고(AWS는 Terraform 정책 초안), 행동 이상만 근거인 대상은 수동 조사로 분류합니다.
조치는 **복제본에 가상으로 적용**한 뒤 같은 파이프라인으로 다시 분석해 위험도 변화를 봅니다. 실제 클라우드 권한은 바꾸지 않아요.

## 논문 실험 재현

논문의 25개 식별자(AWS 9 · Azure 8 · GCP 8, 정책 25건 → 정규화 레코드 38건) 실험은 현재 코드로 재현됩니다.

| 항목 | 결과 |
|---|---|
| 판정 | BLOCK 1 · ALERT 4 · ALLOW 20 |
| 조치 대상 | 5개 — 이 중 행동 이상만 근거인 1개는 수동 조사로 분리하고 4개에 조치 적용 |
| 조치 후 평균 위험도 | 0.450 → 0.096 (78.7% 감소) |
| 단독 승격 | 행동 이상 A ≥ 0.8: `developer01`, `serviceaccount01` · 그래프 G ≥ 0.6: `developer01`, `auditor01`, `dataanalyst01` |

```bash
cd hanium-project
../hanium-web/.venv/bin/python - <<'EOF'      # ./setup.sh 로 만든 가상환경
import contextlib, io, json
import pandas as pd
from pipeline import run_pipeline

base = json.load(open("data/mock25_extended.json", encoding="utf-8"))["baseline_input"]   # 논문의 25개 식별자
data = {**base, "metadata": pd.DataFrame(base["metadata"]), "behavior": pd.DataFrame(base["behavior"])}
with contextlib.redirect_stdout(io.StringIO()):          # 노트북 시절의 진행 출력을 숨긴다
    state = run_pipeline(data=data)

print(state["integrated_risk_df"]["final_action"].value_counts().to_dict())
applied = state["remediation_effect_df"].query("remediation_applied")
print(f"평균 위험도 {applied.before_risk_score.mean():.3f} → {applied.after_risk_score.mean():.3f}")
EOF
```

현재 화면의 Mock 300개는 **BLOCK 1 · ALERT 47 · ALLOW 252**입니다. 25개를 포함하지만 행동 이상 점수 A가 모집단 상대 점수라서, 25개만 분석할 때와 개별 점수는 다를 수 있어요.

## 구현 범위와 한계

| 구분 | 내용 |
|---|---|
| 구현 | Mock AWS·Azure·GCP 정규화, 규칙·행동 이상·권한 그래프 분석, 통합 판정, 조치 계획과 가상 적용·재분석, 대시보드, SQLite 이력 저장 |
| 별도 흐름 | 실제 AWS IAM 수집과 정책 검사(사용자·그룹·역할 정책의 와일드카드·`iam:PassRole` 검토 후보). 통합 위험 점수에는 연결하지 않았고, 후보는 위험 확정이 아니라 검토 대상입니다 |
| 아직 없음 | 실제 행동 로그 기반 이상 탐지, 실제 AWS 데이터의 통합 분석, 실효 권한 평가(명시적 Deny·권한 경계·SCP·리소스 정책·역할 신뢰 정책), 다단계 권한 상승(role chaining) 경로 탐지, Azure·GCP 실계정 연동 |
| 설계에는 있으나 미구현 | 이상 탐지 알고리즘 확장(LOF·One-Class SVM — 현재는 Isolation Forest만), CloudFormation 스크립트(현재는 Terraform 초안만) |

실험의 한계: 모의 데이터와 경험적 가중치를 썼고, 행동 이상 점수는 상대 점수입니다. 실제 데이터 기반 가중치 조정과 이상 점수 정규화 개선이 향후 과제예요.

## 화면 설계의 배경

사용자 설문(28명)과 인터뷰(4명)에서 공통으로 나온 요구를 화면에 반영했습니다.

- **탐지 근거를 함께 보여 달라** → 대상 상세의 *왜 ALERT인가요?* 와 **판정 경로**(어느 단계에서 결정됐는지, 점수와 임계값 비교)
- **자동 조치는 관리자 승인 후에** → 개선 권고와 Terraform은 **초안**으로만 제공하고 실제 권한은 바꾸지 않음

## 구성

| 폴더 | 내용 |
|---|---|
| [`hanium-project/`](hanium-project) | 분석 엔진 — 정책 정규화, 규칙, 행동 이상 탐지, 권한 그래프, 통합 판정, 개선 시뮬레이션, 데이터·검증 코드 |
| [`hanium-web/`](hanium-web) | 대시보드 — FastAPI(백엔드) + Vue 3(프론트). 자세한 내용은 [hanium-web/README.md](hanium-web/README.md) |

## 빠른 시작

필요한 것: **Python 3.12 이상**(고정 버전 numpy 2.5.4 때문), **Node.js 20.19 이상**

```bash
cd hanium-web
./setup.sh     # 가상환경(.venv)과 패키지 설치 — 처음 한 번
./dev.sh       # API(8010) + 화면(5173) 실행
```

브라우저에서 **http://localhost:5173** 을 엽니다. 저장소를 처음 받은 상태라면 첫 접속 때 분석이 한 번 자동으로 실행돼요(몇 초 걸립니다).
화면 위쪽의 **분석 실행·저장**을 누르면 다시 분석하고 `hanium-project/data/iam.db`에 이력을 저장합니다.

## 테스트

```bash
cd hanium-project
../hanium-web/.venv/bin/python -m unittest \
  checks.check_aws_role_policies checks.check_aws_group_policies checks.check_policy_validation
```

60개 중 59개가 통과하고 1개는 건너뜁니다. 건너뛰는 테스트는 실제 AWS 수집본(`data/aws_iam_snapshot.json`)이 있을 때만 실행돼요.

## 커밋하면 안 되는 것

- **`hanium-project/data/aws_iam_snapshot.json`** — 실제 AWS 계정에서 수집한 원본입니다(계정 ID 포함). `.gitignore`에 등록돼 있지만, 직접 만들었다면 올라가지 않았는지 확인하세요.
- AWS 자격 증명(액세스 키 등) — `data/aws_collector.py`로 실제 수집할 때만 필요하며 코드나 문서에 적지 마세요.
- `data/iam.db`, `validation/reports/` 안의 결과 파일 — 실행하면 생기는 파일이라 `.gitignore`로 제외했습니다.

## 더 읽을 것

- [`hanium-project/MOCK300_GUIDE.md`](hanium-project/MOCK300_GUIDE.md) — 300개 Mock 구성
- [`hanium-project/EXTENDED25_GUIDE.md`](hanium-project/EXTENDED25_GUIDE.md) — 기존 25개에 역할·그룹을 더한 단계
- [`hanium-project/POLICY_VALIDATION_GUIDE.md`](hanium-project/POLICY_VALIDATION_GUIDE.md) — 정책 사례 검증
- [`hanium-project/LOCAL_CHANGES.md`](hanium-project/LOCAL_CHANGES.md), [`hanium-project/README`](hanium-project/README) — 개발 기록.
  이 기록에는 이전의 Streamlit 대시보드 설명이 남아 있어요. Streamlit 화면은 Vue 화면으로 대체되어 이 저장소에 포함하지 않았습니다.
- [`hanium-project/notebooks/hanium_original.ipynb`](hanium-project/notebooks/hanium_original.ipynb) — 원본 Colab 코드

## 지원

본 프로젝트는 과학기술정보통신부 대학디지털교육역량강화사업의 지원을 통해 수행한 한이음 드림업 프로젝트 결과물입니다.

"""Vue 프론트용 API.

분석 로직은 hanium-project 의 코드를 그대로 가져다 쓰고, 이 파일은
저장된 분석 보고서를 화면에 맞는 모양으로 바꿔서 내려주는 역할만 한다.
조회(GET)는 보고서 파일을 읽기만 하며, 분석 실행·DB 저장은 POST /api/runs 에서만 일어난다.
"""
from __future__ import annotations

import math
import os
import sys
import threading
from collections import Counter
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def find_project() -> Path:
    """분석 코드(hanium-project) 위치. 환경 변수가 있으면 그 경로, 없으면 저장소 구조(../hanium-project)."""
    env = os.environ.get("HANIUM_PROJECT")
    candidates = [Path(env)] if env else [ROOT / "hanium-project"]
    for candidate in candidates:
        if (candidate / "analysis").is_dir():
            return candidate.resolve()
    raise SystemExit(
        "hanium-project 를 찾을 수 없습니다. 찾아본 위치:\n  "
        + "\n  ".join(str(c) for c in candidates)
        + "\n환경 변수 HANIUM_PROJECT 에 hanium-project 폴더 경로를 지정하세요."
    )


PROJECT = find_project()
sys.path.insert(0, str(PROJECT))

import json  # noqa: E402

try:
    import pandas as pd  # noqa: E402
    from fastapi import FastAPI, HTTPException  # noqa: E402
    from fastapi.responses import FileResponse, JSONResponse, Response  # noqa: E402
    from fastapi.staticfiles import StaticFiles  # noqa: E402

    from analysis.current_dataset import REPORT_PATH, run_current_analysis  # noqa: E402
    from analysis.hybrid import MergeModule, RuleEngine  # noqa: E402
    from data import storage  # noqa: E402
except ModuleNotFoundError as error:
    raise SystemExit(
        f"필요한 패키지가 없습니다: {error.name}\n"
        f"지금 쓰는 Python: {sys.executable} ({sys.version.split()[0]})\n"
        "hanium-web 폴더에서 ./setup.sh 를 한 번 실행한 뒤 ./dev.sh 로 시작하세요.\n"
        "(고정 버전 numpy 2.5.4 는 Python 3.12 이상에서만 설치됩니다.)"
    ) from error

DIST = HERE.parent / "frontend" / "dist"
VERDICTS = ("BLOCK", "ALERT", "ALLOW")

app = FastAPI(title="Hanium IAM API", docs_url="/api/docs", openapi_url="/api/openapi.json")
run_lock = threading.Lock()


# ── 공통 도구 ────────────────────────────────────────────────────────────────

def clean(value):
    """NaN/Infinity 는 JSON 으로 내보낼 수 없으므로 None 으로 바꾼다."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    return value


class Report:
    """보고서 파일을 읽어 두고, 파일이 바뀌면 다시 읽는다."""

    def __init__(self):
        self._mtime = None
        self._data = None
        self._lock = threading.Lock()

    @staticmethod
    def _ensure_file() -> None:
        """결과 파일이 없으면(저장소를 막 받은 상태) 한 번 분석해서 만든다. DB 에는 저장하지 않는다."""
        if REPORT_PATH.exists():
            return
        with run_lock:  # 분석 실행 중이면 끝나길 기다린다
            if REPORT_PATH.exists():
                return
            try:
                REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
                run_current_analysis(save=False)
            except Exception as error:  # noqa: BLE001
                raise HTTPException(500, f"첫 분석을 만들지 못했습니다: {type(error).__name__} · {error}") from error

    def get(self) -> dict:
        self._ensure_file()
        mtime = REPORT_PATH.stat().st_mtime_ns
        with self._lock:
            if mtime != self._mtime:
                self._data = self._index(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
                self._mtime = mtime
            return self._data

    @staticmethod
    def _index(report: dict) -> dict:
        stages = report["stages"]
        integrated = {r["identity"]: r for r in stages["integrated_risk_df"]}
        rows = []
        for r in report["identities"]:
            extra = integrated.get(r["대상"], {})
            rows.append(
                {
                    "name": r["대상"],
                    "cloud": r["클라우드"],
                    "verdict": r["판정"],
                    "risk_score": r["위험 점수"],
                    "rule_score": r["규칙 R"],
                    "anomaly_score": r["행동 이상 A"],
                    "graph_score": r["그래프 G"],
                    "groups": r["소속 그룹"],
                    "role_assignments": r["전환 역할 설정"],
                    "reasons": r["판정 근거"],
                    "decision_by": extra.get("decision_by"),
                    "is_anomaly": bool(extra.get("is_anomaly")),
                    "graph_finding_count": extra.get("graph_finding_count", 0),
                    "raw_privilege_finding_count": extra.get("raw_privilege_finding_count", 0),
                }
            )
        ranked = sorted(rows, key=lambda x: x["risk_score"], reverse=True)
        for position, row in enumerate(ranked, start=1):
            row["rank"] = position
        return {"report": report, "rows": rows}


report_store = Report()


def current() -> tuple[dict, list[dict]]:
    data = report_store.get()
    return data["report"], data["rows"]


def by_identity(rows: list[dict], name: str) -> list[dict]:
    return [r for r in rows if r.get("identity") == name]


# ── 조회 ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"ok": True, "has_report": REPORT_PATH.exists(), "running": run_lock.locked()}


@app.get("/api/model")
def model():
    """판정에 쓰는 가중치·임계값. 화면의 '판정 경로' 설명이 코드의 값과 어긋나지 않도록 코드에서 읽는다."""
    return {
        "weights": {"rule": MergeModule.W_RULE, "ai": MergeModule.W_AI, "graph": MergeModule.W_GRAPH},
        "threshold": MergeModule.THRESHOLD,
        "ai_alert": MergeModule.AI_ALERT_SCORE,
        "graph_alert": MergeModule.GRAPH_ALERT_SCORE,
        "rules": [{"name": name, "severity": severity} for name, _, severity in RuleEngine.RULES],
    }


@app.get("/api/overview")
def overview():
    report, rows = current()
    stages = report["stages"]

    verdict_by_cloud: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = verdict_by_cloud.setdefault(row["cloud"], dict.fromkeys(VERDICTS, 0))
        bucket[row["verdict"]] += 1

    bins = []
    for i in range(10):
        low, high = i / 10, (i + 1) / 10
        bucket = dict.fromkeys(VERDICTS, 0)
        for row in rows:
            score = row["risk_score"]
            if low <= score < high or (i == 9 and score == 1.0):
                bucket[row["verdict"]] += 1
        bins.append({"from": low, "to": high, **bucket})

    reasons = Counter(code for row in rows for code in row["reasons"])
    effects = stages["remediation_effect_df"]
    applied = [e for e in effects if e.get("remediation_applied")]
    plans = stages["remediation_plan_df"]

    remediation = {
        "planned": len(plans),
        "applied": len(applied),
        "action_changed": sum(1 for e in applied if e.get("action_changed")),
        "risk_improved": sum(1 for e in applied if e.get("risk_improved")),
        "avg_before": _mean([e["before_risk_score"] for e in applied]),
        "avg_after": _mean([e["after_risk_score"] for e in applied]),
        "by_type": dict(Counter(p["remediation_type"] for p in plans)),
        "after_verdicts": dict(Counter(r["final_action"] for r in stages["post_integrated_risk_df"])),
    }

    return clean(
        {
            "executed_at": report["executed_at"],
            "dataset_version": report["dataset_version"],
            "source": report["source"],
            "run_id": report.get("run_id"),
            "dataset_id": report.get("dataset_id"),
            "seed": report["input"].get("seed"),
            "summary": report["summary"] | {"total": report["summary"]["users"]},
            "verdict_by_cloud": verdict_by_cloud,
            "score_bins": bins,
            "reasons": [{"code": c, "count": n} for c, n in reasons.most_common()],
            "decision_by": dict(Counter(row["decision_by"] for row in rows)),
            "top_risk": [r for r in sorted(rows, key=lambda x: x["rank"]) if r["verdict"] != "ALLOW"][:8],
            "remediation": remediation,
            "notes": report["notes"],
        }
    )


def _mean(values: list[float]):
    return sum(values) / len(values) if values else None


@app.get("/api/identities")
def identities():
    return clean(current()[1])


@app.get("/api/identities/{name}")
def identity_detail(name: str):
    report, rows = current()
    row = next((r for r in rows if r["name"] == name), None)
    if row is None:
        raise HTTPException(404, f"대상을 찾을 수 없습니다: {name}")

    stages = report["stages"]
    source = report["input"]
    metadata = next((m for m in source["metadata"] if m["identity"] == name), None)
    behavior = next((b for b in source["behavior"] if b["identity"] == name), None)
    same_cloud = [b for b in source["behavior"] if b["cloud_provider"] == row["cloud"]]

    # 그룹 경유 정책은 본문이 그룹에 들어 있으므로 화면에서 보여줄 수 있게 붙여 준다.
    groups = {g["GroupName"]: g for g in source["aws_snapshot"]["groups"]}
    aws_items = []
    for item in report["aws_analysis"]["policy_items"]:
        if item.get("identity_name") != name:
            continue
        item = dict(item)
        if item.get("attachment_type") == "group" and "raw_policy_document" not in item:
            group = groups.get(item.get("group_name"), {})
            doc = next(
                (p["PolicyDocument"] for p in group.get("GroupPolicyList", []) if p["PolicyName"] == item["policy_name"]),
                None,
            )
            item["raw_policy_document"] = doc
        aws_items.append(item)

    return clean(
        {
            "identity": row,
            "total": len(rows),
            "metadata": metadata,
            "behavior": behavior,
            "population": {
                "api_call_median": median(b["api_call_count"] for b in same_cloud),
                "failed_login_median": median(b["failed_login_count"] for b in same_cloud),
                "cloud": row["cloud"],
                "size": len(same_cloud),
            },
            "policies": by_identity(source["policies"], name),
            "aws_policy_items": aws_items,
            "rules": next(iter(by_identity(stages["rule_identity_summary_df"], name)), None),
            "ai": next(iter(by_identity(stages["ai_analysis_df"], name)), None),
            "graph_summary": next(iter(by_identity(stages["graph_identity_summary_df"], name)), None),
            "graph_findings": by_identity(stages["graph_findings_df"], name),
            "raw_privilege_findings": by_identity(stages["raw_privilege_findings_df"], name),
            "integrated": next(iter(by_identity(stages["integrated_risk_df"], name)), None),
            "remediation_plan": next(iter(by_identity(stages["remediation_plan_df"], name)), None),
            "remediation_effect": next(iter(by_identity(stages["remediation_effect_df"], name)), None),
        }
    )


@app.get("/api/aws")
def aws():
    report, _ = current()
    analysis = report["aws_analysis"]
    snapshot = report["input"]["aws_snapshot"]
    items = analysis["policy_items"]
    return clean(
        {
            "analysis_scope": analysis["analysis_scope"],
            "collected_at": analysis["collected_at"],
            "source": snapshot.get("source"),
            "counts": {
                "users": len(snapshot["users"]),
                "roles": len(snapshot["roles"]),
                "groups": len(snapshot["groups"]),
                "policy_bodies": len(items),
                "role_policy_bodies": sum(i.get("identity_type") == "role" for i in items),
                "group_policy_links": sum(i.get("attachment_type") == "group" for i in items),
                "wildcard": len(analysis["wildcard_findings"]),
                "passrole": len(analysis["passrole_findings"]),
            },
            "policy_items": [{k: v for k, v in i.items() if k != "raw_policy_document"} for i in items],
            "wildcard_findings": analysis["wildcard_findings"],
            "passrole_findings": analysis["passrole_findings"],
        }
    )


@app.get("/api/access")
def access():
    report, _ = current()
    snapshot = report["input"]["aws_snapshot"]
    analysis = report["aws_analysis"]
    assignments = report["role_assignments"]

    roles = []
    for role in snapshot["roles"]:
        trusted = []
        for statement in role["AssumeRolePolicyDocument"].get("Statement", []):
            principal = statement.get("Principal", {}).get("AWS", [])
            trusted += [principal] if isinstance(principal, str) else list(principal)
        roles.append(
            {
                "name": role["RoleName"],
                "arn": role["Arn"],
                "assumable_by": sorted(a["user"] for a in assignments if a["role"] == role["RoleName"]),
                "trusted_principals": trusted,
                "policies": [{"name": p["PolicyName"], "document": p["PolicyDocument"]} for p in role["RolePolicyList"]],
                "wildcard_count": sum(f["identity"] == role["Arn"] for f in analysis["wildcard_findings"]),
                "passrole_count": sum(f["identity"] == role["Arn"] for f in analysis["passrole_findings"]),
            }
        )

    groups = []
    for group in snapshot["groups"]:
        members = sorted(u["UserName"] for u in snapshot["users"] if group["GroupName"] in u["GroupList"])
        groups.append(
            {
                "name": group["GroupName"],
                "arn": group["Arn"],
                "members": members,
                "policies": [{"name": p["PolicyName"], "document": p["PolicyDocument"]} for p in group["GroupPolicyList"]],
            }
        )
    return clean({"roles": roles, "groups": groups, "assignment_count": len(assignments)})


@app.get("/api/remediations")
def remediations():
    report, rows = current()
    stages = report["stages"]
    effects = {e["identity"]: e for e in stages["remediation_effect_df"]}
    plans = [{**p, "effect": effects.get(p["identity"])} for p in stages["remediation_plan_df"]]
    return clean(plans)


@app.get("/api/runs")
def runs():
    frame = storage.list_analysis_runs()
    return clean(frame.to_dict("records"))


# ── 실행·내려받기 ─────────────────────────────────────────────────────────────

@app.post("/api/runs")
def run_analysis():
    """300개 전체 분석을 다시 실행하고 DB 에 저장한다(Streamlit 의 '전체 분석 실행·저장'과 같음)."""
    if not run_lock.acquire(blocking=False):
        raise HTTPException(409, "이미 분석이 실행 중입니다.")
    try:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        report = run_current_analysis(save=True)
    except Exception as error:  # noqa: BLE001 - 화면에 원인을 그대로 보여준다
        raise HTTPException(500, f"분석 실행 오류: {type(error).__name__} · {error}") from error
    finally:
        run_lock.release()
    return clean(
        {
            "executed_at": report["executed_at"],
            "run_id": report.get("run_id"),
            "dataset_id": report.get("dataset_id"),
            "verdicts": report["summary"]["verdicts"],
        }
    )


@app.get("/api/export/report.json")
def export_report():
    current()
    return FileResponse(REPORT_PATH, media_type="application/json", filename="mock300-analysis-report.json")


@app.get("/api/export/identities.csv")
def export_csv():
    report, _ = current()
    body = pd.DataFrame(report["identities"]).to_csv(index=False).encode("utf-8-sig")
    return Response(
        body,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="mock300-analysis.csv"'},
    )


@app.exception_handler(HTTPException)
async def http_error(_, error: HTTPException):
    return JSONResponse({"detail": error.detail}, status_code=error.status_code)


# ── 빌드된 프론트 서빙(frontend/dist 가 있을 때만) ─────────────────────────────

if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Not found")
        target = (DIST / path).resolve()
        if path and target.is_file() and DIST in target.parents:
            return FileResponse(target)
        return FileResponse(DIST / "index.html")

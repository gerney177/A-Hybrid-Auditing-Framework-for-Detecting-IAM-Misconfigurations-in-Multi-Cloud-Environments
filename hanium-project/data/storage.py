#수집 당시의 정책,메타데이터, 행동데이터를 하나의 묶음으로 보존하는 테이블
# data/storage.py
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pandas as pd


# 실행 위치와 관계없이 프로젝트의 data 폴더에 저장
DB_PATH = Path(__file__).resolve().parent / "iam.db"


def dataframe_to_records(df):
    """DataFrame의 결측값을 None으로 바꾸고 목록으로 변환."""
    cleaned = df.astype(object)
    cleaned = cleaned.where(pd.notna(cleaned), None)
    return cleaned.to_dict(orient="records")


def save_dataset(data, source):
    """입력 데이터 전체를 저장하고 데이터 ID를 반환."""
    payload = {
        "policies": data["policies"],
        "metadata": dataframe_to_records(data["metadata"]),
        "behavior": dataframe_to_records(data["behavior"]),
    }
    # Preserve added topology alongside the same 25 identities when saving.
    for key in ('baseline_dataset_id','baseline_input','source','aws_snapshot','role_assignments','changes','notes','seed','dataset_version'):
        if key in data:
            payload[key] = data[key]

    # DB에 쓰기 전에 JSON 변환이 가능한지 확인
    #payload_Json:그 시점의 입력 데이터 전체
    payload_json = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
    )

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS datasets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
        """)

        cursor = connection.execute(
            """
            INSERT INTO datasets (source, payload_json)
            VALUES (?, ?)
            """,
            (source, payload_json),
        )#source: mock,json,aws 등 데이터 출처

        dataset_id = cursor.lastrowid

    return dataset_id


def load_dataset(dataset_id):
    """저장된 데이터를 기존 분석 함수의 입력 형식으로 복원."""
    if not DB_PATH.exists():
        raise FileNotFoundError("DB가 없습니다. 먼저 데이터를 저장하세요.")

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        row = connection.execute(
            "SELECT payload_json FROM datasets WHERE id = ?",
            (dataset_id,),
        ).fetchone()

    if row is None:
        raise ValueError(f"저장된 데이터가 없습니다: {dataset_id}")

    payload = json.loads(row[0])

    return {
        **payload,
        "policies": payload["policies"],
        "metadata": pd.DataFrame(payload["metadata"]),
        "behavior": pd.DataFrame(payload["behavior"]),
    }
def save_analysis_run(dataset_id, state):
    """분석 결과를 입력 데이터 ID와 연결해 저장."""
    result_keys = [
        "integrated_risk_df",
        "post_integrated_risk_df",
        "remediation_plan_df",
        "remediation_effect_df",
    ]

    results = {
        key: dataframe_to_records(state[key])
        for key in result_keys
    }

    results_json = json.dumps(
        results,
        ensure_ascii=False,
        allow_nan=False,
    )

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                results_json TEXT NOT NULL,
                FOREIGN KEY (dataset_id) REFERENCES datasets(id)
            )
        """)

        cursor = connection.execute(
            """
            INSERT INTO analysis_runs (dataset_id, results_json)
            VALUES (?, ?)
            """,
            (dataset_id, results_json),
        )

        run_id = cursor.lastrowid

    return run_id


def list_analysis_runs():
    """최근 분석 실행부터 목록을 반환."""
    columns = ["run_id", "dataset_id", "created_at", "source"]

    if not DB_PATH.exists():
        return pd.DataFrame(columns=columns)

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        table_exists = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'analysis_runs'
            """
        ).fetchone()

        if table_exists is None:
            return pd.DataFrame(columns=columns)

        return pd.read_sql_query(
            """
            SELECT
                r.id AS run_id,
                r.dataset_id,
                r.created_at,
                d.source
            FROM analysis_runs AS r
            JOIN datasets AS d ON d.id = r.dataset_id
            ORDER BY r.id DESC
            """,
            connection,
        )
def load_analysis_run(run_id):
    """저장된 분석 결과를 조회한다."""
    if not DB_PATH.exists():
        raise FileNotFoundError("DB가 없습니다.")

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        row = connection.execute(
            """
            SELECT dataset_id, created_at, results_json
            FROM analysis_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

    if row is None:
        raise ValueError(f"저장된 분석 실행이 없습니다: {run_id}")

    results = json.loads(row[2])

    return {
        "run_id": run_id,
        "dataset_id": row[0],
        "created_at": row[1],
        "results": {
            key: pd.DataFrame(records)
            for key, records in results.items()
        },
    }
def ensure_aws_analysis_table(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS aws_policy_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            snapshot_json TEXT NOT NULL,
            results_json TEXT NOT NULL
        )
    """)


def save_aws_policy_run(snapshot, state):
    """AWS 수집 원본과 검사 결과를 함께 저장한다."""
    snapshot_json = json.dumps(
        snapshot, ensure_ascii=False, allow_nan=False
    )
    results_json = json.dumps(
        state, ensure_ascii=False, allow_nan=False
    )

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        ensure_aws_analysis_table(connection)

        cursor = connection.execute(
            """
            INSERT INTO aws_policy_runs (
                snapshot_json, results_json
            )
            VALUES (?, ?)
            """,
            (snapshot_json, results_json),
        )

        run_id = cursor.lastrowid

    return run_id


def list_aws_policy_runs():
    """저장된 AWS 분석 목록을 최신순으로 반환한다."""
    if not DB_PATH.exists():
        return []

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        ensure_aws_analysis_table(connection)

        rows = connection.execute("""
            SELECT id, created_at
            FROM aws_policy_runs
            ORDER BY id DESC
        """).fetchall()

    return [
        {"run_id": row[0], "created_at": row[1]}
        for row in rows
    ]


def load_aws_policy_run(run_id):
    """저장 당시의 원본과 분석 결과를 복원한다."""
    if not DB_PATH.exists():
        raise FileNotFoundError("DB가 없습니다.")

    with closing(sqlite3.connect(DB_PATH)) as connection, connection:
        ensure_aws_analysis_table(connection)

        row = connection.execute(
            """
            SELECT created_at, snapshot_json, results_json
            FROM aws_policy_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

    if row is None:
        raise ValueError(f"저장된 AWS 분석이 없습니다: {run_id}")

    return {
        "run_id": run_id,
        "created_at": row[0],
        "snapshot": json.loads(row[1]),
        "state": json.loads(row[2]),
    }

# 행동 로그를 이용한 Isolation Forest 이상 탐지

import pandas as pd
from pandas.api.types import is_numeric_dtype

from config import SEED
from analysis.hybrid import AIEngine

DEFAULT_AI_FEATURE_COLS = [
    "login_hour",
    "api_call_count",
    "failed_login_count",
]


def validate_behavior_data(behavior_df, feature_cols):
    """IsolationForest 실행 전 행동 데이터를 검증합니다."""

    required_cols = [
        "identity",
        "cloud_provider",
        *feature_cols,
    ]

    missing_cols = [
        col
        for col in required_cols
        if col not in behavior_df.columns
    ]

    if missing_cols:
        raise ValueError(
            f"Behavior 데이터 필수 컬럼 누락: {missing_cols}"
        )

    if behavior_df.empty:
        raise ValueError("Behavior 데이터가 비어 있습니다.")

    if behavior_df["identity"].isnull().any():
        raise ValueError("identity 컬럼에 null 값이 있습니다.")

    duplicated_identities = (
        behavior_df.loc[
            behavior_df["identity"].duplicated(keep=False),
            "identity",
        ]
        .unique()
        .tolist()
    )

    if duplicated_identities:
        raise ValueError(
            "각 identity는 하나의 behavior record만 가져야 합니다. "
            f"중복 identity: {duplicated_identities}"
        )

    for col in feature_cols:
        if not is_numeric_dtype(behavior_df[col]):
            raise TypeError(
                f"AI feature '{col}'은 숫자 타입이어야 합니다. "
                f"현재 타입: {behavior_df[col].dtype}"
            )

        if behavior_df[col].isnull().any():
            raise ValueError(
                f"AI feature '{col}'에 null 값이 있습니다."
            )


def run_ai_analysis(
    behavior_data,
    feature_cols=None,
    ai_engine=None,
):
    """
    행동 데이터를 기반으로 IsolationForest 분석을 실행합니다.

    Returns
    -------
    dict
        분석 결과 DataFrame, 모델, 점수, 메트릭을 포함합니다.
    """

    if feature_cols is None:
        feature_cols = DEFAULT_AI_FEATURE_COLS.copy()
    else:
        feature_cols = list(feature_cols)

    behavior_df = pd.DataFrame(
        behavior_data
    ).copy(deep=True)

    validate_behavior_data(
        behavior_df=behavior_df,
        feature_cols=feature_cols,
    )

    X_behavior = behavior_df[feature_cols].copy()

    if ai_engine is None:
        ai_engine = AIEngine(random_state=SEED)

    # 모델에는 항상 동일한 NumPy 형식으로 입력
    X_behavior_model = X_behavior.to_numpy()

    ai_engine.fit(X_behavior_model)

    raw_isolation_score = (
        ai_engine.model.score_samples(X_behavior_model)
    )

    ai_scores = [
        ai_engine.score(feature_values)
        for feature_values in X_behavior_model
    ]

    isolation_prediction = (
        ai_engine.model.predict(X_behavior_model)
    )

    ai_analysis_df = behavior_df.copy()
    ai_analysis_df["raw_isolation_score"] = (
        raw_isolation_score
    )
    ai_analysis_df["ai_score"] = ai_scores
    ai_analysis_df["isolation_prediction"] = (
        isolation_prediction
    )
    ai_analysis_df["is_detected_anomaly"] = (
        ai_analysis_df["isolation_prediction"] == -1
    )

    # 동점 발생 시에도 순서가 동일하도록 안정적으로 정렬
    ai_ranked_df = (
        ai_analysis_df
        .sort_values(
            by=[
                "ai_score",
                "raw_isolation_score",
                "identity",
            ],
            ascending=[False, True, True],
        )
        .reset_index(drop=True)
    )

    ai_ranked_df["anomaly_rank"] = (
        ai_ranked_df.index + 1
    )

    rank_map = (
        ai_ranked_df
        .set_index("identity")["anomaly_rank"]
    )

    ai_analysis_df["anomaly_rank"] = (
        ai_analysis_df["identity"]
        .map(rank_map)
        .astype(int)
    )

    detected_anomalies = int(
        ai_analysis_df["is_detected_anomaly"].sum()
    )

    metrics = {
        "total_records": len(ai_analysis_df),
        "total_features": len(feature_cols),
        "detected_anomalies": detected_anomalies,
        "normal_predictions": (
            len(ai_analysis_df) - detected_anomalies
        ),
    }

    return {
        "behavior_df": behavior_df,
        "feature_cols": feature_cols,
        "feature_df": X_behavior,
        "engine": ai_engine,
        "model": ai_engine.model,
        "raw_scores": raw_isolation_score,
        "ai_scores": ai_scores,
        "predictions": isolation_prediction,
        "analysis_df": ai_analysis_df,
        "ranked_df": ai_ranked_df,
        "rank_map": rank_map,
        "metrics": metrics,
    }


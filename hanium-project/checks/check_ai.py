# Cell 8-A의 AI 분석 실행 및 결과 검증

import pandas as pd
from IPython.display import display

from data.mock_data import generate_mock_data
from preprocessing.normalizer import normalize_policy_dataset
from analysis.anomaly import run_ai_analysis


# 행동 데이터와 정규화 데이터를 같은 데이터 생성 결과에서 준비
data = generate_mock_data()

mock_behavior_log_data = data["behavior"]
mock_iam_policy_data = data["policies"]

normalized_records = normalize_policy_dataset(mock_iam_policy_data)
normalized_df = pd.DataFrame(normalized_records)

# 원본 Cell 8-A의 시작 출력
print("--- Cell 8-A: IsolationForest AI Analysis Layer ---")
# ==================================================
# AI 분석 실행
# ==================================================

print("\n1. Execute AI Analysis")
print("----------------------")

ai_state = run_ai_analysis(
    behavior_data=mock_behavior_log_data,
)

# 기존 Cell 9, 10, 12와 호환되는 변수명 유지
behavior_df = ai_state["behavior_df"]
feature_cols = ai_state["feature_cols"]
X_behavior = ai_state["feature_df"]

ai_engine = ai_state["engine"]
ai_model = ai_state["model"]

raw_isolation_score = ai_state["raw_scores"]
ai_scores = ai_state["ai_scores"]
isolation_prediction = ai_state["predictions"]

ai_analysis_df = ai_state["analysis_df"]
ai_ranked_df = ai_state["ranked_df"]
rank_map = ai_state["rank_map"]

ai_metrics = ai_state["metrics"]


# ==================================================
# Identity 일관성 검증
# ==================================================

print("\n2. Identity Consistency Validation")
print("----------------------------------")

unknown_ai_identities = sorted(
    set(ai_analysis_df["identity"])
    - set(normalized_df["identity"])
)

if unknown_ai_identities:
    raise ValueError(
        "normalized_df에 존재하지 않는 AI identity가 있습니다: "
        f"{unknown_ai_identities}"
    )

print("Identity consistency with normalized_df validated.")


# ==================================================
# 분석 결과 출력
# ==================================================

print("\n3. AI Anomaly Analysis Summary")
print("------------------------------")

# 기존 변수명 호환
total_behavior_records = ai_metrics["total_records"]
total_ai_features = ai_metrics["total_features"]
detected_anomalies = ai_metrics["detected_anomalies"]
normal_predictions = ai_metrics["normal_predictions"]

print(f"Total Behavior Records: {total_behavior_records}")
print(f"Total AI Features: {total_ai_features}")
print(f"Detected Anomalies: {detected_anomalies}")
print(f"Normal Predictions: {normal_predictions}")

if not ai_ranked_df.empty:
    top_anomaly_record = ai_ranked_df.iloc[0].copy()
    top_anomaly_identity = top_anomaly_record["identity"]
    top_anomaly_ai_score = top_anomaly_record["ai_score"]

    print(
        f"Top Anomaly Identity: {top_anomaly_identity} "
        f"(AI Score: {top_anomaly_ai_score:.3f})"
    )
else:
    top_anomaly_record = pd.Series(dtype=object)
    top_anomaly_identity = None
    top_anomaly_ai_score = None

print("\n4. Top Anomaly Ranking")
print("----------------------")
display(ai_ranked_df.head(10))


# ==================================================
# 출력 계약 검증
# ==================================================

print("\n5. Output Contract Verification")
print("--------------------------------")

if not isinstance(ai_analysis_df, pd.DataFrame):
    raise TypeError("ai_analysis_df는 DataFrame이어야 합니다.")

if not isinstance(ai_ranked_df, pd.DataFrame):
    raise TypeError("ai_ranked_df는 DataFrame이어야 합니다.")

required_output_cols = [
    "identity",
    "ai_score",
    "raw_isolation_score",
    "isolation_prediction",
    "is_detected_anomaly",
    "anomaly_rank",
]

missing_output_cols = [
    col
    for col in required_output_cols
    if col not in ai_analysis_df.columns
]

if missing_output_cols:
    raise ValueError(
        f"AI 분석 결과 컬럼 누락: {missing_output_cols}"
    )

print("All required AI analysis outputs validated.")
print("\nCell 8-A completed successfully.")
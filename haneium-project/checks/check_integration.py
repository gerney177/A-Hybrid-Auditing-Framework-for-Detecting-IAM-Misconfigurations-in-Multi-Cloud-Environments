import pandas as pd
from IPython.display import display

from data.mock_data import generate_mock_data
from preprocessing.normalizer import normalize_policy_dataset

from analysis.rules import run_rule_analysis
from analysis.anomaly import run_ai_analysis
from analysis.graph_analysis import run_graph_analysis
from analysis.hybrid import MergeModule
from analysis.integration import (
    run_integrated_risk_analysis,
    validate_integration_outputs,
)


# 1. Mock 데이터 준비
data = generate_mock_data()

mock_iam_policy_data = data["policies"]
mock_identity_security_metadata = data["metadata"]
mock_behavior_log_data = data["behavior"]

# 2. 정책 정규화
normalized_records = normalize_policy_dataset(
    mock_iam_policy_data
)
normalized_df = pd.DataFrame(normalized_records)

# 3. Rule 분석
rule_state = run_rule_analysis(
    normalized_df=normalized_df,
    identity_metadata_df=mock_identity_security_metadata,
)

rule_identity_summary_df = rule_state["identity_summary_df"]

# 4. AI 분석
ai_state = run_ai_analysis(
    behavior_data=mock_behavior_log_data,
)

ai_analysis_df = ai_state["analysis_df"]

# 5. Graph 분석
graph_state = run_graph_analysis(
    records=normalized_records,
    normalized_df=normalized_df,
    policy_data=mock_iam_policy_data,
    metadata_df=mock_identity_security_metadata,
)

graph_identity_summary_df = graph_state["identity_summary_df"]
graph_findings_df = graph_state["findings_df"]
raw_privilege_findings_df = graph_state["raw_findings_df"]

print("--- Cell 10-A2: Execute Hybrid Risk Analysis ---")
integration_state = run_integrated_risk_analysis(
    rule_summary_df=rule_identity_summary_df,
    ai_analysis_df=ai_analysis_df,
    graph_summary_df=graph_identity_summary_df,
    graph_findings_df=graph_findings_df,
    raw_findings_df=raw_privilege_findings_df,
    metadata_df=mock_identity_security_metadata,
    merge_module_class=MergeModule,
)


# 기존 Cell 10-B, 11, 12와 호환되는 변수명 유지
all_identities = integration_state["all_identities"]
rule_agg_df = integration_state["rule_agg_df"]
ai_agg_df = integration_state["ai_agg_df"]
graph_agg_df = integration_state["graph_agg_df"]
graph_findings_agg = integration_state["graph_findings_agg"]
raw_privilege_agg = integration_state["raw_privilege_agg"]
merge_module = integration_state["merge_module"]
integrated_risk_df = integration_state["integrated_risk_df"]
risk_ranked_df = integration_state["risk_ranked_df"]
final_action_counts = integration_state["final_action_counts"]

print("\n1. Final Action Distribution")
display(final_action_counts)

print("\n2. Top 10 Ranked Identities")
display(risk_ranked_df.head(10))

print("\n3. developer01 Validation")
developer01_row = integrated_risk_df[
    integrated_risk_df["identity"] == "developer01"
]
if developer01_row.empty:
    raise ValueError("developer01이 integrated_risk_df에 없습니다.")
display(developer01_row.T)

print("\n4. Output Contract Verification")
validate_integration_outputs(
    integrated_df=integrated_risk_df,
    ranked_df=risk_ranked_df,
)

print("Cell 10-A2 completed successfully.")


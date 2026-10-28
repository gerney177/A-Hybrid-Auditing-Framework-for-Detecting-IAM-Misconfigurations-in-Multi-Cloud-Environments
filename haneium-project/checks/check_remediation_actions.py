import pandas as pd

from data.mock_data import generate_mock_data
from preprocessing.adapters import extract_statements
from preprocessing.normalizer import normalize_policy_dataset

from analysis.rules import run_rule_analysis
from analysis.anomaly import run_ai_analysis
from analysis.graph_analysis import run_graph_analysis
from analysis.hybrid import MergeModule
from analysis.integration import run_integrated_risk_analysis

from remediation.target_selection import (
    run_remediation_target_selection,
)


# 1. 원본과 같은 Mock 데이터 준비
data = generate_mock_data()

mock_iam_policy_data = data["policies"]
mock_identity_security_metadata = data["metadata"]
mock_behavior_log_data = data["behavior"]


# 2. 정책 정규화
normalized_records = normalize_policy_dataset(
    mock_iam_policy_data
)
normalized_df = pd.DataFrame(normalized_records)


# 3. 규칙 분석
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


# 5. 그래프 분석
graph_state = run_graph_analysis(
    records=normalized_records,
    normalized_df=normalized_df,
    policy_data=mock_iam_policy_data,
    metadata_df=mock_identity_security_metadata,
)

graph_identity_summary_df = graph_state["identity_summary_df"]
graph_findings_df = graph_state["findings_df"]
raw_privilege_findings_df = graph_state["raw_findings_df"]


# 6. 통합 위험 분석
integration_state = run_integrated_risk_analysis(
    rule_summary_df=rule_identity_summary_df,
    ai_analysis_df=ai_analysis_df,
    graph_summary_df=graph_identity_summary_df,
    graph_findings_df=graph_findings_df,
    raw_findings_df=raw_privilege_findings_df,
    metadata_df=mock_identity_security_metadata,
    merge_module_class=MergeModule,
)

integrated_risk_df = integration_state["integrated_risk_df"]
risk_ranked_df = integration_state["risk_ranked_df"]


# 7. Cell 11-1B: 개선 대상 선택
print("--- Cell 11-1B: Execute Remediation Target Selection ---")

remediation_target_state = run_remediation_target_selection(
    integrated_df=integrated_risk_df,
    ranked_df=risk_ranked_df,
    policy_data=mock_iam_policy_data,
    metadata_df=mock_identity_security_metadata,
    normalized_df=normalized_df,
    raw_findings_df=raw_privilege_findings_df,
    extract_statements_func=extract_statements,
)

# Cell 11-2·11-3·11-4에서 사용하는 기존 변수명 유지
cell11_input_snapshots = remediation_target_state["input_snapshots"]
target_actions = remediation_target_state["target_actions"]
remediation_targets_df = remediation_target_state["targets_df"]
remediation_target_metrics = remediation_target_state["target_metrics"]
target_preview_columns = remediation_target_state["preview_columns"]


print("\n1. Remediation Target Summary")
print(
    f"Total Remediation Targets: "
    f"{remediation_target_metrics['total_targets']}"
)
print(
    f"BLOCK Targets: "
    f"{remediation_target_metrics['block_targets']}"
)
print(
    f"ALERT Targets: "
    f"{remediation_target_metrics['alert_targets']}"
)

print("\n2. Remediation Target Preview")

if remediation_targets_df.empty:
    print("No BLOCK or ALERT identities were found.")
else:
    # 노트북의 display()를 터미널 출력으로 변경
    print(
        remediation_targets_df[target_preview_columns]
        .to_string(index=False)
    )

print("Cell 11-1B completed successfully.")

from remediation.actions import (
    run_remediation_action_generation,
    validate_remediation_actions,
)


# 8. Cell 11-2B: 개선 조치 생성
print("--- Cell 11-2B: Execute Remediation Action Generation ---")

remediation_action_state = run_remediation_action_generation(
    targets_df=remediation_targets_df,
    policy_data=mock_iam_policy_data,
    extract_statements_func=extract_statements,
)

# Cell 11-3·11-4에서 사용하는 기존 변수명 유지
remediation_actions_df = remediation_action_state["actions_df"]
remediation_action_columns = remediation_action_state["action_columns"]
list_columns = remediation_action_state["list_columns"]

print("\n1. Machine-readable Remediation Actions")
print(remediation_actions_df.to_string(index=False))

print("\n2. Output Contract Verification")
validate_remediation_actions(
    actions_df=remediation_actions_df,
    targets_df=remediation_targets_df,
)

print("Cell 11-2B completed successfully.")
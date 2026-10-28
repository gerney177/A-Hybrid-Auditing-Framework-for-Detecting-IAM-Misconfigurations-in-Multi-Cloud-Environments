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

from remediation.plans import (
    REMEDIATION_PLAN_COLUMNS,
    run_remediation_plan_generation,
)


# 9. Cell 11-3B: 개선 계획 생성
print("--- Cell 11-3B: Execute Remediation Plan Generation ---")

remediation_plan_state = run_remediation_plan_generation(
    targets_df=remediation_targets_df,
    actions_df=remediation_actions_df,
)

# Cell 11-4·12에서 사용하는 기존 변수명 유지
remediation_source_df = remediation_plan_state["source_df"]
remediation_plan_df = remediation_plan_state["plan_df"]

terraform_code_by_identity = remediation_plan_state[
    "terraform_code_map"
]

focus_remediation_identity = remediation_plan_state[
    "focus_identity"
]

focus_terraform_code = remediation_plan_state[
    "focus_terraform_code"
]

plan_preview_columns = remediation_plan_state["preview_columns"]
remediation_plan_columns = REMEDIATION_PLAN_COLUMNS.copy()


print("\n1. Remediation Plan Preview")

if remediation_plan_df.empty:
    print("No remediation plans were generated.")
else:
    print(
        remediation_plan_df[plan_preview_columns]
        .to_string(index=False)
    )


print("\n2. Focus Remediation Identity")
print(
    f"Focus Remediation Identity: "
    f"{focus_remediation_identity}"
)


print("\n3. Focus Identity Terraform Draft")

if focus_terraform_code:
    print(focus_terraform_code)
else:
    print("Terraform draft is not available for the focus identity.")

print("Cell 11-3B completed successfully.")

from remediation.verification import run_cell11_verification


# 10. Cell 11-4B: 개선 결과 검증
print("--- Cell 11-4B: Execute Remediation Verification ---")

cell11_verification_state = run_cell11_verification(
    targets_df=remediation_targets_df,
    actions_df=remediation_actions_df,
    plan_df=remediation_plan_df,
    terraform_code_map=terraform_code_by_identity,
    input_snapshots=cell11_input_snapshots,
    focus_identity=focus_remediation_identity,
    focus_code=focus_terraform_code,
    integrated_df=integrated_risk_df,
    ranked_df=risk_ranked_df,
    policy_data=mock_iam_policy_data,
    metadata_df=mock_identity_security_metadata,
    normalized_df=normalized_df,
    raw_findings_df=raw_privilege_findings_df,
)

remediation_summary_df = cell11_verification_state["summary_df"]

target_identity_set = cell11_verification_state[
    "identity_sets"
]["target_identities"]

action_identity_set = cell11_verification_state[
    "identity_sets"
]["action_identities"]

plan_identity_set = cell11_verification_state[
    "identity_sets"
]["plan_identities"]

expected_focus_identity = cell11_verification_state[
    "expected_focus_identity"
]

mfa_target_identities = cell11_verification_state[
    "mfa_target_identities"
]

final_display_columns = cell11_verification_state[
    "final_display_columns"
]


# 기존 요약 변수명 유지
summary_row = remediation_summary_df.iloc[0]

total_targets = int(summary_row["total_targets"])
block_targets = int(summary_row["block_targets"])
alert_targets = int(summary_row["alert_targets"])
terraform_draft_count = int(summary_row["terraform_draft_count"])
manual_review_count = int(summary_row["manual_review_count"])
simulation_ready_count = int(summary_row["simulation_ready_count"])


print("\n1. Remediation Summary")
print(remediation_summary_df.to_string(index=False))


print("\n2. Verification Results")
print(f"Verified Focus Identity: {expected_focus_identity}")
print(
    f"MFA remediation verified for "
    f"{len(mfa_target_identities)} identities."
)
print("Original Cell 1-10 input data remains unchanged.")


print("\n3. Final Cell 11 Output")
print(
    remediation_plan_df[final_display_columns]
    .to_string(index=False)
)

print("All Cell 11 output contracts verified.")
print(
    "Cell 11 Least Privilege and Remediation "
    "Recommendation completed successfully."
)
from remediation.application import (
    POLICY_LOG_COLUMNS,
    METADATA_LOG_COLUMNS,
    run_remediation_application_simulation,
)


# 11. Cell 12-1B: 개선 조치 적용 시뮬레이션
print("--- Cell 12-1B: Execute Remediation Application Simulation ---")

remediation_application_state = run_remediation_application_simulation(
    actions_df=remediation_actions_df,
    policy_data=mock_iam_policy_data,
    metadata_df=mock_identity_security_metadata,
    extract_statements_func=extract_statements,
)


# Cell 12-2 이후에서 사용하는 기존 변수명 유지
cell12_original_iam_snapshot = remediation_application_state[
    "original_policy_snapshot"
]

cell12_original_metadata_snapshot = remediation_application_state[
    "original_metadata_snapshot"
]

remediated_iam_policy_data = remediation_application_state[
    "remediated_policy_data"
]

remediated_identity_metadata = remediation_application_state[
    "remediated_metadata_df"
]

simulation_rows = remediation_application_state["simulation_rows"]

policy_application_logs = remediation_application_state["policy_logs"]
metadata_application_logs = remediation_application_state["metadata_logs"]

policy_application_log_df = remediation_application_state["policy_log_df"]
metadata_application_log_df = remediation_application_state["metadata_log_df"]

remediation_application_summary_df = remediation_application_state[
    "summary_df"
]

policy_log_columns = POLICY_LOG_COLUMNS.copy()
metadata_log_columns = METADATA_LOG_COLUMNS.copy()


summary_row = remediation_application_summary_df.iloc[0]

policy_change_targets = int(summary_row["policy_change_targets"])
metadata_change_targets = int(summary_row["metadata_change_targets"])
total_removed_actions = int(summary_row["total_removed_actions"])


print("\n1. Policy Application Log")
print(policy_application_log_df.to_string(index=False))

print("\n2. Metadata Application Log")
print(metadata_application_log_df.to_string(index=False))

print("\n3. Application Summary")
print(remediation_application_summary_df.to_string(index=False))

print("Original Mock Data remains unchanged.")
print("All Cell 12-1 output contracts verified.")
print(
    "Cell 12-1 Generic Remediation Application "
    "Simulation completed successfully."
)
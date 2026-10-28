# Cell 7의 규칙 분석 실행 및 시연 시나리오 검증

import pandas as pd
from IPython.display import display

from data.mock_data import generate_mock_data
from preprocessing.normalizer import normalize_policy_dataset
from analysis.rules import run_rule_analysis


data = generate_mock_data()

mock_iam_policy_data = data["policies"]
mock_identity_security_metadata = data["metadata"]

normalized_records = normalize_policy_dataset(mock_iam_policy_data)
normalized_df = pd.DataFrame(normalized_records)

print("--- Cell 7-A: Rule Analysis Functions ---")
print("Cell 7-A completed: reusable rule analysis functions defined.")

print("--- Cell 7-B: Execute Rule Analysis ---")

rule_state = run_rule_analysis(
    normalized_df=normalized_df,
    identity_metadata_df=mock_identity_security_metadata,
)

# 기존 셀과의 호환성을 위한 변수 연결
rule_engine = rule_state["rule_engine"]
rule_input_df = rule_state["input_df"]
rule_analysis_df = rule_state["analysis_df"]
rule_findings_df = rule_state["findings_df"]
rule_identity_summary_df = rule_state["identity_summary_df"]
rule_trigger_counts = rule_state["trigger_counts"]

rule_metrics = rule_state["metrics"]

print("\n1. Rule Analysis Summary")
print("------------------------")
print(f"Total IAM Records Analyzed: {rule_metrics['total_records']}")
print(f"Total Rule Violation Records: {rule_metrics['violation_records']}")
print(f"Unique Identities with Violations: {rule_metrics['violation_identities']}")
print(f"Safe Records: {rule_metrics['safe_records']}")

print("\n2. Rule Trigger Counts")
print("----------------------")
display(rule_trigger_counts)

display_findings_cols = [
    "identity",
    "source_csp",
    "operation",
    "target",
    "is_wildcard",
    "is_admin",
    "mfa_enabled",
    "has_api_key",
    "rule_score",
    "triggered_rules",
]

print("\n3. Rule Findings")
print("----------------")

if rule_findings_df.empty:
    print("No rule violations found.")
else:
    print(
        f"Total {len(rule_findings_df)} "
        f"rule findings (showing top 20):"
    )
    display(
        rule_findings_df[
            display_findings_cols
        ].head(20)
    )

print("\n4. Identity-level Rule Summary")
print("------------------------------")
display(rule_identity_summary_df)

print("\nCell 7-B completed successfully.")

print("--- Cell 7-C: Demo Scenario Validation ---")


def assert_identity_triggered_rule(
    analysis_df,
    identity,
    expected_rule,
):
    identity_df = analysis_df[
        analysis_df["identity"] == identity
    ]

    assert not identity_df.empty, (
        f"테스트 identity '{identity}'가 존재하지 않습니다."
    )

    triggered = any(
        expected_rule in rules
        for rules in identity_df["triggered_rules"]
    )

    assert triggered, (
        f"'{identity}'에서 예상 규칙 "
        f"'{expected_rule}'이 발동하지 않았습니다."
    )


assert_identity_triggered_rule(
    analysis_df=rule_analysis_df,
    identity="developer01",
    expected_rule="NO_WILDCARD",
)

print("Demo scenario validation passed.")

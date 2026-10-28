import copy
import pandas as pd

print("--- Cell 11-1A: Remediation Target Selection Functions ---")

REMEDIATION_REQUIRED_RISK_COLUMNS = [
    "identity",
    "source_csp",
    "final_action",
    "hybrid_risk_score",
    "triggered_rules",
    "graph_evidence",
    "raw_policy_evidence",
    "raw_privilege_actions",
    "is_anomaly",
]

REMEDIATION_TARGET_PREVIEW_COLUMNS = [
    "remediation_priority",
    "identity",
    "source_csp",
    "final_action",
    "hybrid_risk_score",
    "triggered_rules",
    "is_anomaly",
    "graph_evidence",
    "raw_privilege_actions",
]


def validate_remediation_selection_inputs(
    integrated_df,
    ranked_df,
    policy_data,
    metadata_df,
    normalized_df,
    raw_findings_df,
    extract_statements_func,
):
    """Cell 11에서 사용할 분석 결과와 원본 데이터를 검증합니다."""

    expected_inputs = {
        "integrated_df": (integrated_df, pd.DataFrame),
        "ranked_df": (ranked_df, pd.DataFrame),
        "policy_data": (policy_data, list),
        "metadata_df": (metadata_df, pd.DataFrame),
        "normalized_df": (normalized_df, pd.DataFrame),
        "raw_findings_df": (raw_findings_df, pd.DataFrame),
    }

    invalid_inputs = [
        name
        for name, (value, expected_type) in expected_inputs.items()
        if not isinstance(value, expected_type)
    ]

    if invalid_inputs:
        raise TypeError(
            f"Cell 11 입력 타입 오류: {invalid_inputs}"
        )

    if not callable(extract_statements_func):
        raise TypeError(
            "extract_statements_func는 호출 가능한 함수여야 합니다."
        )

    if integrated_df.empty or ranked_df.empty:
        raise ValueError(
            "integrated_df와 ranked_df는 비어 있을 수 없습니다."
        )

    for dataframe_name, dataframe in {
        "integrated_df": integrated_df,
        "ranked_df": ranked_df,
    }.items():
        missing_columns = [
            column
            for column in REMEDIATION_REQUIRED_RISK_COLUMNS
            if column not in dataframe.columns
        ]

        if missing_columns:
            raise ValueError(
                f"{dataframe_name} 필수 컬럼 누락: "
                f"{missing_columns}"
            )

        if dataframe["identity"].duplicated().any():
            raise ValueError(
                f"{dataframe_name}는 identity당 한 행이어야 합니다."
            )

    if set(integrated_df["identity"]) != set(ranked_df["identity"]):
        raise ValueError(
            "integrated_df와 ranked_df의 identity 집합이 다릅니다."
        )

    valid_actions = {"BLOCK", "ALERT", "ALLOW"}
    if not set(integrated_df["final_action"]).issubset(valid_actions):
        raise ValueError(
            "final_action에는 BLOCK, ALERT, ALLOW만 사용할 수 있습니다."
        )


def create_cell11_input_snapshots(
    integrated_df,
    ranked_df,
    policy_data,
    metadata_df,
    normalized_df,
    raw_findings_df,
):
    """Cell 11 실행 전 입력을 보존하여 이후 변경 여부를 검증합니다."""

    return {
        "integrated_risk_df": integrated_df.copy(deep=True),
        "risk_ranked_df": ranked_df.copy(deep=True),
        "mock_iam_policy_data": copy.deepcopy(policy_data),
        "mock_identity_security_metadata": metadata_df.copy(deep=True),
        "normalized_df": normalized_df.copy(deep=True),
        "raw_privilege_findings_df": raw_findings_df.copy(deep=True),
    }


def select_remediation_targets(
    integrated_df,
    ranked_df,
    target_actions=None,
):
    """기존 위험 순서를 유지하며 BLOCK·ALERT 대상을 선택합니다."""

    if target_actions is None:
        target_actions = ["BLOCK", "ALERT"]
    else:
        target_actions = list(target_actions)

    invalid_actions = sorted(
        set(target_actions) - {"BLOCK", "ALERT"}
    )
    if invalid_actions:
        raise ValueError(
            f"Remediation 대상이 될 수 없는 action: {invalid_actions}"
        )

    targets_df = (
        ranked_df[
            ranked_df["final_action"].isin(target_actions)
        ]
        .copy()
        .reset_index(drop=True)
    )

    targets_df.insert(
        0,
        "remediation_priority",
        range(1, len(targets_df) + 1),
    )

    expected_identities = set(
        integrated_df.loc[
            integrated_df["final_action"].isin(target_actions),
            "identity",
        ]
    )
    actual_identities = set(targets_df["identity"])

    if actual_identities != expected_identities:
        raise ValueError(
            "Remediation 대상이 BLOCK·ALERT 결과와 일치하지 않습니다."
        )

    if not targets_df["final_action"].isin(target_actions).all():
        raise ValueError(
            "Remediation 대상에 ALLOW identity가 포함되었습니다."
        )

    return targets_df, target_actions


def summarize_remediation_targets(targets_df):
    """Remediation 대상 개수와 action별 개수를 반환합니다."""

    return {
        "total_targets": len(targets_df),
        "block_targets": int(
            targets_df["final_action"].eq("BLOCK").sum()
        ),
        "alert_targets": int(
            targets_df["final_action"].eq("ALERT").sum()
        ),
    }


def run_remediation_target_selection(
    integrated_df,
    ranked_df,
    policy_data,
    metadata_df,
    normalized_df,
    raw_findings_df,
    extract_statements_func,
):
    """Cell 11-1의 검증·스냅샷·대상 선택을 한 번에 실행합니다."""

    validate_remediation_selection_inputs(
        integrated_df=integrated_df,
        ranked_df=ranked_df,
        policy_data=policy_data,
        metadata_df=metadata_df,
        normalized_df=normalized_df,
        raw_findings_df=raw_findings_df,
        extract_statements_func=extract_statements_func,
    )

    snapshots = create_cell11_input_snapshots(
        integrated_df=integrated_df,
        ranked_df=ranked_df,
        policy_data=policy_data,
        metadata_df=metadata_df,
        normalized_df=normalized_df,
        raw_findings_df=raw_findings_df,
    )

    targets_df, target_actions = select_remediation_targets(
        integrated_df=integrated_df,
        ranked_df=ranked_df,
    )

    return {
        "input_snapshots": snapshots,
        "target_actions": target_actions,
        "targets_df": targets_df,
        "target_metrics": summarize_remediation_targets(targets_df),
        "preview_columns": REMEDIATION_TARGET_PREVIEW_COLUMNS.copy(),
    }


print("Cell 11-1A completed: remediation target functions defined.")


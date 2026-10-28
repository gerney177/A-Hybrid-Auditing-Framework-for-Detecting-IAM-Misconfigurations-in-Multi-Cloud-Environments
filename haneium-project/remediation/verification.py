import pandas as pd

print("--- Cell 11-4A: Remediation Verification Functions ---")

ACTION_LIST_COLUMNS = [
    "policy_actions_to_remove",
    "candidate_actions_to_keep",
    "behavior_followup",
]

PLAN_LIST_COLUMNS = [
    "triggered_rules",
    "graph_evidence",
    "raw_policy_evidence",
    "recommendation",
    "manual_steps",
]

FINAL_REMEDIATION_DISPLAY_COLUMNS = [
    "remediation_priority",
    "identity",
    "source_csp",
    "final_action",
    "remediation_type",
    "terraform_supported",
]


def validate_cell11_outputs(
    targets_df,
    actions_df,
    plan_df,
    terraform_code_map,
    input_snapshots,
    focus_identity,
    focus_code,
):
    """Cell 11-1~3에서 생성된 객체들의 기본 타입을 검증합니다."""
    expected_inputs = {
        "targets_df": (targets_df, pd.DataFrame),
        "actions_df": (actions_df, pd.DataFrame),
        "plan_df": (plan_df, pd.DataFrame),
        "terraform_code_map": (terraform_code_map, dict),
        "input_snapshots": (input_snapshots, dict),
    }
    invalid_inputs = [
        name
        for name, (value, expected_type) in expected_inputs.items()
        if not isinstance(value, expected_type)
    ]
    if invalid_inputs:
        raise TypeError(f"Cell 11 출력 타입 오류: {invalid_inputs}")

    if focus_identity is not None and not isinstance(focus_identity, str):
        raise TypeError("focus_identity는 str 또는 None이어야 합니다.")
    if focus_code is not None and not isinstance(focus_code, str):
        raise TypeError("focus_code는 str 또는 None이어야 합니다.")


def create_remediation_summary(actions_df, plan_df):
    """Cell 11 전체 조치 결과를 한 행의 요약 DataFrame으로 만듭니다."""
    return pd.DataFrame([{
        "total_targets": len(plan_df),
        "block_targets": int(
            plan_df["final_action"].eq("BLOCK").sum()
        ),
        "alert_targets": int(
            plan_df["final_action"].eq("ALERT").sum()
        ),
        "terraform_draft_count": int(
            plan_df["terraform_supported"].sum()
        ),
        "manual_review_count": int(
            plan_df["manual_steps"].map(
                lambda steps: isinstance(steps, list) and bool(steps)
            ).sum()
        ),
        "simulation_ready_count": int(
            actions_df["simulation_ready"].sum()
        ),
    }])


def validate_general_remediation_contracts(
    targets_df,
    actions_df,
    plan_df,
    terraform_code_map,
):
    """대상·Action·Plan의 수, identity, 컬럼 값 계약을 검증합니다."""
    if not (
        len(targets_df) == len(actions_df) == len(plan_df)
    ):
        raise ValueError("Remediation 대상·Action·Plan 수가 다릅니다.")

    target_identities = set(targets_df["identity"])
    action_identities = set(actions_df["identity"])
    plan_identities = set(plan_df["identity"])

    if not (
        target_identities == action_identities == plan_identities
    ):
        raise ValueError(
            "Remediation 대상·Action·Plan identity가 다릅니다."
        )
    if plan_df["identity"].duplicated().any():
        raise ValueError("plan_df는 identity당 한 행이어야 합니다.")
    if not plan_df["final_action"].isin(["BLOCK", "ALERT"]).all():
        raise ValueError("plan_df에 ALLOW identity가 포함되었습니다.")

    for column in ACTION_LIST_COLUMNS:
        if not actions_df[column].map(
            lambda value: isinstance(value, list)
        ).all():
            raise TypeError(f"{column}의 값은 list여야 합니다.")

    if not actions_df["metadata_changes"].map(
        lambda value: isinstance(value, dict)
    ).all():
        raise TypeError("metadata_changes의 값은 dict여야 합니다.")

    for column in PLAN_LIST_COLUMNS:
        if not plan_df[column].map(
            lambda value: isinstance(value, list)
        ).all():
            raise TypeError(f"{column}의 값은 list여야 합니다.")

    for identity, terraform_code in terraform_code_map.items():
        if not isinstance(identity, str):
            raise TypeError("Terraform identity는 str이어야 합니다.")
        if not isinstance(terraform_code, str) or not terraform_code.strip():
            raise ValueError("Terraform 코드는 비어 있지 않은 str이어야 합니다.")

    return {
        "target_identities": target_identities,
        "action_identities": action_identities,
        "plan_identities": plan_identities,
    }


def verify_focus_remediation(plan_df, focus_identity, focus_code):
    """Focus Identity가 가장 높은 Remediation 우선순위인지 확인합니다."""
    if plan_df.empty:
        if focus_identity is not None or focus_code is not None:
            raise ValueError("대상이 없으면 Focus 결과도 None이어야 합니다.")
        return None

    expected_identity = str(
        plan_df
        .sort_values("remediation_priority")
        .iloc[0]["identity"]
    )
    if focus_identity != expected_identity:
        raise ValueError(
            "Focus Identity가 최우선 Remediation 대상과 다릅니다."
        )
    return expected_identity


def verify_developer01_remediation(
    actions_df,
    plan_df,
    terraform_code_map,
):
    """공모전 핵심 시나리오인 developer01의 최소 권한 조치를 검증합니다."""
    if "developer01" not in set(actions_df["identity"]):
        return None

    action_row = actions_df.loc[
        actions_df["identity"] == "developer01"
    ].iloc[0]
    plan_row = plan_df.loc[
        plan_df["identity"] == "developer01"
    ].iloc[0]

    remove_actions = action_row["policy_actions_to_remove"]
    keep_actions = action_row["candidate_actions_to_keep"]

    if not {"s3:*", "iam:PassRole"}.issubset(remove_actions):
        raise ValueError("developer01 제거 권한이 올바르지 않습니다.")
    if not {"s3:GetObject", "s3:PutObject"}.issubset(keep_actions):
        raise ValueError("developer01 유지 권한이 올바르지 않습니다.")
    if action_row["scope_before"] != "*":
        raise ValueError("developer01의 기존 scope는 '*'여야 합니다.")
    if action_row["scope_after"] != "arn:aws:s3:::developer01-bucket/*":
        raise ValueError("developer01의 권장 scope가 다릅니다.")
    if not bool(plan_row["terraform_supported"]):
        raise ValueError("developer01은 Terraform 지원 대상이어야 합니다.")

    terraform_code = terraform_code_map.get("developer01")
    if not isinstance(terraform_code, str):
        raise ValueError("developer01 Terraform 초안이 없습니다.")

    required_fragments = [
        'resource "aws_iam_policy"',
        "s3:GetObject",
        "s3:PutObject",
    ]
    if not all(fragment in terraform_code for fragment in required_fragments):
        raise ValueError("Terraform 초안에 필수 내용이 없습니다.")
    if any(
        fragment in terraform_code
        for fragment in ["s3:*", "iam:PassRole"]
    ):
        raise ValueError("Terraform 초안에 위험 권한이 남아 있습니다.")
    if "terraform apply" in terraform_code.lower():
        raise ValueError("Terraform 초안에 apply 명령이 포함되었습니다.")

    return {
        "action_row": action_row,
        "plan_row": plan_row,
        "remove_actions": remove_actions,
        "keep_actions": keep_actions,
        "terraform_code": terraform_code,
    }


def verify_mfa_remediation(
    targets_df,
    actions_df,
    plan_df,
    terraform_code_map,
):
    """MFA_REQUIRED 대상이 수동 MFA 조치로 생성됐는지 확인합니다.

    MFA_REQUIRED는 두 가지 형태로 나타날 수 있습니다.
    1) MFA_REQUIRED만 단독으로 걸린 경우 (예: 정책은 정상, MFA만 미설정)
       -> Terraform 정책 초안이 있으면 안 됩니다 (remediation_type=MANUAL_MFA_SIMULATION_READY).
    2) NO_WILDCARD 등 정책 위반과 MFA_REQUIRED가 함께 걸린 경우 (예: developer01)
       -> 정책 Terraform 초안과 MFA 수동 조치가 함께 존재해야 합니다
          (remediation_type=POLICY_DRAFT_AND_MANUAL_MFA).
    """
    mfa_identities = targets_df.loc[
        targets_df["triggered_rules"].map(
            lambda rules: (
                isinstance(rules, list)
                and "MFA_REQUIRED" in rules
            )
        ),
        "identity",
    ].tolist()

    for identity in mfa_identities:
        action_row = actions_df.loc[
            actions_df["identity"] == identity
        ].iloc[0]
        plan_row = plan_df.loc[
            plan_df["identity"] == identity
        ].iloc[0]

        if action_row["metadata_changes"].get("mfa_enabled") is not True:
            raise ValueError(f"{identity}의 MFA 변경안이 올바르지 않습니다.")

        remediation_type = plan_row["remediation_type"]
        has_terraform_code = (
            identity in terraform_code_map
            and terraform_code_map[identity] is not None
        )

        if remediation_type == "MANUAL_MFA_SIMULATION_READY":
            # MFA 외에 다른 위반이 없는 순수 MFA 케이스: Terraform이 있으면 오류.
            if bool(plan_row["terraform_supported"]) or has_terraform_code:
                raise ValueError(
                    f"{identity}는 MFA 단독 조치 대상인데 "
                    f"Terraform 초안이 함께 생성되었습니다."
                )
        elif remediation_type == "POLICY_DRAFT_AND_MANUAL_MFA":
            # 정책 위반 + MFA 위반이 함께 걸린 케이스: Terraform과 MFA 조치가 모두 있어야 함.
            if not bool(plan_row["terraform_supported"]) or not has_terraform_code:
                raise ValueError(
                    f"{identity}는 정책 위반도 함께 있으므로 "
                    f"Terraform 초안이 함께 생성되어야 합니다."
                )
        else:
            raise ValueError(
                f"{identity}의 MFA_REQUIRED 케이스에 예상치 못한 "
                f"remediation_type이 있습니다: {remediation_type}"
            )

    return mfa_identities


def verify_cell11_input_integrity(
    integrated_df,
    ranked_df,
    policy_data,
    metadata_df,
    normalized_df,
    raw_findings_df,
    input_snapshots,
):
    """Cell 11이 이전 분석 결과와 Mock 원본을 변경하지 않았는지 확인합니다."""
    pd.testing.assert_frame_equal(
        integrated_df,
        input_snapshots["integrated_risk_df"],
    )
    pd.testing.assert_frame_equal(
        ranked_df,
        input_snapshots["risk_ranked_df"],
    )
    pd.testing.assert_frame_equal(
        metadata_df,
        input_snapshots["mock_identity_security_metadata"],
    )
    pd.testing.assert_frame_equal(
        normalized_df,
        input_snapshots["normalized_df"],
    )
    pd.testing.assert_frame_equal(
        raw_findings_df,
        input_snapshots["raw_privilege_findings_df"],
    )
    if policy_data != input_snapshots["mock_iam_policy_data"]:
        raise ValueError("mock_iam_policy_data가 Cell 11에서 변경됐습니다.")


def run_cell11_verification(
    targets_df,
    actions_df,
    plan_df,
    terraform_code_map,
    input_snapshots,
    focus_identity,
    focus_code,
    integrated_df,
    ranked_df,
    policy_data,
    metadata_df,
    normalized_df,
    raw_findings_df,
):
    """Cell 11의 요약과 전체 출력 계약 검증을 실행합니다."""
    validate_cell11_outputs(
        targets_df,
        actions_df,
        plan_df,
        terraform_code_map,
        input_snapshots,
        focus_identity,
        focus_code,
    )
    summary_df = create_remediation_summary(actions_df, plan_df)
    identity_sets = validate_general_remediation_contracts(
        targets_df,
        actions_df,
        plan_df,
        terraform_code_map,
    )
    expected_focus_identity = verify_focus_remediation(
        plan_df,
        focus_identity,
        focus_code,
    )
    developer_result = verify_developer01_remediation(
        actions_df,
        plan_df,
        terraform_code_map,
    )
    mfa_identities = verify_mfa_remediation(
        targets_df,
        actions_df,
        plan_df,
        terraform_code_map,
    )
    verify_cell11_input_integrity(
        integrated_df,
        ranked_df,
        policy_data,
        metadata_df,
        normalized_df,
        raw_findings_df,
        input_snapshots,
    )

    return {
        "summary_df": summary_df,
        "identity_sets": identity_sets,
        "expected_focus_identity": expected_focus_identity,
        "developer_result": developer_result,
        "mfa_target_identities": mfa_identities,
        "final_display_columns": FINAL_REMEDIATION_DISPLAY_COLUMNS.copy(),
    }


print("Cell 11-4A completed: remediation verification functions defined.")


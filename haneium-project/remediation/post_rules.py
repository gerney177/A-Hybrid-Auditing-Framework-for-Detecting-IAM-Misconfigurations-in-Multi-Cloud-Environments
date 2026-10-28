import pandas as pd

print("--- Cell 12-2A: Post-remediation Rule Analysis Functions ---")


REQUIRED_POST_RULE_STATE_KEYS = [
    "rule_engine",
    "input_df",
    "analysis_df",
    "findings_df",
    "identity_summary_df",
    "trigger_counts",
    "metrics",
]


def validate_post_rule_inputs(
    policy_data,
    identity_metadata_df,
    normalize_policy_dataset_func,
    run_rule_analysis_func,
):
    """Cell 12-2의 입력 데이터와 재사용 함수를 검증합니다."""
    if not isinstance(policy_data, list):
        raise TypeError("policy_data는 list여야 합니다.")
    if not isinstance(identity_metadata_df, pd.DataFrame):
        raise TypeError("identity_metadata_df는 DataFrame이어야 합니다.")
    if identity_metadata_df.empty:
        raise ValueError("identity_metadata_df가 비어 있습니다.")
    if not callable(normalize_policy_dataset_func):
        raise TypeError("normalize_policy_dataset_func는 함수여야 합니다.")
    if not callable(run_rule_analysis_func):
        raise TypeError("run_rule_analysis_func는 함수여야 합니다.")

    required_metadata_columns = [
        "identity",
        "cloud_provider",
        "is_admin",
        "mfa_enabled",
        "has_api_key",
    ]
    missing_columns = [
        column
        for column in required_metadata_columns
        if column not in identity_metadata_df.columns
    ]
    if missing_columns:
        raise ValueError(
            f"Identity metadata 필수 컬럼 누락: {missing_columns}"
        )
    if identity_metadata_df["identity"].duplicated().any():
        raise ValueError("Identity metadata에 중복 identity가 있습니다.")


def merge_triggered_rules(rule_lists):
    """여러 레코드에서 발동한 Rule 이름을 중복 없이 정렬합니다."""
    return sorted({
        rule_name
        for rule_list in rule_lists
        for rule_name in rule_list
    })


def complete_rule_identity_summary(
    grouped_rule_summary_df,
    identity_metadata_df,
):
    """정책 레코드가 사라진 Identity까지 Rule 요약에 포함합니다."""
    identity_base_df = (
        identity_metadata_df[[
            "identity",
            "cloud_provider",
        ]]
        .rename(columns={"cloud_provider": "source_csp"})
    )

    identity_summary_df = identity_base_df.merge(
        grouped_rule_summary_df,
        on=["identity", "source_csp"],
        how="left",
        validate="one_to_one",
    )

    identity_summary_df["max_rule_score"] = (
        identity_summary_df["max_rule_score"].fillna(0.0)
    )
    identity_summary_df["violation_record_count"] = (
        identity_summary_df["violation_record_count"]
        .fillna(0)
        .astype(int)
    )
    identity_summary_df["triggered_rule_names"] = (
        identity_summary_df["triggered_rule_names"].apply(
            lambda value: value if isinstance(value, list) else []
        )
    )

    return identity_base_df, identity_summary_df


def create_post_rule_summary(normalized_df, rule_findings_df):
    """조치 후 정규화 및 Rule 분석 핵심 지표를 한 행으로 만듭니다."""
    return pd.DataFrame([{
        "normalized_records": len(normalized_df),
        "wildcard_records": int(normalized_df["is_wildcard"].sum()),
        "unknown_records": int(
            (normalized_df["operation"] == "UNKNOWN").sum()
        ),
        "rule_violation_records": len(rule_findings_df),
        "identities_with_violations": (
            rule_findings_df["identity"].nunique()
        ),
    }])


def validate_post_rule_outputs(
    normalized_records,
    normalized_df,
    rule_state,
    identity_summary_df,
    summary_df,
):
    """Cell 12-3 이후가 사용할 출력 계약을 검증합니다."""
    if not isinstance(normalized_records, list):
        raise TypeError("normalized_records는 list여야 합니다.")
    if not isinstance(normalized_df, pd.DataFrame):
        raise TypeError("normalized_df는 DataFrame이어야 합니다.")

    missing_state_keys = [
        key
        for key in REQUIRED_POST_RULE_STATE_KEYS
        if key not in rule_state
    ]
    if missing_state_keys:
        raise ValueError(
            f"Rule 분석 결과 key 누락: {missing_state_keys}"
        )

    dataframe_keys = [
        "input_df",
        "analysis_df",
        "findings_df",
        "identity_summary_df",
    ]
    for key in dataframe_keys:
        if not isinstance(rule_state[key], pd.DataFrame):
            raise TypeError(f"rule_state['{key}']는 DataFrame이어야 합니다.")

    if not isinstance(identity_summary_df, pd.DataFrame):
        raise TypeError("identity_summary_df는 DataFrame이어야 합니다.")
    if not isinstance(summary_df, pd.DataFrame):
        raise TypeError("summary_df는 DataFrame이어야 합니다.")
    if identity_summary_df["identity"].duplicated().any():
        raise ValueError("identity_summary_df는 identity당 한 행이어야 합니다.")


def run_post_remediation_rule_analysis(
    policy_data,
    identity_metadata_df,
    normalize_policy_dataset_func,
    run_rule_analysis_func,
):
    """조치 후 정책을 정규화하고 기존 Rule 분석 모듈로 재분석합니다."""
    validate_post_rule_inputs(
        policy_data,
        identity_metadata_df,
        normalize_policy_dataset_func,
        run_rule_analysis_func,
    )

    normalized_records = normalize_policy_dataset_func(policy_data)
    normalized_df = pd.DataFrame(normalized_records)
    if normalized_df.empty:
        raise ValueError("Remediation 이후 정규화 결과가 비어 있습니다.")

    rule_state = run_rule_analysis_func(
        normalized_df=normalized_df,
        identity_metadata_df=identity_metadata_df,
    )

    grouped_rule_summary_df = rule_state["identity_summary_df"]
    identity_base_df, identity_summary_df = (
        complete_rule_identity_summary(
            grouped_rule_summary_df,
            identity_metadata_df,
        )
    )
    summary_df = create_post_rule_summary(
        normalized_df,
        rule_state["findings_df"],
    )

    validate_post_rule_outputs(
        normalized_records,
        normalized_df,
        rule_state,
        identity_summary_df,
        summary_df,
    )

    return {
        "normalized_records": normalized_records,
        "normalized_df": normalized_df,
        "rule_engine": rule_state["rule_engine"],
        "rule_input_df": rule_state["input_df"],
        "rule_analysis_df": rule_state["analysis_df"],
        "rule_findings_df": rule_state["findings_df"],
        "rule_grouped_df": grouped_rule_summary_df,
        "identity_base_df": identity_base_df,
        "rule_identity_summary_df": identity_summary_df,
        "rule_trigger_counts": rule_state["trigger_counts"],
        "rule_metrics": rule_state["metrics"],
        "rule_summary_df": summary_df,
    }


print("Cell 12-2A completed: post-remediation Rule functions defined.")

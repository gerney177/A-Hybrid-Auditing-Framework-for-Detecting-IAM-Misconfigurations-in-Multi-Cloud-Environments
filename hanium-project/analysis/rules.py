# Cell 7의 규칙 분석 실행 및 시연 시나리오 검증

# 정규화된 정책과 계정 정보를 결합해 규칙 기반 위험을 분석한다.

import pandas as pd
from analysis.hybrid import RuleEngine

RULE_REQUIRED_FIELDS = [
    "identity",
    "source_csp",
    "cloud_provider",
    "is_wildcard",
    "is_admin",
    "mfa_enabled",
    "has_api_key",
]


def get_triggered_rules(record, rule_engine):
    """RuleEngine에 등록된 규칙 중 발동한 규칙 이름을 반환합니다."""
    return sorted([
        rule_name
        for rule_name, check_func, _ in rule_engine.RULES
        if check_func(record)
    ])


def get_unique_sorted_triggered_rules(rules_lists):
    """여러 레코드에서 발동한 규칙 이름을 중복 없이 합칩니다."""
    return sorted({
        rule_name
        for rules in rules_lists
        for rule_name in rules
    })


def validate_rule_input(rule_input_df):
    """RuleEngine 실행 전에 필수 컬럼, null, CSP 일관성을 검증합니다."""

    missing_fields = [
        field
        for field in RULE_REQUIRED_FIELDS
        if field not in rule_input_df.columns
    ]

    if missing_fields:
        raise ValueError(
            f"Rule Analysis 필수 컬럼 누락: {missing_fields}"
        )

    metadata_fields = [
        "is_admin",
        "mfa_enabled",
        "has_api_key",
        "cloud_provider",
    ]

    null_fields = [
        field
        for field in metadata_fields
        if rule_input_df[field].isnull().any()
    ]

    if null_fields:
        raise ValueError(
            f"Identity metadata JOIN 실패 가능성: {null_fields} 컬럼에 null 존재"
        )

    csp_mismatch_df = rule_input_df[
        rule_input_df["source_csp"]
        != rule_input_df["cloud_provider"]
    ]

    if not csp_mismatch_df.empty:
        mismatch_records = csp_mismatch_df[
            ["identity", "source_csp", "cloud_provider"]
        ].to_dict("records")

        raise ValueError(
            f"CSP 일관성 검증 실패: {mismatch_records}"
        )


def run_rule_analysis(
    normalized_df,
    identity_metadata_df,
    rule_engine=None,
):
    """
    정규화된 IAM 데이터와 Identity metadata를 입력받아
    Rule 기반 분석 결과를 반환합니다.
    """

    if normalized_df.empty:
        raise ValueError("normalized_df가 비어 있습니다.")

    if identity_metadata_df.empty:
        raise ValueError("identity_metadata_df가 비어 있습니다.")

    duplicated_identities = identity_metadata_df[
        identity_metadata_df.duplicated(
            subset=["identity"],
            keep=False,
        )
    ]

    if not duplicated_identities.empty:
        duplicated_names = sorted(
            duplicated_identities["identity"].unique()
        )

        raise ValueError(
            f"Identity metadata에 중복 identity가 있습니다: "
            f"{duplicated_names}"
        )

    if rule_engine is None:
        rule_engine = RuleEngine()

    # normalized record 여러 개 : identity metadata 한 개
    rule_input_df = normalized_df.merge(
        identity_metadata_df,
        on="identity",
        how="left",
        validate="many_to_one",
    )

    validate_rule_input(rule_input_df)

    def analyze_record(row):
        record = row.to_dict()

        return pd.Series({
            "rule_score": rule_engine.score(record),
            "triggered_rules": get_triggered_rules(
                record,
                rule_engine,
            ),
        })

    analysis_result_df = rule_input_df.apply(
        analyze_record,
        axis=1,
    )

    rule_analysis_df = pd.concat(
        [
            rule_input_df.reset_index(drop=True),
            analysis_result_df.reset_index(drop=True),
        ],
        axis=1,
    )

    # 점수와 규칙 발동 여부가 서로 일치하는지 검증
    score_has_violation = rule_analysis_df["rule_score"] > 0
    rules_have_violation = rule_analysis_df[
        "triggered_rules"
    ].map(bool)

    inconsistent_df = rule_analysis_df[
        score_has_violation != rules_have_violation
    ]

    if not inconsistent_df.empty:
        raise ValueError(
            "rule_score와 triggered_rules가 일치하지 않습니다."
        )

    rule_findings_df = rule_analysis_df[
        rule_analysis_df["rule_score"] > 0
    ].copy()

    rule_identity_summary_df = (
        rule_analysis_df
        .groupby(
            ["identity", "source_csp"],
            as_index=False,
        )
        .agg(
            max_rule_score=("rule_score", "max"),
            violation_record_count=(
                "rule_score",
                lambda scores: (scores > 0).sum(),
            ),
            triggered_rule_names=(
                "triggered_rules",
                get_unique_sorted_triggered_rules,
            ),
        )
    )

    rule_names = [
        rule_name
        for rule_name, _, _ in rule_engine.RULES
    ]

    rule_trigger_counts = (
        rule_analysis_df["triggered_rules"]
        .explode()
        .value_counts()
        .reindex(rule_names, fill_value=0)
        .sort_index()
        .astype(int)
    )

    metrics = {
        "total_records": len(rule_analysis_df),
        "violation_records": len(rule_findings_df),
        "violation_identities": (
            rule_findings_df["identity"].nunique()
        ),
        "safe_records": (
            rule_analysis_df["rule_score"] == 0
        ).sum(),
    }

    return {
        "rule_engine": rule_engine,
        "input_df": rule_input_df,
        "analysis_df": rule_analysis_df,
        "findings_df": rule_findings_df,
        "identity_summary_df": rule_identity_summary_df,
        "trigger_counts": rule_trigger_counts,
        "metrics": metrics,
    }


print("Cell 7-A completed: reusable rule analysis functions defined.")
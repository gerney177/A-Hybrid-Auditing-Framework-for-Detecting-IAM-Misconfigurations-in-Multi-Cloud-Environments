import pandas as pd

print("--- Cell 12-4A: Post-remediation Risk Comparison Functions ---")


POST_RISK_REQUIRED_DATAFRAMES = {
    "integrated_risk_df",
    "risk_ranked_df",
    "ai_analysis_df",
    "post_rule_identity_summary_df",
    "post_graph_identity_summary_df",
    "post_graph_findings_df",
    "post_raw_privilege_findings_df",
    "remediated_identity_metadata",
    "remediation_actions_df",
}

POST_RISK_NUMERIC_COLUMNS = [
    "rule_score",
    "rule_finding_count",
    "permission_edge_count",
    "wildcard_edge_count",
    "unknown_operation_count",
    "target_count",
    "graph_finding_count",
    "raw_privilege_finding_count",
]

POST_RISK_INTEGER_COLUMNS = [
    "rule_finding_count",
    "permission_edge_count",
    "wildcard_edge_count",
    "unknown_operation_count",
    "target_count",
    "graph_finding_count",
    "raw_privilege_finding_count",
]

POST_RISK_LIST_COLUMNS = [
    "triggered_rules",
    "graph_finding_types",
    "raw_privilege_finding_types",
    "raw_privilege_actions",
]

POST_ACTION_ORDER = {
    "BLOCK": 0,
    "ALERT": 1,
    "ALLOW": 2,
}

RISK_COMPARISON_COLUMNS = [
    "identity",
    "source_csp",
    "before_rule_score",
    "after_rule_score",
    "before_graph_findings",
    "after_graph_findings",
    "before_risk_score",
    "after_risk_score",
    "risk_reduction",
    "before_action",
    "after_action",
    "risk_improved",
]


def validate_post_risk_inputs(
    dataframe_inputs,
    merge_module_class,
    run_integrated_risk_analysis_func,
):
    """Cell 12-4 입력 DataFrame과 재사용 모듈을 검증합니다."""
    missing_inputs = sorted(
        POST_RISK_REQUIRED_DATAFRAMES - set(dataframe_inputs)
    )
    if missing_inputs:
        raise ValueError(f"Cell 12-4 입력 누락: {missing_inputs}")

    invalid_inputs = [
        name
        for name, value in dataframe_inputs.items()
        if name in POST_RISK_REQUIRED_DATAFRAMES
        and not isinstance(value, pd.DataFrame)
    ]
    if invalid_inputs:
        raise TypeError(
            f"다음 입력은 DataFrame이어야 합니다: {invalid_inputs}"
        )
    if not callable(merge_module_class):
        raise TypeError("merge_module_class는 호출 가능해야 합니다.")
    if not callable(run_integrated_risk_analysis_func):
        raise TypeError(
            "run_integrated_risk_analysis_func는 함수여야 합니다."
        )


def prepare_post_graph_debug_outputs(
    graph_identity_summary_df,
    graph_findings_df,
    raw_privilege_findings_df,
):
    """기존 Cell 12-4 중간 Graph 집계 변수의 구조를 유지합니다."""
    graph_agg_df = graph_identity_summary_df[[
        "identity",
        "permission_edge_count",
        "wildcard_edge_count",
        "unknown_operation_count",
        "target_count",
    ]].copy()

    if graph_findings_df.empty:
        graph_finding_agg_df = pd.DataFrame(columns=[
            "identity",
            "graph_finding_count",
            "graph_finding_types",
        ])
    else:
        graph_finding_agg_df = (
            graph_findings_df.groupby("identity")
            .agg(
                graph_finding_count=("finding_type", "size"),
                graph_finding_types=(
                    "finding_type",
                    lambda values: sorted(set(values)),
                ),
            )
            .reset_index()
        )

    if raw_privilege_findings_df.empty:
        raw_finding_agg_df = pd.DataFrame(columns=[
            "identity",
            "raw_privilege_finding_count",
            "raw_privilege_finding_types",
            "raw_privilege_actions",
        ])
    else:
        raw_finding_agg_df = (
            raw_privilege_findings_df.groupby("identity")
            .agg(
                raw_privilege_finding_count=("finding_type", "size"),
                raw_privilege_finding_types=(
                    "finding_type",
                    lambda values: sorted(set(values)),
                ),
                raw_privilege_actions=(
                    "raw_action",
                    lambda values: sorted(set(values)),
                ),
            )
            .reset_index()
        )

    graph_agg_df = (
        graph_agg_df.merge(
            graph_finding_agg_df,
            on="identity",
            how="left",
            validate="one_to_one",
        )
        .merge(
            raw_finding_agg_df,
            on="identity",
            how="left",
            validate="one_to_one",
        )
    )

    return graph_agg_df, graph_finding_agg_df, raw_finding_agg_df


def build_post_decision_reasons(row):
    """조치 후 Hybrid 판정의 핵심 이유를 반환합니다."""
    reasons = []

    if row["final_action"] == "BLOCK" and row["decision_by"] == "rule":
        reasons.extend(row["triggered_rules"])
    elif row["final_action"] == "ALERT" and row["decision_by"] == "hybrid":
        reasons.extend(row["triggered_rules"])
        if bool(row["is_anomaly"]):
            reasons.append("AI_ANOMALY_DETECTED")

    return list(dict.fromkeys(reasons))


def build_post_raw_evidence(row):
    """조치 후 Raw policy Finding을 설명 가능한 문자열로 변환합니다."""
    evidence = []

    for finding_type in row["raw_privilege_finding_types"]:
        if row["raw_privilege_actions"]:
            evidence.extend([
                f"{finding_type}: {action}"
                for action in row["raw_privilege_actions"]
            ])
        else:
            evidence.append(finding_type)

    return list(dict.fromkeys(evidence))


def normalize_post_integrated_output(integrated_df):
    """재사용 모듈의 내부 정렬 key를 제거하고 기존 출력 계약을 맞춥니다."""
    result_df = integrated_df.drop(
        columns=["action_sort_key"],
        errors="ignore",
    ).copy()

    # 기존 Cell 12-4의 설명 생성 규칙을 명시적으로 유지합니다.
    result_df["decision_reasons"] = result_df.apply(
        build_post_decision_reasons,
        axis=1,
    )
    result_df["graph_evidence"] = result_df[
        "graph_finding_types"
    ].apply(list)
    result_df["raw_policy_evidence"] = result_df.apply(
        build_post_raw_evidence,
        axis=1,
    )
    return result_df


def rank_post_remediation_risk(integrated_df):
    """조치 후 Identity를 BLOCK→ALERT→ALLOW 및 위험도 순으로 정렬합니다."""
    return (
        integrated_df.assign(
            action_sort_key=integrated_df["final_action"].map(
                POST_ACTION_ORDER
            )
        )
        .sort_values(
            by=[
                "action_sort_key",
                "hybrid_risk_score",
                "is_anomaly",
                "graph_finding_count",
                "identity",
            ],
            ascending=[True, False, False, False, True],
        )
        .drop(columns=["action_sort_key"])
        .reset_index(drop=True)
    )


def build_risk_comparison(
    before_integrated_df,
    after_integrated_df,
    before_ranked_df,
    remediation_actions_df,
):
    """조치 전후 위험 점수·판정·우선순위를 Identity별로 비교합니다."""
    before_df = before_integrated_df[[
        "identity",
        "source_csp",
        "rule_score",
        "ai_anomaly_score_raw",
        "graph_finding_count",
        "hybrid_risk_score",
        "final_action",
    ]].rename(columns={
        "rule_score": "before_rule_score",
        "ai_anomaly_score_raw": "before_ai_score",
        "graph_finding_count": "before_graph_findings",
        "hybrid_risk_score": "before_risk_score",
        "final_action": "before_action",
    })

    after_df = after_integrated_df[[
        "identity",
        "source_csp",
        "rule_score",
        "ai_anomaly_score_raw",
        "graph_finding_count",
        "hybrid_risk_score",
        "final_action",
    ]].rename(columns={
        "rule_score": "after_rule_score",
        "ai_anomaly_score_raw": "after_ai_score",
        "graph_finding_count": "after_graph_findings",
        "hybrid_risk_score": "after_risk_score",
        "final_action": "after_action",
    })

    comparison_df = before_df.merge(
        after_df,
        on=["identity", "source_csp"],
        how="inner",
        validate="one_to_one",
    )

    applied_identities = set(
        remediation_actions_df.loc[
            remediation_actions_df["simulation_ready"]
            .fillna(False)
            .astype(bool),
            "identity",
        ]
    )
    comparison_df["remediation_applied"] = comparison_df[
        "identity"
    ].isin(applied_identities)
    comparison_df["risk_reduction"] = (
        comparison_df["before_risk_score"]
        - comparison_df["after_risk_score"]
    ).round(3)
    comparison_df["action_changed"] = (
        comparison_df["before_action"]
        != comparison_df["after_action"]
    )
    comparison_df["risk_improved"] = (
        comparison_df["after_risk_score"]
        < comparison_df["before_risk_score"]
    )

    before_rank_map = {
        identity: rank
        for rank, identity in enumerate(
            before_ranked_df["identity"],
            start=1,
        )
    }
    comparison_df["before_priority"] = comparison_df[
        "identity"
    ].map(before_rank_map)
    comparison_df.sort_values(by="before_priority", inplace=True)
    comparison_df.reset_index(drop=True, inplace=True)

    remediation_effect_df = comparison_df[
        comparison_df["remediation_applied"]
    ].copy()

    return {
        "before_df": before_df,
        "after_df": after_df,
        "applied_identities": applied_identities,
        "before_rank_map": before_rank_map,
        "comparison_df": comparison_df,
        "remediation_effect_df": remediation_effect_df,
    }


def create_before_after_summary(
    before_integrated_df,
    after_integrated_df,
    remediation_effect_df,
):
    """전체 조치 효과를 한 행의 요약 지표로 만듭니다."""
    return pd.DataFrame([{
        "before_block_count": int(
            (before_integrated_df["final_action"] == "BLOCK").sum()
        ),
        "after_block_count": int(
            (after_integrated_df["final_action"] == "BLOCK").sum()
        ),
        "before_average_risk": round(
            before_integrated_df["hybrid_risk_score"].mean(),
            3,
        ),
        "after_average_risk": round(
            after_integrated_df["hybrid_risk_score"].mean(),
            3,
        ),
        "remediated_identities": len(remediation_effect_df),
        "improved_identities": int(
            remediation_effect_df["risk_improved"].sum()
        ),
    }])


def validate_post_risk_outputs(
    before_integrated_df,
    after_integrated_df,
    comparison_df,
    remediation_effect_df,
):
    """조치 후 Risk 결과의 Identity·AI·위험도 계약을 검증합니다."""
    if after_integrated_df["identity"].duplicated().any():
        raise ValueError("after_integrated_df에 중복 identity가 있습니다.")
    if set(after_integrated_df["identity"]) != set(
        before_integrated_df["identity"]
    ):
        raise ValueError("조치 전후 Identity 집합이 다릅니다.")

    ai_score_unchanged = (
        comparison_df["before_ai_score"].round(12)
        == comparison_df["after_ai_score"].round(12)
    ).all()
    if not ai_score_unchanged:
        raise ValueError("행동 로그가 같은데 AI 점수가 변경되었습니다.")

    risk_not_increased = (
        remediation_effect_df["after_risk_score"]
        <= remediation_effect_df["before_risk_score"]
    ).all()
    if not risk_not_increased:
        raise ValueError("조치한 Identity의 위험도가 증가했습니다.")


def run_post_remediation_risk_comparison(
    before_integrated_df,
    before_ranked_df,
    ai_analysis_df,
    post_rule_summary_df,
    post_graph_summary_df,
    post_graph_findings_df,
    post_raw_findings_df,
    remediated_metadata_df,
    remediation_actions_df,
    merge_module_class,
    run_integrated_risk_analysis_func,
):
    """Cell 10-A 모듈을 재사용해 조치 후 Risk와 개선 효과를 계산합니다."""
    dataframe_inputs = {
        "integrated_risk_df": before_integrated_df,
        "risk_ranked_df": before_ranked_df,
        "ai_analysis_df": ai_analysis_df,
        "post_rule_identity_summary_df": post_rule_summary_df,
        "post_graph_identity_summary_df": post_graph_summary_df,
        "post_graph_findings_df": post_graph_findings_df,
        "post_raw_privilege_findings_df": post_raw_findings_df,
        "remediated_identity_metadata": remediated_metadata_df,
        "remediation_actions_df": remediation_actions_df,
    }
    validate_post_risk_inputs(
        dataframe_inputs,
        merge_module_class,
        run_integrated_risk_analysis_func,
    )

    integration_state = run_integrated_risk_analysis_func(
        rule_summary_df=post_rule_summary_df,
        ai_analysis_df=ai_analysis_df,
        graph_summary_df=post_graph_summary_df,
        graph_findings_df=post_graph_findings_df,
        raw_findings_df=post_raw_findings_df,
        metadata_df=remediated_metadata_df,
        merge_module_class=merge_module_class,
    )

    post_integrated_df = normalize_post_integrated_output(
        integration_state["integrated_risk_df"]
    )
    post_ranked_df = rank_post_remediation_risk(post_integrated_df)

    graph_agg_df, graph_finding_agg_df, raw_finding_agg_df = (
        prepare_post_graph_debug_outputs(
            post_graph_summary_df,
            post_graph_findings_df,
            post_raw_findings_df,
        )
    )

    comparison_state = build_risk_comparison(
        before_integrated_df,
        post_integrated_df,
        before_ranked_df,
        remediation_actions_df,
    )
    before_after_summary_df = create_before_after_summary(
        before_integrated_df,
        post_integrated_df,
        comparison_state["remediation_effect_df"],
    )

    validate_post_risk_outputs(
        before_integrated_df,
        post_integrated_df,
        comparison_state["comparison_df"],
        comparison_state["remediation_effect_df"],
    )

    return {
        "integration_state": integration_state,
        "rule_agg_df": integration_state["rule_agg_df"],
        "ai_agg_df": integration_state["ai_agg_df"],
        "graph_agg_df": graph_agg_df,
        "graph_finding_agg_df": graph_finding_agg_df,
        "raw_finding_agg_df": raw_finding_agg_df,
        "identity_base_df": integration_state["all_identities"],
        "merge_module": integration_state["merge_module"],
        "integrated_risk_df": post_integrated_df,
        "risk_ranked_df": post_ranked_df,
        **comparison_state,
        "before_after_summary_df": before_after_summary_df,
    }


print("Cell 12-4A completed: post-remediation Risk functions defined.")


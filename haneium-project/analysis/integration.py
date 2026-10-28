import pandas as pd


print("--- Cell 10-A1: Hybrid Risk Analysis Functions ---")

LIST_COLUMNS = [
    "triggered_rules",
    "graph_finding_types",
    "raw_privilege_finding_types",
    "raw_privilege_actions",
    "decision_reasons",
    "graph_evidence",
    "raw_policy_evidence",
]

INTEGRATED_REQUIRED_COLUMNS = [
    "identity", "source_csp",
    "rule_score", "rule_finding_count", "triggered_rules",
    "ai_anomaly_score_raw", "raw_isolation_score",
    "isolation_prediction", "is_anomaly", "anomaly_rank",
    "permission_edge_count", "wildcard_edge_count",
    "unknown_operation_count", "target_count",
    "graph_finding_count", "graph_finding_types",
    "raw_privilege_finding_count",
    "raw_privilege_finding_types", "raw_privilege_actions",
    "hybrid_risk_score", "final_action", "decision_by", "graph_score",
    "decision_reasons", "graph_evidence", "raw_policy_evidence",
]


def validate_integration_inputs(
    rule_summary_df,
    ai_analysis_df,
    graph_summary_df,
    graph_findings_df,
    raw_findings_df,
    metadata_df,
):
    """Rule·AI·Graph 통합에 필요한 입력과 핵심 컬럼을 검증합니다."""
    dataframe_inputs = {
        "rule_summary_df": rule_summary_df,
        "ai_analysis_df": ai_analysis_df,
        "graph_summary_df": graph_summary_df,
        "graph_findings_df": graph_findings_df,
        "raw_findings_df": raw_findings_df,
        "metadata_df": metadata_df,
    }

    invalid_names = [
        name
        for name, value in dataframe_inputs.items()
        if not isinstance(value, pd.DataFrame)
    ]
    if invalid_names:
        raise TypeError(
            f"다음 입력은 DataFrame이어야 합니다: {invalid_names}"
        )

    required_columns = {
        "rule_summary_df": {
            "identity", "source_csp", "max_rule_score",
            "violation_record_count", "triggered_rule_names",
        },
        "ai_analysis_df": {
            "identity", "ai_score", "raw_isolation_score",
            "isolation_prediction", "is_detected_anomaly",
            "anomaly_rank",
        },
        "graph_summary_df": {
            "identity", "permission_edge_count",
            "wildcard_edge_count", "unknown_operation_count",
            "target_count",
        },
        "graph_findings_df": {"identity", "finding_type"},
        "raw_findings_df": {
            "identity", "finding_type", "raw_action",
        },
        "metadata_df": {"identity", "cloud_provider"},
    }

    for name, columns in required_columns.items():
        missing = sorted(columns - set(dataframe_inputs[name].columns))
        if missing:
            raise ValueError(f"{name} 필수 컬럼 누락: {missing}")

    if metadata_df.empty:
        raise ValueError("metadata_df가 비어 있습니다.")
    if metadata_df["identity"].duplicated().any():
        raise ValueError("metadata_df에 중복 identity가 있습니다.")


def _to_list(value):
    """list가 아닌 결측값을 안전한 빈 list로 변환합니다."""
    return value if isinstance(value, list) else []


def prepare_rule_aggregation(rule_summary_df):
    """Cell 7의 Rule 요약을 통합용 컬럼으로 변환합니다."""
    rule_df = rule_summary_df.copy()
    rule_df["max_rule_score"] = rule_df["max_rule_score"].fillna(0.0)
    rule_df["violation_record_count"] = (
        rule_df["violation_record_count"].fillna(0).astype(int)
    )
    rule_df["triggered_rule_names"] = (
        rule_df["triggered_rule_names"].map(_to_list)
    )

    return rule_df.rename(columns={
        "max_rule_score": "rule_score",
        "violation_record_count": "rule_finding_count",
        "triggered_rule_names": "triggered_rules",
    })


def prepare_ai_aggregation(ai_analysis_df):
    """Cell 8의 identity별 AI 결과를 통합용 컬럼으로 변환합니다."""
    return (
        ai_analysis_df[[
            "identity", "ai_score", "raw_isolation_score",
            "isolation_prediction", "is_detected_anomaly",
            "anomaly_rank",
        ]]
        .copy()
        .rename(columns={
            "ai_score": "ai_anomaly_score_raw",
            "is_detected_anomaly": "is_anomaly",
        })
    )


def prepare_graph_aggregation(
    graph_summary_df,
    graph_findings_df,
    raw_findings_df,
):
    """Cell 9의 그래프 및 원본 정책 Finding을 identity별로 집계합니다."""
    graph_base_df = graph_summary_df[[
        "identity", "permission_edge_count", "wildcard_edge_count",
        "unknown_operation_count", "target_count",
    ]].copy()

    graph_findings_agg = (
        graph_findings_df
        .groupby("identity")
        .agg(
            graph_finding_count=("finding_type", "size"),
            graph_finding_types=(
                "finding_type",
                lambda values: sorted(values.unique()),
            ),
        )
        .reset_index()
    )

    raw_privilege_agg = (
        raw_findings_df
        .groupby("identity")
        .agg(
            raw_privilege_finding_count=("finding_type", "size"),
            raw_privilege_finding_types=(
                "finding_type",
                lambda values: sorted(values.unique()),
            ),
            raw_privilege_actions=(
                "raw_action",
                lambda values: sorted(values.unique()),
            ),
        )
        .reset_index()
    )

    graph_df = (
        graph_base_df
        .merge(graph_findings_agg, on="identity", how="left")
        .merge(raw_privilege_agg, on="identity", how="left")
    )

    count_columns = [
        "graph_finding_count",
        "raw_privilege_finding_count",
    ]
    graph_df[count_columns] = (
        graph_df[count_columns].fillna(0).astype(int)
    )

    for column in [
        "graph_finding_types",
        "raw_privilege_finding_types",
        "raw_privilege_actions",
    ]:
        graph_df[column] = graph_df[column].map(_to_list)

    return graph_df, graph_findings_agg, raw_privilege_agg


def merge_analysis_layers(
    metadata_df,
    rule_df,
    ai_df,
    graph_df,
):
    """모든 identity에 Rule·AI·Graph 결과를 하나의 행으로 병합합니다."""
    all_identities = (
        metadata_df[["identity", "cloud_provider"]]
        .copy()
        .rename(columns={"cloud_provider": "source_csp"})
    )

    integrated_df = (
        all_identities
        .merge(
            rule_df,
            on=["identity", "source_csp"],
            how="left",
            validate="one_to_one",
        )
        .merge(
            ai_df,
            on="identity",
            how="left",
            validate="one_to_one",
        )
        .merge(
            graph_df,
            on="identity",
            how="left",
            validate="one_to_one",
        )
    )

    integrated_df["rule_score"] = (
        integrated_df["rule_score"].fillna(0.0)
    )
    integrated_df["rule_finding_count"] = (
        integrated_df["rule_finding_count"].fillna(0).astype(int)
    )
    integrated_df["triggered_rules"] = (
        integrated_df["triggered_rules"].map(_to_list)
    )
    integrated_df["is_anomaly"] = (
        integrated_df["is_anomaly"].fillna(False).astype(bool)
    )

    # Graph 레이어 결과가 없는 identity(그래프에 노드가 없는 예외적인 경우)를 대비해
    # 카운트 컬럼의 NaN을 0으로 채웁니다. 이 값들은 이후 graph_score 계산에 쓰입니다.
    graph_count_columns = [
        "permission_edge_count",
        "wildcard_edge_count",
        "unknown_operation_count",
        "target_count",
    ]
    integrated_df[graph_count_columns] = (
        integrated_df[graph_count_columns].fillna(0).astype(int)
    )

    if integrated_df["ai_anomaly_score_raw"].isna().any():
        missing = integrated_df.loc[
            integrated_df["ai_anomaly_score_raw"].isna(),
            "identity",
        ].tolist()
        raise ValueError(f"AI 분석 결과가 없는 identity: {missing}")

    return integrated_df, all_identities


def compute_graph_score(row) -> float:
    """Graph/Raw Policy 근거를 0~1 스케일의 단일 위험도로 압축합니다.
    wildcard/UNKNOWN 권한 엣지와 iam:PassRole류 권한 상승 벡터가 많을수록 커집니다.
    """
    raw_signal = (
        row["wildcard_edge_count"]
        + row["unknown_operation_count"]
        + row["raw_privilege_finding_count"]
    )
    return float(min(1.0, raw_signal / 3.0))


def get_hybrid_decision(row, merge_module_instance):
    """한 identity의 Rule·AI·Graph 점수를 최종 조치로 결합합니다."""
    graph_s = compute_graph_score(row)
    decision = merge_module_instance.decide(
        rule_s=row["rule_score"],
        ai_s=row["ai_anomaly_score_raw"],
        graph_s=graph_s,
    )
    return pd.Series({
        "hybrid_risk_score": decision["risk"],
        "final_action": decision["action"],
        "decision_by": decision["by"],
        "graph_score": graph_s,
    })


def apply_hybrid_decisions(integrated_df, merge_module_instance):
    """모든 identity에 MergeModule 판정을 적용합니다."""
    result_df = integrated_df.copy()
    decision_columns = [
        "hybrid_risk_score",
        "final_action",
        "decision_by",
        "graph_score",
    ]
    result_df[decision_columns] = result_df.apply(
        lambda row: get_hybrid_decision(
            row,
            merge_module_instance,
        ),
        axis=1,
    )
    return result_df


def build_decision_evidence(row):
    """최종 판정의 Rule·Graph·Raw Policy 근거를 생성합니다."""
    decision_reasons = []

    if row["final_action"] == "BLOCK" and row["decision_by"] == "rule":
        decision_reasons.extend(row["triggered_rules"])
    elif row["final_action"] == "ALERT" and row["decision_by"] == "ai":
        # Rule 위반은 없지만 AI가 단독으로 이상 행동을 지목해 승격된 경우
        decision_reasons.append("AI_ONLY_ANOMALY_ALERT")
    elif row["final_action"] == "ALERT" and row["decision_by"] == "graph":
        # Rule 위반·행동 이상은 없지만 Graph/Raw Policy 근거(권한 상승 벡터 등)만으로
        # 승격된 경우
        decision_reasons.append("GRAPH_ONLY_RISK_ALERT")
    elif (
        row["final_action"] == "ALERT"
        and row["decision_by"] == "hybrid"
    ):
        if row["rule_score"] > 0:
            decision_reasons.extend(row["triggered_rules"])
        if row["is_anomaly"]:
            decision_reasons.append("AI_ANOMALY_DETECTED")
        if row["graph_score"] > 0:
            decision_reasons.append("GRAPH_RISK_SIGNAL")

    graph_evidence = list(row["graph_finding_types"])
    raw_policy_evidence = []

    for finding_type in row["raw_privilege_finding_types"]:
        if (
            finding_type == "PRIVILEGE_ESCALATION_VECTOR"
            and row["raw_privilege_actions"]
        ):
            raw_policy_evidence.extend([
                f"{finding_type}: {action}"
                for action in row["raw_privilege_actions"]
            ])
        else:
            raw_policy_evidence.append(finding_type)

    return pd.Series({
        "decision_reasons": decision_reasons,
        "graph_evidence": graph_evidence,
        "raw_policy_evidence": raw_policy_evidence,
    })


def add_decision_evidence(integrated_df):
    """모든 identity에 설명 가능한 판정 근거 컬럼을 추가합니다."""
    result_df = integrated_df.copy()
    evidence_columns = [
        "decision_reasons",
        "graph_evidence",
        "raw_policy_evidence",
    ]
    result_df[evidence_columns] = result_df.apply(
        build_decision_evidence,
        axis=1,
    )
    return result_df


def rank_integrated_risk(integrated_df):
    """BLOCK→ALERT→ALLOW 순서와 위험 점수로 identity를 정렬합니다."""
    result_df = integrated_df.copy()
    action_order = {"BLOCK": 0, "ALERT": 1, "ALLOW": 2}
    result_df["action_sort_key"] = (
        result_df["final_action"].map(action_order)
    )

    ranked_df = (
        result_df
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
        .drop(columns="action_sort_key")
        .reset_index(drop=True)
    )
    return result_df, ranked_df


def validate_integration_outputs(integrated_df, ranked_df):
    """10-A 결과의 컬럼, 타입, 값 범위를 검증합니다."""
    missing = [
        column
        for column in INTEGRATED_REQUIRED_COLUMNS
        if column not in integrated_df.columns
    ]
    if missing:
        raise ValueError(f"integrated_risk_df 필수 컬럼 누락: {missing}")
    if integrated_df["identity"].duplicated().any():
        raise ValueError("integrated_risk_df에 중복 identity가 있습니다.")
    if not integrated_df["final_action"].isin(
        ["BLOCK", "ALERT", "ALLOW"]
    ).all():
        raise ValueError("final_action에 유효하지 않은 값이 있습니다.")
    if integrated_df["hybrid_risk_score"].lt(0).any():
        raise ValueError("hybrid_risk_score는 0보다 작을 수 없습니다.")
    if not isinstance(ranked_df, pd.DataFrame):
        raise TypeError("risk_ranked_df는 DataFrame이어야 합니다.")

    for column in LIST_COLUMNS:
        if not integrated_df[column].map(
            lambda value: isinstance(value, list)
        ).all():
            raise TypeError(f"{column}에는 list만 저장되어야 합니다.")


def run_integrated_risk_analysis(
    rule_summary_df,
    ai_analysis_df,
    graph_summary_df,
    graph_findings_df,
    raw_findings_df,
    metadata_df,
    merge_module_class,
):
    """Cell 10-A의 전체 통합 위험 분석 파이프라인을 실행합니다."""
    validate_integration_inputs(
        rule_summary_df,
        ai_analysis_df,
        graph_summary_df,
        graph_findings_df,
        raw_findings_df,
        metadata_df,
    )

    rule_df = prepare_rule_aggregation(rule_summary_df)
    ai_df = prepare_ai_aggregation(ai_analysis_df)
    graph_df, graph_findings_agg, raw_privilege_agg = (
        prepare_graph_aggregation(
            graph_summary_df,
            graph_findings_df,
            raw_findings_df,
        )
    )
    integrated_df, all_identities = merge_analysis_layers(
        metadata_df,
        rule_df,
        ai_df,
        graph_df,
    )

    merge_module_instance = merge_module_class()
    integrated_df = apply_hybrid_decisions(
        integrated_df,
        merge_module_instance,
    )
    integrated_df = add_decision_evidence(integrated_df)
    integrated_df, ranked_df = rank_integrated_risk(integrated_df)
    validate_integration_outputs(integrated_df, ranked_df)

    return {
        "all_identities": all_identities,
        "rule_agg_df": rule_df,
        "ai_agg_df": ai_df,
        "graph_agg_df": graph_df,
        "graph_findings_agg": graph_findings_agg,
        "raw_privilege_agg": raw_privilege_agg,
        "merge_module": merge_module_instance,
        "integrated_risk_df": integrated_df,
        "risk_ranked_df": ranked_df,
        "final_action_counts": integrated_df["final_action"].value_counts(),
    }

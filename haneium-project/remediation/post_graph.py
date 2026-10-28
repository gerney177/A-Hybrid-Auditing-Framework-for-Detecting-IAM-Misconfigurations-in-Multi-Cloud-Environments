import pandas as pd
import networkx as nx

print("--- Cell 12-3A: Post-remediation Graph Analysis Functions ---")


POST_GRAPH_COUNT_COLUMNS = [
    "permission_edge_count",
    "wildcard_edge_count",
    "unknown_operation_count",
    "target_count",
]

POST_GRAPH_FINDING_COLUMNS = [
    "identity",
    "finding_type",
    "operation",
    "target",
    "effect",
    "source_csp",
    "description",
]

POST_RAW_RULE_COLUMNS = [
    "raw_action",
    "finding_type",
    "severity",
    "description",
]

POST_RAW_PRIVILEGE_COLUMNS = [
    "identity",
    "source_csp",
    "raw_action",
    "scope",
    "effect",
    "finding_type",
    "severity",
    "description",
]

REQUIRED_POST_GRAPH_STATE_KEYS = [
    "graph",
    "identity_summary_df",
]


def validate_post_graph_inputs(
    records,
    normalized_df,
    policy_data,
    identity_metadata_df,
    raw_privilege_findings_df,
    run_graph_analysis_func,
    extract_statements_func,
):
    """Cell 12-3 입력 데이터와 재사용 함수를 검증합니다."""
    if not isinstance(records, list):
        raise TypeError("records는 list여야 합니다.")
    if not isinstance(normalized_df, pd.DataFrame):
        raise TypeError("normalized_df는 DataFrame이어야 합니다.")
    if not isinstance(policy_data, list):
        raise TypeError("policy_data는 list여야 합니다.")
    if not isinstance(identity_metadata_df, pd.DataFrame):
        raise TypeError("identity_metadata_df는 DataFrame이어야 합니다.")
    if not isinstance(raw_privilege_findings_df, pd.DataFrame):
        raise TypeError("raw_privilege_findings_df는 DataFrame이어야 합니다.")
    if not callable(run_graph_analysis_func):
        raise TypeError("run_graph_analysis_func는 함수여야 합니다.")
    if not callable(extract_statements_func):
        raise TypeError("extract_statements_func는 함수여야 합니다.")

    missing_raw_rule_columns = [
        column
        for column in POST_RAW_RULE_COLUMNS
        if column not in raw_privilege_findings_df.columns
    ]
    if missing_raw_rule_columns:
        raise ValueError(
            "Raw privilege rule 필수 컬럼 누락: "
            f"{missing_raw_rule_columns}"
        )


def keep_post_graph_node_contract(graph):
    """조치 후 그래프 노드에는 기존 계약인 node_type만 유지합니다."""
    for node_name in graph.nodes:
        node_type = graph.nodes[node_name].get("node_type", "Resource")
        graph.nodes[node_name].clear()
        graph.nodes[node_name]["node_type"] = node_type
    return graph


def build_post_graph_identity_summary(
    graph_identity_summary_df,
    identity_metadata_df,
):
    """그래프 통계를 전체 Identity 기준표와 결합합니다."""
    grouped_df = (
        graph_identity_summary_df[[
            "identity",
            *POST_GRAPH_COUNT_COLUMNS,
        ]]
        .sort_values("identity")
        .reset_index(drop=True)
    )

    identity_base_df = (
        identity_metadata_df[[
            "identity",
            "cloud_provider",
        ]]
        .rename(columns={"cloud_provider": "source_csp"})
    )

    identity_summary_df = identity_base_df.merge(
        grouped_df,
        on="identity",
        how="left",
        validate="one_to_one",
    )
    identity_summary_df[POST_GRAPH_COUNT_COLUMNS] = (
        identity_summary_df[POST_GRAPH_COUNT_COLUMNS]
        .fillna(0)
        .astype(int)
    )

    return grouped_df, identity_base_df, identity_summary_df


def build_post_graph_findings(normalized_df):
    """조치 후 남은 Wildcard와 UNKNOWN operation을 Finding으로 만듭니다."""
    finding_frames = []

    wildcard_findings_df = normalized_df[
        normalized_df["is_wildcard"] == True
    ].copy()
    if not wildcard_findings_df.empty:
        wildcard_findings_df["finding_type"] = "WILDCARD_PERMISSION"
        wildcard_findings_df["description"] = (
            "Wildcard permission remains after remediation."
        )
        finding_frames.append(wildcard_findings_df)

    unknown_findings_df = normalized_df[
        normalized_df["operation"] == "UNKNOWN"
    ].copy()
    if not unknown_findings_df.empty:
        unknown_findings_df["finding_type"] = "UNKNOWN_OPERATION"
        unknown_findings_df["description"] = (
            "An unmapped operation remains after remediation."
        )
        finding_frames.append(unknown_findings_df)

    if finding_frames:
        findings_df = pd.concat(
            finding_frames,
            ignore_index=True,
        )[POST_GRAPH_FINDING_COLUMNS]
    else:
        findings_df = pd.DataFrame(columns=POST_GRAPH_FINDING_COLUMNS)

    return (
        wildcard_findings_df,
        unknown_findings_df,
        finding_frames,
        findings_df,
    )


def build_raw_privilege_rule_catalog(raw_privilege_findings_df):
    """조치 전 Raw Finding에서 재분석용 Rule catalog를 만듭니다."""
    rule_catalog_df = (
        raw_privilege_findings_df[POST_RAW_RULE_COLUMNS]
        .drop_duplicates(
            subset=["raw_action", "finding_type"]
        )
    )

    rules_by_action = {}
    for _, rule_row in rule_catalog_df.iterrows():
        action_key = str(rule_row["raw_action"]).lower()
        rules_by_action.setdefault(action_key, []).append(
            rule_row.to_dict()
        )

    return rule_catalog_df, rules_by_action


def detect_post_raw_privilege_findings(
    policy_data,
    rules_by_action,
    extract_statements_func,
):
    """조치 후 Raw policy에 Rule catalog의 위험 Action이 남았는지 확인합니다."""
    findings = []

    for policy_item in policy_data:
        statements = extract_statements_func(
            policy_item["csp"],
            policy_item["raw_policy_document"],
        )

        for statement in statements:
            for action in statement["actions"]:
                matched_rules = rules_by_action.get(
                    str(action).lower(),
                    [],
                )

                for matched_rule in matched_rules:
                    findings.append({
                        "identity": policy_item["identity"],
                        "source_csp": policy_item["csp"],
                        "raw_action": str(action),
                        "scope": statement["scope"],
                        "effect": statement["effect"],
                        "finding_type": matched_rule["finding_type"],
                        "severity": matched_rule["severity"],
                        "description": matched_rule["description"],
                    })

    findings_df = pd.DataFrame(
        findings,
        columns=POST_RAW_PRIVILEGE_COLUMNS,
    )
    return findings, findings_df


def create_post_graph_summary(
    graph,
    identity_summary_df,
    graph_findings_df,
    raw_privilege_findings_df,
):
    """조치 후 그래프 재분석 핵심 지표를 한 행으로 만듭니다."""
    return pd.DataFrame([{
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "wildcard_edges": int(
            identity_summary_df["wildcard_edge_count"].sum()
        ),
        "unknown_edges": int(
            identity_summary_df["unknown_operation_count"].sum()
        ),
        "graph_findings": len(graph_findings_df),
        "raw_privilege_findings": len(raw_privilege_findings_df),
    }])


def validate_post_graph_outputs(
    graph,
    identity_summary_df,
    graph_findings_df,
    raw_privilege_findings_df,
    confirmed_privilege_paths,
    summary_df,
):
    """Cell 12-4가 사용할 그래프 출력 계약을 검증합니다."""
    if not isinstance(graph, nx.MultiDiGraph):
        raise TypeError("graph는 nx.MultiDiGraph여야 합니다.")

    dataframe_outputs = {
        "identity_summary_df": identity_summary_df,
        "graph_findings_df": graph_findings_df,
        "raw_privilege_findings_df": raw_privilege_findings_df,
        "summary_df": summary_df,
    }
    for output_name, output_df in dataframe_outputs.items():
        if not isinstance(output_df, pd.DataFrame):
            raise TypeError(f"{output_name}는 DataFrame이어야 합니다.")

    if not isinstance(confirmed_privilege_paths, list):
        raise TypeError("confirmed_privilege_paths는 list여야 합니다.")
    if identity_summary_df["identity"].duplicated().any():
        raise ValueError("identity_summary_df는 identity당 한 행이어야 합니다.")


def run_post_remediation_graph_analysis(
    records,
    normalized_df,
    policy_data,
    identity_metadata_df,
    raw_privilege_findings_df,
    run_graph_analysis_func,
    extract_statements_func,
):
    """기존 Graph 모듈을 재사용해 조치 후 상태를 다시 분석합니다."""
    validate_post_graph_inputs(
        records,
        normalized_df,
        policy_data,
        identity_metadata_df,
        raw_privilege_findings_df,
        run_graph_analysis_func,
        extract_statements_func,
    )

    graph_state = run_graph_analysis_func(
        records=records,
        normalized_df=normalized_df,
        policy_data=policy_data,
        metadata_df=identity_metadata_df,
    )
    missing_graph_state_keys = [
        key
        for key in REQUIRED_POST_GRAPH_STATE_KEYS
        if key not in graph_state
    ]
    if missing_graph_state_keys:
        raise ValueError(
            f"Graph 분석 결과 key 누락: {missing_graph_state_keys}"
        )

    graph = keep_post_graph_node_contract(graph_state["graph"])
    grouped_df, identity_base_df, identity_summary_df = (
        build_post_graph_identity_summary(
            graph_state["identity_summary_df"],
            identity_metadata_df,
        )
    )

    (
        wildcard_findings_df,
        unknown_findings_df,
        finding_frames,
        graph_findings_df,
    ) = build_post_graph_findings(normalized_df)

    raw_rule_catalog_df, raw_rules_by_action = (
        build_raw_privilege_rule_catalog(raw_privilege_findings_df)
    )
    raw_findings, post_raw_findings_df = (
        detect_post_raw_privilege_findings(
            policy_data,
            raw_rules_by_action,
            extract_statements_func,
        )
    )

    # 현재 그래프는 Identity -> Target의 1-hop 구조입니다.
    confirmed_privilege_paths = []
    summary_df = create_post_graph_summary(
        graph,
        identity_summary_df,
        graph_findings_df,
        post_raw_findings_df,
    )

    validate_post_graph_outputs(
        graph,
        identity_summary_df,
        graph_findings_df,
        post_raw_findings_df,
        confirmed_privilege_paths,
        summary_df,
    )

    return {
        "graph": graph,
        "graph_state": graph_state,
        "graph_grouped_df": grouped_df,
        "identity_graph_base_df": identity_base_df,
        "graph_identity_summary_df": identity_summary_df,
        "wildcard_findings_df": wildcard_findings_df,
        "unknown_findings_df": unknown_findings_df,
        "graph_finding_frames": finding_frames,
        "graph_findings_df": graph_findings_df,
        "raw_rule_catalog_df": raw_rule_catalog_df,
        "raw_rules_by_action": raw_rules_by_action,
        "raw_privilege_findings": raw_findings,
        "raw_privilege_findings_df": post_raw_findings_df,
        "confirmed_privilege_paths": confirmed_privilege_paths,
        "graph_summary_df": summary_df,
    }


print("Cell 12-3A completed: post-remediation Graph functions defined.")


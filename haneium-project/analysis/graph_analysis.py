import networkx as nx
import pandas as pd

from preprocessing.normalizer import to_graph
from preprocessing.adapters import extract_statements

GRAPH_REQUIRED_COLS = [
    "identity", "operation", "target",
    "effect", "is_wildcard", "source_csp",
]

# CSP별 권한 상승(Privilege Escalation) 벡터로 취급할 원본 액션 목록.
# 기존에는 AWS의 "iam:PassRole"만 하드코딩되어 있어 Azure/GCP의 고위험
# 정책(예: 역할 할당 변경, IAM 정책 자체 변경 권한)이 탐지되지 않았습니다.
# Cell 11-2의 remediation action 생성 로직도 이 상수를 함께 사용합니다.
PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:passrole",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "microsoft.authorization/roleassignments/write",
    "resourcemanager.projects.setiampolicy",
}


def validate_graph_inputs(
    records,
    normalized_df,
    policy_data,
    metadata_df,
):
    """9-A 입력 데이터의 타입, 빈 값, 필수 컬럼을 확인합니다."""

    if not isinstance(records, list) or not records:
        raise ValueError(
            "normalized_records는 비어 있지 않은 list여야 합니다."
        )

    if (
        not isinstance(normalized_df, pd.DataFrame)
        or normalized_df.empty
    ):
        raise ValueError(
            "normalized_df는 비어 있지 않은 DataFrame이어야 합니다."
        )

    missing_cols = [
        col
        for col in GRAPH_REQUIRED_COLS
        if col not in normalized_df.columns
    ]

    if missing_cols:
        raise ValueError(
            f"normalized_df 필수 컬럼 누락: {missing_cols}"
        )

    if not isinstance(policy_data, list):
        raise TypeError("policy_data는 list여야 합니다.")

    if not isinstance(metadata_df, pd.DataFrame):
        raise TypeError("metadata_df는 DataFrame이어야 합니다.")

    required_metadata_cols = {
        "identity",
        "cloud_provider",
    }

    if not required_metadata_cols.issubset(metadata_df.columns):
        raise ValueError(
            "metadata_df에 identity/cloud_provider가 필요합니다."
        )

    if metadata_df["identity"].duplicated().any():
        raise ValueError(
            "metadata_df에 중복 identity가 있습니다."
        )


def build_privilege_graph(
    records,
    normalized_df,
    metadata_df,
):
    """권한 그래프를 만들고 Identity/Resource 노드 속성을 추가합니다."""

    graph = to_graph(records)

    if not isinstance(graph, nx.MultiDiGraph):
        raise TypeError(
            "to_graph() 결과는 MultiDiGraph여야 합니다."
        )

    identities = set(normalized_df["identity"])

    metadata_map = (
        metadata_df
        .set_index("identity")
        .to_dict("index")
    )

    for node in graph.nodes:
        if node in identities:
            graph.nodes[node]["node_type"] = "Identity"
            graph.nodes[node].update(
                metadata_map.get(node, {})
            )
        else:
            graph.nodes[node]["node_type"] = "Resource"

    return graph


def summarize_graph(
    graph,
    normalized_df,
    metadata_df,
):
    """그래프 전체와 identity별 통계를 계산합니다."""

    edge_df = pd.DataFrame([
        {
            "identity": source,
            "target": target,
            "operation": data.get("op"),
            "effect": data.get("effect"),
            "is_wildcard": bool(
                data.get("wildcard", False)
            ),
        }
        for source, target, data
        in graph.edges(data=True)
    ])

    metrics = {
        "total_nodes": graph.number_of_nodes(),

        "identity_nodes": sum(
            data.get("node_type") == "Identity"
            for _, data in graph.nodes(data=True)
        ),

        "resource_nodes": sum(
            data.get("node_type") == "Resource"
            for _, data in graph.nodes(data=True)
        ),

        "total_edges": graph.number_of_edges(),

        "wildcard_edges": int(
            edge_df["is_wildcard"].sum()
        ),

        "unknown_operation_edges": int(
            edge_df["operation"]
            .eq("UNKNOWN")
            .sum()
        ),
    }

    operation_counts = (
        edge_df["operation"]
        .value_counts()
    )

    csp_map = (
        metadata_df
        .set_index("identity")["cloud_provider"]
        .to_dict()
    )

    identity_rows = []

    for identity in (
        normalized_df["identity"].drop_duplicates()
    ):
        identity_edges = edge_df[
            edge_df["identity"] == identity
        ]

        identity_rows.append({
            "identity": identity,

            "source_csp": csp_map.get(
                identity,
                "Unknown",
            ),

            "permission_edge_count": len(
                identity_edges
            ),

            "wildcard_edge_count": int(
                identity_edges[
                    "is_wildcard"
                ].sum()
            ),

            "unknown_operation_count": int(
                identity_edges[
                    "operation"
                ].eq("UNKNOWN").sum()
            ),

            "target_count": (
                identity_edges["target"]
                .nunique()
            ),
        })

    return {
        "edge_df": edge_df,
        "metrics": metrics,
        "operation_counts": operation_counts,
        "identity_summary_df": pd.DataFrame(
            identity_rows
        ),
    }


def detect_graph_findings(
    edge_df,
    normalized_df,
):
    """Wildcard와 UNKNOWN operation을 Finding으로 변환합니다."""

    finding_columns = [
        "identity",
        "finding_type",
        "operation",
        "target",
        "effect",
        "source_csp",
        "description",
    ]

    csp_map = (
        normalized_df
        .drop_duplicates([
            "identity",
            "operation",
            "target",
        ])
        .set_index([
            "identity",
            "operation",
            "target",
        ])["source_csp"]
        .to_dict()
    )

    findings = []

    for row in edge_df.to_dict("records"):
        lookup_key = (
            row["identity"],
            row["operation"],
            row["target"],
        )

        common_data = {
            "identity": row["identity"],
            "operation": row["operation"],
            "target": row["target"],
            "effect": row["effect"],
            "source_csp": csp_map.get(
                lookup_key,
                "Unknown",
            ),
        }

        if row["is_wildcard"]:
            findings.append({
                **common_data,
                "finding_type": (
                    "WILDCARD_PERMISSION"
                ),
                "description": (
                    "Wildcard permission detected."
                ),
            })

        if row["operation"] == "UNKNOWN":
            findings.append({
                **common_data,
                "finding_type": (
                    "UNKNOWN_OPERATION"
                ),
                "description": (
                    "Unrecognized operation detected."
                ),
            })

    return pd.DataFrame(
        findings,
        columns=finding_columns,
    )


def detect_raw_privilege_findings(
    policy_data,
):
    """원본 정책에서 CSP별 권한 상승(Privilege Escalation) 벡터 액션을 탐지합니다."""

    finding_columns = [
        "identity",
        "source_csp",
        "raw_action",
        "scope",
        "effect",
        "finding_type",
        "severity",
        "description",
    ]

    findings = []

    for item in policy_data:
        statements = extract_statements(
            item["csp"],
            item["raw_policy_document"],
        )

        for statement in statements:
            for action in statement["actions"]:

                if action.lower() not in PRIVILEGE_ESCALATION_ACTIONS:
                    continue

                findings.append({
                    "identity": item["identity"],
                    "source_csp": item["csp"],
                    "raw_action": action,
                    "scope": statement["scope"],
                    "effect": statement["effect"],
                    "finding_type": (
                        "PRIVILEGE_ESCALATION_VECTOR"
                    ),
                    "severity": "High",
                    "description": (
                        f"Privilege escalation action "
                        f"'{action}' detected in raw policy."
                    ),
                })

    return pd.DataFrame(
        findings,
        columns=finding_columns,
    )


def run_graph_analysis(
    records,
    normalized_df,
    policy_data,
    metadata_df,
):
    """9-A 전체 분석을 실행하고 결과를 하나의 dict로 반환합니다."""

    validate_graph_inputs(
        records=records,
        normalized_df=normalized_df,
        policy_data=policy_data,
        metadata_df=metadata_df,
    )

    graph = build_privilege_graph(
        records=records,
        normalized_df=normalized_df,
        metadata_df=metadata_df,
    )

    summary = summarize_graph(
        graph=graph,
        normalized_df=normalized_df,
        metadata_df=metadata_df,
    )

    graph_findings_df = detect_graph_findings(
        edge_df=summary["edge_df"],
        normalized_df=normalized_df,
    )

    raw_findings_df = (
        detect_raw_privilege_findings(
            policy_data=policy_data,
        )
    )

    # 현재 그래프는 Identity -> Target의 1-hop 구조
    confirmed_paths = []

    return {
        "graph": graph,
        **summary,
        "findings_df": graph_findings_df,
        "raw_findings_df": raw_findings_df,
        "confirmed_paths": confirmed_paths,
    }


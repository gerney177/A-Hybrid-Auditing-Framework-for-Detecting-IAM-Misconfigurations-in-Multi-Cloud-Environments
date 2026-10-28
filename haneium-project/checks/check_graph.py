import networkx as nx
import pandas as pd
from IPython.display import display

from data.mock_data import generate_mock_data
from preprocessing.normalizer import normalize_policy_dataset
from analysis.graph_analysis import run_graph_analysis


# 1. 원본 Mock 데이터 준비
data = generate_mock_data()

mock_iam_policy_data = data["policies"]
mock_identity_security_metadata = data["metadata"]

# 2. 정책 정규화
normalized_records = normalize_policy_dataset(
    mock_iam_policy_data
)
normalized_df = pd.DataFrame(normalized_records)


graph_state = run_graph_analysis(
    records=normalized_records,
    normalized_df=normalized_df,
    policy_data=mock_iam_policy_data,
    metadata_df=mock_identity_security_metadata,
)


# ==================================================
# 기존 셀과 호환되는 변수 연결
# ==================================================

privilege_graph = graph_state["graph"]
graph_edge_df = graph_state["edge_df"]
graph_metrics = graph_state["metrics"]
operation_counts = graph_state["operation_counts"]

graph_identity_summary_df = (
    graph_state["identity_summary_df"]
)

graph_findings_df = (
    graph_state["findings_df"]
)

raw_privilege_findings_df = (
    graph_state["raw_findings_df"]
)

confirmed_privilege_paths = (
    graph_state["confirmed_paths"]
)


# 기존 9-A에서 만들던 요약 변수 유지
num_identity_nodes = (
    graph_metrics["identity_nodes"]
)

num_resource_nodes = (
    graph_metrics["resource_nodes"]
)

num_edges = (
    graph_metrics["total_edges"]
)


# ==================================================
# 분석 결과 출력
# ==================================================

print("\n1. Graph Summary")
print("----------------")

display(
    pd.Series(
        graph_metrics,
        name="value",
    )
)

print("\nOperation Counts:")
display(
    operation_counts.rename("count")
)


print("\n2. Identity Summary")
print("-------------------")

display(
    graph_identity_summary_df
    .sort_values(
        "permission_edge_count",
        ascending=False,
    )
    .head(10)
)


print("\n3. Graph Findings")
print("-----------------")

if graph_findings_df.empty:
    print("No graph-based findings detected.")
else:
    display(graph_findings_df.head(10))


print("\n4. Raw Policy Privilege Findings")
print("---------------------------------")

if raw_privilege_findings_df.empty:
    print(
        "No raw policy privilege findings detected."
    )
else:
    display(
        raw_privilege_findings_df.head(10)
    )


# ==================================================
# developer01 검증
# ==================================================

print("\n5. developer01 Validation")
print("-------------------------")

developer01_graph_data = (
    graph_identity_summary_df[
        graph_identity_summary_df["identity"]
        == "developer01"
    ]
)

developer01_raw_findings = (
    raw_privilege_findings_df[
        raw_privilege_findings_df["identity"]
        == "developer01"
    ]
)

display(developer01_graph_data)
display(developer01_raw_findings)

assert not developer01_graph_data.empty, (
    "developer01 그래프 요약이 없습니다."
)

assert not developer01_raw_findings.empty, (
    "developer01 iam:PassRole Finding이 없습니다."
)


# ==================================================
# 권한 상승 경로 출력
# ==================================================

print("\n6. Confirmed Privilege Path Summary")
print("-----------------------------------")

if not confirmed_privilege_paths:
    print(
        "No confirmed multi-hop privilege "
        "escalation paths."
    )
    print(
        "Current graph model is "
        "Identity -> Target (1-hop)."
    )
else:
    display(confirmed_privilege_paths)


# ==================================================
# 다음 셀에 전달할 출력 검증
# ==================================================

print("\n7. Output Contract Verification")
print("--------------------------------")

assert isinstance(
    privilege_graph,
    nx.MultiDiGraph,
)

assert isinstance(
    graph_identity_summary_df,
    pd.DataFrame,
)

assert isinstance(
    graph_findings_df,
    pd.DataFrame,
)

assert isinstance(
    raw_privilege_findings_df,
    pd.DataFrame,
)

assert isinstance(
    confirmed_privilege_paths,
    list,
)

print("All graph analysis outputs were verified.")
print("Cell 9-A2 completed successfully.")
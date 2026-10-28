# Cell 3의 엔진 정의 및 ALERT 도달 가능성 검증
from analysis.hybrid import RuleEngine, AIEngine, MergeModule


# --- 검증 코드 ---
print("Cell 3 hybrid engine definitions loaded successfully.")
print("RuleEngine defined:", callable(RuleEngine))
print("AIEngine defined:", callable(AIEngine))
print("MergeModule defined:", callable(MergeModule))

# --- ALERT 도달 가능성 회귀 검증 ---
# rule_s=0(무위반)이어도 AI/Graph 레이어만으로 THRESHOLD에 도달 가능해야
# "하이브리드 판정"이라는 이름이 성립합니다. 이 assert가 실패하면
# 가중치(W_AI, W_GRAPH) 또는 THRESHOLD를 다시 조정해야 합니다.
_max_hybrid_only_risk = round(
    MergeModule.W_AI * 1.0 + MergeModule.W_GRAPH * 1.0,
    3,
)
print(
    f"Hybrid-only max risk (rule_s=0, ai_s=1.0, graph_s=1.0): "
    f"{_max_hybrid_only_risk} (THRESHOLD={MergeModule.THRESHOLD})"
)
assert _max_hybrid_only_risk >= MergeModule.THRESHOLD, (
    "AI/Graph 단독으로는 THRESHOLD에 도달할 수 없습니다. "
    "가중치 또는 THRESHOLD를 조정하세요."
)
print("ALERT reachability check passed: Rule 위반 없이도 ALERT에 도달할 수 있습니다.")

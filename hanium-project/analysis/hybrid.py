# 규칙·AI 분석과 최종 판정을 담당하는 엔진
from sklearn.ensemble import IsolationForest


class RuleEngine:  # Deterministic Layer (Trusted Filter)
    # (규칙명, 판정식, 심각도) - 심각도 합이 1.0 이상이면 즉시 BLOCK
    RULES = [
        ("NO_ROOT_KEY", lambda r: r["identity"] == "root" and r["has_api_key"], 1.0),
        ("NO_WILDCARD", lambda r: r["is_wildcard"], 0.6),
        ("MFA_REQUIRED", lambda r: r["is_admin"] and not r["mfa_enabled"], 0.5),
        ("API_KEY_NO_MFA", lambda r: r["has_api_key"] and not r["mfa_enabled"], 0.4),
    ]

    def score(self, rec) -> float:
        # 발동한 규칙들의 심각도를 합산합니다 (여러 규칙이 겹칠수록 더 위험).
        total_severity = sum(
            severity
            for _, check_func, severity in self.RULES
            if check_func(rec)
        )
        return float(min(1.0, total_severity))


class AIEngine:  # Probabilistic Layer
    def __init__(self, random_state: int = None):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=random_state,
        )
        self._score_lo = None
        self._score_hi = None

    def fit(self, X):
        self.model.fit(X)
        # 학습 데이터 기준 score_samples 범위를 저장해 0~1 정규화에 사용합니다.
        raw_scores = self.model.score_samples(X)
        self._score_lo = float(raw_scores.min())
        self._score_hi = float(raw_scores.max())

    def score(self, x) -> float:
        """학습 데이터(모집단) 내 상대적 이상도.
        가장 정상적인 표본 -> 0.0, 가장 이상한 표본 -> 1.0.
        """
        raw = float(self.model.score_samples([x])[0])
        if self._score_hi is None or self._score_hi == self._score_lo:
            return 0.0
        normalized = (self._score_hi - raw) / (self._score_hi - self._score_lo)
        return float(min(1.0, max(0.0, normalized)))


class MergeModule:  # Decision Layer
    W_RULE, W_AI, W_GRAPH = 0.5, 0.3, 0.2
    THRESHOLD = 0.5
    # 규칙/그래프 근거가 약해도 AI가 이 값 이상으로 이상치를 지목하면 단독 ALERT 승격
    AI_ALERT_SCORE = 0.8
    # AI 근거가 약해도 Graph/Raw Policy 근거(wildcard·UNKNOWN·권한 상승 벡터)가
    # 이 값 이상이면 단독 ALERT 승격. W_GRAPH(0.2)만으로는 graph_s가 1.0이어도
    # 가중합 risk가 0.2에 그쳐 THRESHOLD(0.5)에 도달할 수 없으므로, "정책상 위험
    # 신호는 있지만 행동/규칙 위반은 없는" Azure/GCP 권한 상승 시나리오를 잡으려면
    # AI와 동일하게 단독 승격 경로가 필요합니다.
    GRAPH_ALERT_SCORE = 0.6

    def decide(
        self,
        rule_s: float,
        ai_s: float,
        graph_s: float = 0.0,
    ) -> dict:
        if rule_s >= 1.0:  # 명확한 규칙 위반 -> 즉시 조치
            return {"risk": 1.0, "action": "BLOCK", "by": "rule"}

        risk = round(
            self.W_RULE * rule_s + self.W_AI * ai_s + self.W_GRAPH * graph_s,
            3,
        )

        if risk >= self.THRESHOLD:
            return {"risk": risk, "action": "ALERT", "by": "hybrid"}

        # Rule/Graph 근거가 약해도 AI 단독으로 강한 이상치면 별도로 ALERT 승격합니다.
        # (정책상 위반은 없지만 행동 이상만으로 잡히는 사례 - 하이브리드의 존재 이유)
        # IsolationForest의 이산적 예측(is_anomaly)이 아니라 연속값 ai_s를 직접
        # 비교합니다. is_anomaly는 contamination 하이퍼파라미터가 정하는 "상위 몇 개"
        # 컷오프라서, 진짜 이상치가 2명 이상인데 contamination이 낮게 잡히면
        # 두 번째로 이상한 표본이 label=-1을 못 받는 경우가 생길 수 있습니다.
        if ai_s >= self.AI_ALERT_SCORE:
            return {"risk": risk, "action": "ALERT", "by": "ai"}

        # Rule/AI 근거가 약해도 Graph/Raw Policy 단독으로 강한 위험 신호면 승격합니다.
        # (행동은 정상이지만 정책 자체에 권한 상승 벡터가 있는 사례)
        if graph_s >= self.GRAPH_ALERT_SCORE:
            return {"risk": risk, "action": "ALERT", "by": "graph"}

        return {"risk": risk, "action": "ALLOW", "by": "hybrid"}

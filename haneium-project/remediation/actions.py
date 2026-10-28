import pandas as pd
from analysis.graph_analysis import PRIVILEGE_ESCALATION_ACTIONS

print("--- Cell 11-2A: Remediation Action Functions ---")

REMEDIATION_ACTION_COLUMNS = [
    "identity",
    "source_csp",
    "policy_actions_to_remove",
    "candidate_actions_to_keep",
    "scope_before",
    "scope_after",
    "metadata_changes",
    "behavior_followup",
    "simulation_ready",
]

REMEDIATION_LIST_COLUMNS = [
    "policy_actions_to_remove",
    "candidate_actions_to_keep",
    "behavior_followup",
]


def _cell11_as_list(value):
    """리스트형 Evidence 값을 안전하게 새 list로 변환합니다."""
    if isinstance(value, list):
        return list(value)
    if isinstance(value, (tuple, set)):
        return list(value)
    if value is None:
        return []
    return [value]


def find_raw_policy_item(policy_data, identity, source_csp):
    """identity와 CSP가 모두 일치하는 원본 정책을 찾습니다."""
    for policy_item in policy_data:
        if (
            policy_item.get("identity") == identity
            and str(policy_item.get("csp")).upper()
            == str(source_csp).upper()
        ):
            return policy_item
    return None


def analyze_policy_remediation(
    identity,
    source_csp,
    triggered_rules,
    graph_evidence,
    raw_policy_evidence,
    raw_privilege_actions,
    policy_data,
    extract_statements_func,
):
    """정책 Evidence를 제거 권한·유지 후보·변경 Scope로 변환합니다."""
    raw_policy_item = find_raw_policy_item(
        policy_data,
        identity,
        source_csp,
    )

    extracted_statements = []
    if raw_policy_item is not None:
        extracted_statements = extract_statements_func(
            source_csp,
            raw_policy_item.get("raw_policy_document", {}),
        )

    has_wildcard = (
        "NO_WILDCARD" in triggered_rules
        or "WILDCARD_PERMISSION" in graph_evidence
    )
    has_unknown_operation = (
        "UNKNOWN_OPERATION" in graph_evidence
    )
    privilege_actions = [
        str(action)
        for action in raw_privilege_actions
        if str(action).lower() in PRIVILEGE_ESCALATION_ACTIONS
    ]
    has_privilege_vector = (
        bool(privilege_actions)
        or any(
            "PRIVILEGE_ESCALATION_VECTOR" in str(evidence)
            for evidence in raw_policy_evidence
        )
    )

    actions_to_remove = []
    actions_to_keep = []
    scope_before = None
    scope_after = None

    if has_wildcard or has_privilege_vector:
        wildcard_actions = []
        concrete_actions = []
        wildcard_scopes = []
        specific_scopes = []

        for statement in extracted_statements:
            for action in _cell11_as_list(
                statement.get("actions", [])
            ):
                action = str(action)
                if "*" in action:
                    wildcard_actions.append(action)
                else:
                    concrete_actions.append(action)

            statement_scope = statement.get("scope")
            if statement_scope == "*":
                wildcard_scopes.append(statement_scope)
            elif statement_scope:
                specific_scopes.append(str(statement_scope))

        actions_to_remove = sorted(
            set(wildcard_actions + privilege_actions)
        )
        actions_to_keep = sorted({
            action
            for action in concrete_actions
            if action not in actions_to_remove
        })

        if wildcard_scopes:
            scope_before = "*"
        elif extracted_statements:
            available_scopes = sorted({
                str(statement.get("scope"))
                for statement in extracted_statements
                if statement.get("scope")
            })
            if available_scopes:
                scope_before = available_scopes[0]

        if specific_scopes:
            scope_after = sorted(set(specific_scopes))[0]
        elif source_csp.upper() == "AWS":
            scope_after = "${var.approved_resource_arn}"

    return {
        "policy_actions_to_remove": actions_to_remove,
        "candidate_actions_to_keep": actions_to_keep,
        "scope_before": scope_before,
        "scope_after": scope_after,
        "has_unknown_operation": has_unknown_operation,
    }


def build_behavior_followup(is_anomaly, has_unknown_operation):
    """AI 이상 행동과 UNKNOWN operation에 필요한 후속 점검을 생성합니다."""
    followup = []

    if bool(is_anomaly):
        followup.extend([
            "Review recent login sessions.",
            "Review recent API call activity.",
            "Validate whether the anomalous behavior was authorized.",
            "Consider temporary credential revocation if unauthorized.",
        ])

    if has_unknown_operation:
        followup.append(
            "Review the original raw action mapped as UNKNOWN."
        )

    return list(dict.fromkeys(followup))


def build_remediation_action(
    target_row,
    policy_data,
    extract_statements_func,
):
    """한 Remediation 대상의 구조화된 조치 한 행을 생성합니다."""
    identity = str(target_row["identity"])
    source_csp = str(target_row["source_csp"])
    triggered_rules = _cell11_as_list(target_row["triggered_rules"])
    graph_evidence = _cell11_as_list(target_row["graph_evidence"])
    raw_policy_evidence = _cell11_as_list(
        target_row["raw_policy_evidence"]
    )
    raw_privilege_actions = _cell11_as_list(
        target_row["raw_privilege_actions"]
    )

    policy_result = analyze_policy_remediation(
        identity=identity,
        source_csp=source_csp,
        triggered_rules=triggered_rules,
        graph_evidence=graph_evidence,
        raw_policy_evidence=raw_policy_evidence,
        raw_privilege_actions=raw_privilege_actions,
        policy_data=policy_data,
        extract_statements_func=extract_statements_func,
    )

    metadata_changes = {}
    if "MFA_REQUIRED" in triggered_rules:
        metadata_changes["mfa_enabled"] = True

    behavior_followup = build_behavior_followup(
        is_anomaly=target_row["is_anomaly"],
        has_unknown_operation=(
            policy_result["has_unknown_operation"]
        ),
    )

    return {
        "identity": identity,
        "source_csp": source_csp,
        "policy_actions_to_remove": (
            policy_result["policy_actions_to_remove"]
        ),
        "candidate_actions_to_keep": (
            policy_result["candidate_actions_to_keep"]
        ),
        "scope_before": policy_result["scope_before"],
        "scope_after": policy_result["scope_after"],
        "metadata_changes": metadata_changes,
        "behavior_followup": behavior_followup,
        "simulation_ready": bool(
            policy_result["policy_actions_to_remove"]
            or metadata_changes
        ),
    }


def build_remediation_actions(
    targets_df,
    policy_data,
    extract_statements_func,
):
    """모든 Remediation 대상의 조치 DataFrame을 생성합니다."""
    if not isinstance(targets_df, pd.DataFrame):
        raise TypeError("targets_df는 DataFrame이어야 합니다.")
    if not isinstance(policy_data, list):
        raise TypeError("policy_data는 list여야 합니다.")
    if not callable(extract_statements_func):
        raise TypeError("extract_statements_func는 함수여야 합니다.")

    actions = [
        build_remediation_action(
            target_row=row,
            policy_data=policy_data,
            extract_statements_func=extract_statements_func,
        )
        for _, row in targets_df.iterrows()
    ]

    return pd.DataFrame(
        actions,
        columns=REMEDIATION_ACTION_COLUMNS,
    )


def validate_remediation_actions(actions_df, targets_df):
    """생성된 조치와 선택된 대상의 계약을 검증합니다."""
    if not isinstance(actions_df, pd.DataFrame):
        raise TypeError("actions_df는 DataFrame이어야 합니다.")
    if actions_df["identity"].duplicated().any():
        raise ValueError("actions_df는 identity당 한 행이어야 합니다.")
    if set(actions_df["identity"]) != set(targets_df["identity"]):
        raise ValueError("Remediation 대상과 Action 대상이 다릅니다.")

    for column in REMEDIATION_LIST_COLUMNS:
        if not actions_df[column].map(
            lambda value: isinstance(value, list)
        ).all():
            raise TypeError(f"{column}의 값은 list여야 합니다.")

    if not actions_df["metadata_changes"].map(
        lambda value: isinstance(value, dict)
    ).all():
        raise TypeError("metadata_changes의 값은 dict여야 합니다.")


def run_remediation_action_generation(
    targets_df,
    policy_data,
    extract_statements_func,
):
    """Cell 11-2의 Action 생성과 검증을 실행합니다."""
    actions_df = build_remediation_actions(
        targets_df=targets_df,
        policy_data=policy_data,
        extract_statements_func=extract_statements_func,
    )
    validate_remediation_actions(actions_df, targets_df)

    return {
        "actions_df": actions_df,
        "action_columns": REMEDIATION_ACTION_COLUMNS.copy(),
        "list_columns": REMEDIATION_LIST_COLUMNS.copy(),
    }


print("Cell 11-2A completed: remediation action functions defined.")

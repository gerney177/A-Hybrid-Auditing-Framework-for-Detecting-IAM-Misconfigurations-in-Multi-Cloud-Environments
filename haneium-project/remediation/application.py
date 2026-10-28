import copy
import pandas as pd

print("--- Cell 12-1A: Remediation Application Functions ---")

REQUIRED_REMEDIATION_ACTION_COLUMNS = [
    "identity",
    "source_csp",
    "policy_actions_to_remove",
    "candidate_actions_to_keep",
    "scope_before",
    "scope_after",
    "metadata_changes",
    "simulation_ready",
]

POLICY_LOG_COLUMNS = [
    "identity",
    "source_csp",
    "requested_removals",
    "present_before",
    "actual_removed_actions",
    "candidate_actions_preserved",
    "policy_units_removed",
    "scope_updates",
    "status",
]

METADATA_LOG_COLUMNS = [
    "identity",
    "source_csp",
    "field",
    "before_value",
    "after_value",
    "status",
]


def validate_remediation_application_inputs(
    actions_df,
    policy_data,
    metadata_df,
    extract_statements_func,
):
    """Cell 12-1의 조치 명세와 Mock 원본 데이터를 검증합니다."""
    if not isinstance(actions_df, pd.DataFrame):
        raise TypeError("actions_df는 DataFrame이어야 합니다.")
    if not isinstance(policy_data, list):
        raise TypeError("policy_data는 list여야 합니다.")
    if not isinstance(metadata_df, pd.DataFrame):
        raise TypeError("metadata_df는 DataFrame이어야 합니다.")
    if not callable(extract_statements_func):
        raise TypeError("extract_statements_func는 함수여야 합니다.")

    missing_columns = [
        column
        for column in REQUIRED_REMEDIATION_ACTION_COLUMNS
        if column not in actions_df.columns
    ]
    if missing_columns:
        raise ValueError(
            f"actions_df 필수 컬럼 누락: {missing_columns}"
        )
    if actions_df["identity"].duplicated().any():
        raise ValueError("actions_df는 identity당 한 행이어야 합니다.")


def _cell12_to_list(value):
    """단일 값 또는 Collection을 새로운 list로 변환합니다."""
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _find_policy_item(policy_items, identity, source_csp):
    """identity와 CSP가 모두 일치하는 정책 항목을 찾습니다."""
    for policy_item in policy_items:
        if (
            policy_item.get("identity") == identity
            and str(policy_item.get("csp")).upper()
            == str(source_csp).upper()
        ):
            return policy_item
    return None


def _extract_action_set(policy_item, extract_statements_func):
    """기존 CSP Adapter를 이용해 Raw Action 집합을 추출합니다."""
    if policy_item is None:
        return set()

    statements = extract_statements_func(
        policy_item["csp"],
        policy_item["raw_policy_document"],
    )
    return {
        str(action)
        for statement in statements
        for action in statement.get("actions", [])
    }


def _is_concrete_scope(scope):
    """실제 적용할 수 있는 구체적인 Scope인지 확인합니다."""
    if scope is None:
        return False
    scope_text = str(scope).strip()
    return bool(scope_text) and not scope_text.startswith("${")


def _apply_aws_policy_change(
    raw_policy,
    remove_actions,
    scope_before,
    scope_after,
):
    """AWS Statement 구조에 제거 Action과 Scope 변경을 적용합니다."""
    remove_set = {str(action) for action in remove_actions}
    statement_value = raw_policy.get("Statement", [])
    statements = (
        [statement_value]
        if isinstance(statement_value, dict)
        else list(statement_value)
    )

    updated_statements = []
    actual_removed_actions = []
    policy_units_removed = 0
    scope_updates = 0

    for statement in statements:
        statement_copy = copy.deepcopy(statement)

        if "Action" not in statement_copy:
            updated_statements.append(statement_copy)
            continue

        original_action_value = statement_copy["Action"]
        original_actions = _cell12_to_list(original_action_value)
        removed_actions = [
            action
            for action in original_actions
            if str(action) in remove_set
        ]
        remaining_actions = [
            action
            for action in original_actions
            if str(action) not in remove_set
        ]
        actual_removed_actions.extend(removed_actions)

        if not remaining_actions:
            policy_units_removed += 1
            continue

        statement_copy["Action"] = (
            remaining_actions[0]
            if isinstance(original_action_value, str)
            and len(remaining_actions) == 1
            else remaining_actions
        )

        can_update_scope = (
            bool(removed_actions)
            and scope_before is not None
            and _is_concrete_scope(scope_after)
        )
        if can_update_scope:
            resource_value = statement_copy.get("Resource")

            if resource_value == scope_before:
                statement_copy["Resource"] = scope_after
                scope_updates += 1
            elif isinstance(resource_value, list):
                updated_resources = [
                    scope_after if resource == scope_before else resource
                    for resource in resource_value
                ]
                if updated_resources != resource_value:
                    statement_copy["Resource"] = updated_resources
                    scope_updates += 1

        updated_statements.append(statement_copy)

    raw_policy["Statement"] = updated_statements

    return {
        "actual_removed_actions": sorted(set(actual_removed_actions)),
        "policy_units_removed": policy_units_removed,
        "scope_updates": scope_updates,
    }


def _apply_azure_policy_change(
    raw_policy,
    remove_actions,
    scope_before,
    scope_after,
):
    """Azure Mock Policy의 actions에 제거 명세를 적용합니다."""
    remove_set = {str(action) for action in remove_actions}
    original_actions = _cell12_to_list(
        raw_policy.get("actions", [])
    )
    actual_removed_actions = [
        action
        for action in original_actions
        if str(action) in remove_set
    ]
    raw_policy["actions"] = [
        action
        for action in original_actions
        if str(action) not in remove_set
    ]

    return {
        "actual_removed_actions": sorted(set(actual_removed_actions)),
        "policy_units_removed": 0,
        "scope_updates": 0,
    }


def _apply_gcp_policy_change(
    raw_policy,
    remove_actions,
    scope_before,
    scope_after,
):
    """GCP Binding의 permissions에 제거 명세를 적용합니다."""
    remove_set = {str(action) for action in remove_actions}
    binding = raw_policy.get("binding", {})
    original_permissions = _cell12_to_list(
        binding.get("permissions", [])
    )
    actual_removed_actions = [
        permission
        for permission in original_permissions
        if str(permission) in remove_set
    ]
    binding["permissions"] = [
        permission
        for permission in original_permissions
        if str(permission) not in remove_set
    ]
    raw_policy["binding"] = binding

    return {
        "actual_removed_actions": sorted(set(actual_removed_actions)),
        "policy_units_removed": 0,
        "scope_updates": 0,
    }


POLICY_REMEDIATION_ADAPTERS = {
    "AWS": _apply_aws_policy_change,
    "AZURE": _apply_azure_policy_change,
    "GCP": _apply_gcp_policy_change,
}


def apply_policy_remediation(
    change_row,
    original_policy_data,
    remediated_policy_data,
    extract_statements_func,
    adapter_registry,
):
    """한 identity의 정책 변경을 적용하고 감사 로그 한 건을 반환합니다."""
    identity = str(change_row["identity"])
    source_csp = str(change_row["source_csp"])
    normalized_csp = source_csp.upper()
    requested_removals = {
        str(action)
        for action in _cell12_to_list(
            change_row["policy_actions_to_remove"]
        )
    }

    if not requested_removals:
        return None

    candidate_actions = {
        str(action)
        for action in _cell12_to_list(
            change_row["candidate_actions_to_keep"]
        )
    }
    original_item = _find_policy_item(
        original_policy_data,
        identity,
        source_csp,
    )
    remediated_item = _find_policy_item(
        remediated_policy_data,
        identity,
        source_csp,
    )

    if original_item is None or remediated_item is None:
        raise ValueError(
            f"Policy를 찾을 수 없습니다: {identity} ({source_csp})"
        )
    if normalized_csp not in adapter_registry:
        raise ValueError(f"지원하지 않는 CSP입니다: {source_csp}")

    actions_before = _extract_action_set(
        original_item,
        extract_statements_func,
    )
    application_result = adapter_registry[normalized_csp](
        raw_policy=remediated_item["raw_policy_document"],
        remove_actions=requested_removals,
        scope_before=change_row["scope_before"],
        scope_after=change_row["scope_after"],
    )
    actions_after = _extract_action_set(
        remediated_item,
        extract_statements_func,
    )

    return {
        "identity": identity,
        "source_csp": source_csp,
        "requested_removals": sorted(requested_removals),
        "present_before": sorted(
            requested_removals.intersection(actions_before)
        ),
        "actual_removed_actions": application_result[
            "actual_removed_actions"
        ],
        "candidate_actions_preserved": sorted(
            candidate_actions.intersection(actions_after)
        ),
        "policy_units_removed": application_result[
            "policy_units_removed"
        ],
        "scope_updates": application_result["scope_updates"],
        "status": (
            "APPLIED"
            if application_result["actual_removed_actions"]
            else "NO_CHANGE"
        ),
    }


def apply_metadata_remediation(change_row, remediated_metadata_df):
    """한 identity의 Metadata 변경을 적용하고 감사 로그를 반환합니다."""
    identity = str(change_row["identity"])
    source_csp = str(change_row["source_csp"])
    metadata_changes = dict(change_row["metadata_changes"])
    logs = []

    for field_name, new_value in metadata_changes.items():
        if field_name not in remediated_metadata_df.columns:
            raise ValueError(
                f"지원하지 않는 Metadata 필드입니다: {field_name}"
            )

        matching_indexes = remediated_metadata_df.index[
            remediated_metadata_df["identity"] == identity
        ].tolist()
        if len(matching_indexes) != 1:
            raise ValueError(
                f"Metadata identity가 없거나 중복됩니다: {identity}"
            )

        target_index = matching_indexes[0]
        before_value = remediated_metadata_df.at[
            target_index,
            field_name,
        ]
        remediated_metadata_df.at[
            target_index,
            field_name,
        ] = new_value
        after_value = remediated_metadata_df.at[
            target_index,
            field_name,
        ]

        logs.append({
            "identity": identity,
            "source_csp": source_csp,
            "field": field_name,
            "before_value": before_value,
            "after_value": after_value,
            "status": (
                "APPLIED"
                if before_value != after_value
                else "ALREADY_SATISFIED"
            ),
        })

    return logs


def apply_remediation_instructions(
    actions_df,
    policy_data,
    metadata_df,
    extract_statements_func,
    adapter_registry,
):
    """Simulation Ready 조치를 독립 복사본에 적용합니다."""
    original_policy_snapshot = copy.deepcopy(policy_data)
    original_metadata_snapshot = metadata_df.copy(deep=True)
    remediated_policy_data = copy.deepcopy(policy_data)
    remediated_metadata_df = metadata_df.copy(deep=True)

    simulation_rows = actions_df.loc[
        actions_df["simulation_ready"].fillna(False).astype(bool)
    ].copy()

    policy_logs = []
    metadata_logs = []

    for _, change_row in simulation_rows.iterrows():
        policy_log = apply_policy_remediation(
            change_row=change_row,
            original_policy_data=original_policy_snapshot,
            remediated_policy_data=remediated_policy_data,
            extract_statements_func=extract_statements_func,
            adapter_registry=adapter_registry,
        )
        if policy_log is not None:
            policy_logs.append(policy_log)

        metadata_logs.extend(
            apply_metadata_remediation(
                change_row,
                remediated_metadata_df,
            )
        )

    return {
        "original_policy_snapshot": original_policy_snapshot,
        "original_metadata_snapshot": original_metadata_snapshot,
        "remediated_policy_data": remediated_policy_data,
        "remediated_metadata_df": remediated_metadata_df,
        "simulation_rows": simulation_rows,
        "policy_logs": policy_logs,
        "metadata_logs": metadata_logs,
    }


def verify_applied_remediation(
    simulation_rows,
    original_policy_data,
    remediated_policy_data,
    remediated_metadata_df,
    extract_statements_func,
):
    """요청된 제거·유지·Metadata 변경이 실제 복사본에 반영됐는지 검증합니다."""
    for _, change_row in simulation_rows.iterrows():
        identity = str(change_row["identity"])
        source_csp = str(change_row["source_csp"])
        requested_removals = {
            str(action)
            for action in _cell12_to_list(
                change_row["policy_actions_to_remove"]
            )
        }
        candidate_actions = {
            str(action)
            for action in _cell12_to_list(
                change_row["candidate_actions_to_keep"]
            )
        }

        if requested_removals:
            original_item = _find_policy_item(
                original_policy_data,
                identity,
                source_csp,
            )
            remediated_item = _find_policy_item(
                remediated_policy_data,
                identity,
                source_csp,
            )
            actions_before = _extract_action_set(
                original_item,
                extract_statements_func,
            )
            actions_after = _extract_action_set(
                remediated_item,
                extract_statements_func,
            )

            removals_present_before = requested_removals.intersection(
                actions_before
            )
            if not removals_present_before.isdisjoint(actions_after):
                raise ValueError(
                    f"{identity}의 제거 Action이 정책에 남아 있습니다."
                )
            if not actions_after.issubset(actions_before):
                raise ValueError(
                    f"{identity}의 조치 과정에서 새 Action이 추가됐습니다."
                )
            expected_preserved = candidate_actions.intersection(
                actions_before
            )
            if not expected_preserved.issubset(actions_after):
                raise ValueError(
                    f"{identity}의 유지 후보 Action이 제거됐습니다."
                )

        for field_name, expected_value in dict(
            change_row["metadata_changes"]
        ).items():
            actual_values = remediated_metadata_df.loc[
                remediated_metadata_df["identity"] == identity,
                field_name,
            ]
            if len(actual_values) != 1:
                raise ValueError(
                    f"{identity}의 Metadata를 검증할 수 없습니다."
                )
            if actual_values.iloc[0] != expected_value:
                raise ValueError(
                    f"{identity}의 {field_name} 변경이 적용되지 않았습니다."
                )


def create_remediation_application_summary(
    simulation_rows,
    policy_log_df,
    metadata_log_df,
):
    """실제 시뮬레이션 적용 건수와 제거 Action 수를 요약합니다."""
    policy_change_targets = int(
        simulation_rows["policy_actions_to_remove"].map(
            lambda value: bool(_cell12_to_list(value))
        ).sum()
    )
    metadata_change_targets = int(
        simulation_rows["metadata_changes"].map(
            lambda value: isinstance(value, dict) and bool(value)
        ).sum()
    )
    total_removed_actions = int(
        policy_log_df["actual_removed_actions"].map(len).sum()
        if not policy_log_df.empty
        else 0
    )

    summary_df = pd.DataFrame([{
        "simulation_targets": len(simulation_rows),
        "policy_change_targets": policy_change_targets,
        "metadata_change_targets": metadata_change_targets,
        "total_removed_actions": total_removed_actions,
        "policy_log_records": len(policy_log_df),
        "metadata_log_records": len(metadata_log_df),
    }])
    return summary_df


def validate_remediation_application_outputs(
    remediated_policy_data,
    remediated_metadata_df,
    policy_log_df,
    metadata_log_df,
    summary_df,
):
    """Cell 12-1에서 생성한 결과 객체 타입을 검증합니다."""
    expected_outputs = {
        "remediated_policy_data": (remediated_policy_data, list),
        "remediated_metadata_df": (remediated_metadata_df, pd.DataFrame),
        "policy_log_df": (policy_log_df, pd.DataFrame),
        "metadata_log_df": (metadata_log_df, pd.DataFrame),
        "summary_df": (summary_df, pd.DataFrame),
    }
    invalid_outputs = [
        name
        for name, (value, expected_type) in expected_outputs.items()
        if not isinstance(value, expected_type)
    ]
    if invalid_outputs:
        raise TypeError(f"Cell 12-1 출력 타입 오류: {invalid_outputs}")


def run_remediation_application_simulation(
    actions_df,
    policy_data,
    metadata_df,
    extract_statements_func,
    adapter_registry=None,
):
    """Cell 12-1의 복사·조치 적용·검증·요약 파이프라인을 실행합니다."""
    validate_remediation_application_inputs(
        actions_df,
        policy_data,
        metadata_df,
        extract_statements_func,
    )
    if adapter_registry is None:
        adapter_registry = POLICY_REMEDIATION_ADAPTERS

    result = apply_remediation_instructions(
        actions_df,
        policy_data,
        metadata_df,
        extract_statements_func,
        adapter_registry,
    )
    policy_log_df = pd.DataFrame(
        result["policy_logs"],
        columns=POLICY_LOG_COLUMNS,
    )
    metadata_log_df = pd.DataFrame(
        result["metadata_logs"],
        columns=METADATA_LOG_COLUMNS,
    )

    verify_applied_remediation(
        result["simulation_rows"],
        result["original_policy_snapshot"],
        result["remediated_policy_data"],
        result["remediated_metadata_df"],
        extract_statements_func,
    )

    if policy_data != result["original_policy_snapshot"]:
        raise ValueError("원본 policy_data가 변경되었습니다.")
    pd.testing.assert_frame_equal(
        metadata_df,
        result["original_metadata_snapshot"],
    )

    summary_df = create_remediation_application_summary(
        result["simulation_rows"],
        policy_log_df,
        metadata_log_df,
    )
    validate_remediation_application_outputs(
        result["remediated_policy_data"],
        result["remediated_metadata_df"],
        policy_log_df,
        metadata_log_df,
        summary_df,
    )

    return {
        **result,
        "policy_log_df": policy_log_df,
        "metadata_log_df": metadata_log_df,
        "summary_df": summary_df,
    }


print("Cell 12-1A completed: remediation application functions defined.")


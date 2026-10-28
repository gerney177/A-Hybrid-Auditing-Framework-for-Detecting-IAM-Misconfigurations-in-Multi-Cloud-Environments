# analysis/policy_checks.py

def classify_action_wildcard(csp, action):
    """와일드카드의 형태를 분류한다. 위험 등급은 아니다."""
    if action == "*":
        return "ALL_ACTIONS"

    # 서비스:* 형태의 해석은 AWS 어댑터 형식에 해당한다.
    if csp == "AWS" and ":" in action:
        service, operation = action.split(":", 1)

        if service and "*" not in service and operation == "*":
            return "SERVICE_ALL_ACTIONS"

    return "ACTION_PATTERN"


def find_action_wildcards(records):
    """Allow 구문의 Action 와일드카드를 검토 후보로 반환."""
    findings = []

    for record in records:
        if record.get("effect") != "Allow":
            continue

        action = record.get("original_action")

        if not isinstance(action, str) or not action:
            raise ValueError("original_action이 누락됐습니다.")

        if "*" not in action:
            continue

        csp = record["source_csp"]

        findings.append({
            **{key: record[key] for key in ('identity_name', 'identity_type', 'attachment_type', 'policy_source_identity', 'policy_type', 'policy_version', 'group_name', 'group_arn', 'permission_path') if key in record},
            "identity": record["identity"],
            "source_csp": csp,
            "policy_name": record.get("policy_name"),
            "policy_id": record.get("policy_id"),
            "original_action": action,
            "original_resources": record.get("original_resources"),
            "condition": record.get("condition", {}),
            "wildcard_type": classify_action_wildcard(csp, action),
            "status": "REVIEW",
        })

    return findings

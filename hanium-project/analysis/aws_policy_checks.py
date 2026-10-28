# analysis/aws_policy_checks.py
from fnmatch import fnmatchcase


def find_aws_passrole_candidates(records):
    """PassRole을 포함하는 Allow Action 구문을 찾는다."""
    findings = []

    for record in records:
        if record.get("source_csp") != "AWS":
            continue

        if record.get("effect") != "Allow":
            continue

        action = record.get("original_action")

        if not isinstance(action, str) or not action:
            raise ValueError("original_action이 누락됐습니다.")

        # iam:PassRole뿐 아니라 iam:Pass*, iam:*, *도 확인
        if not fnmatchcase("iam:passrole", action.lower()):
            continue

        findings.append({
            **{key: record[key] for key in ('identity_name', 'identity_type', 'attachment_type', 'policy_source_identity', 'policy_type', 'policy_version', 'group_name', 'group_arn', 'permission_path') if key in record},
            "identity": record["identity"],
            "policy_name": record.get("policy_name"),
            "policy_id": record.get("policy_id"),
            "original_action": action,
            "matched_action": "iam:PassRole",
            "original_resources": record.get("original_resources"),
            "condition": record.get("condition", {}),
            "status": "REVIEW",
        })

    return findings

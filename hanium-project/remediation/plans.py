import json
import re
import pandas as pd

print("--- Cell 11-3A: Remediation Plan Functions ---")

import json
import re
import pandas as pd

print("--- Cell 11-3A: Remediation Plan Functions ---")

REMEDIATION_PLAN_COLUMNS = [
    "remediation_priority",
    "identity",
    "source_csp",
    "final_action",
    "hybrid_risk_score",
    "triggered_rules",
    "graph_evidence",
    "raw_policy_evidence",
    "remediation_type",
    "recommendation",
    "manual_steps",
    "terraform_supported",
    "terraform_code",
]

REMEDIATION_PLAN_PREVIEW_COLUMNS = [
    "remediation_priority",
    "identity",
    "source_csp",
    "final_action",
    "hybrid_risk_score",
    "remediation_type",
    "recommendation",
    "terraform_supported",
]


def validate_remediation_plan_inputs(targets_df, actions_df):
    """Cell 11-3의 대상과 구조화된 Action 입력을 검증합니다."""
    if not isinstance(targets_df, pd.DataFrame):
        raise TypeError("targets_df는 DataFrame이어야 합니다.")
    if not isinstance(actions_df, pd.DataFrame):
        raise TypeError("actions_df는 DataFrame이어야 합니다.")

    if set(targets_df["identity"]) != set(actions_df["identity"]):
        raise ValueError(
            "Remediation 대상과 Action 대상 identity가 다릅니다."
        )

    if targets_df["identity"].duplicated().any():
        raise ValueError("targets_df에 중복 identity가 있습니다.")
    if actions_df["identity"].duplicated().any():
        raise ValueError("actions_df에 중복 identity가 있습니다.")


def _sanitize_terraform_label(value):
    """Terraform resource label로 사용할 안전한 문자열을 생성합니다."""
    label = re.sub(
        r"[^a-zA-Z0-9_]",
        "_",
        str(value),
    ).lower()

    if not label:
        label = "identity"
    if label[0].isdigit():
        label = "identity_" + label

    return label


def _build_aws_policy_draft(
    identity,
    candidate_actions,
    resource_scope,
):
    """검토용 AWS 최소 권한 Terraform 정책 초안을 생성합니다."""
    terraform_label = (
        _sanitize_terraform_label(identity)
        + "_least_privilege"
    )
    policy_name = (
        _sanitize_terraform_label(identity)
        + "-least-privilege"
    )
    action_lines = [
        "        " + json.dumps(str(action)) + ","
        for action in candidate_actions
    ]
    resource_lines = [
        "        " + json.dumps(str(resource_scope)) + ","
    ]

    terraform_lines = [
        "# DRAFT ONLY - Review before applying.",
        "# This policy is not attached to an IAM user or role.",
        "# Attachment and old-policy removal require approval.",
        "",
        f'resource "aws_iam_policy" "{terraform_label}" {{',
        f'  name        = "{policy_name}"',
        '  description = "Candidate least-privilege IAM policy"',
        "",
        "  policy = jsonencode({",
        '    Version = "2012-10-17"',
        "    Statement = [",
        "      {",
        '        Sid    = "CandidateLeastPrivilege"',
        '        Effect = "Allow"',
        "        Action = [",
        *action_lines,
        "        ]",
        "        Resource = [",
        *resource_lines,
        "        ]",
        "      }",
        "    ]",
        "  })",
        "}",
    ]

    return "\n".join(terraform_lines)


def merge_remediation_sources(targets_df, actions_df):
    """위험 순위를 유지하며 대상과 Machine-readable Action을 병합합니다."""
    return (
        targets_df
        .merge(
            actions_df,
            on=["identity", "source_csp"],
            how="inner",
            validate="one_to_one",
        )
        .sort_values("remediation_priority")
        .reset_index(drop=True)
    )


def build_recommendation_and_steps(remediation_row):
    """한 대상의 Recommendation과 사람의 확인 단계를 생성합니다."""
    actions_to_remove = list(
        remediation_row["policy_actions_to_remove"]
    )
    actions_to_keep = list(
        remediation_row["candidate_actions_to_keep"]
    )
    metadata_changes = dict(
        remediation_row["metadata_changes"]
    )
    behavior_followup = list(
        remediation_row["behavior_followup"]
    )

    recommendation = []
    manual_steps = []

    if actions_to_remove:
        recommendation.append(
            "Remove broad or high-risk IAM actions: "
            + ", ".join(actions_to_remove)
        )

    if actions_to_keep:
        recommendation.append(
            "Use the following actions as candidate "
            "least-privilege permissions after approval: "
            + ", ".join(actions_to_keep)
        )
        manual_steps.append(
            "Confirm that the candidate actions are required "
            "for the identity's actual job responsibilities."
        )

    scope_before = remediation_row["scope_before"]
    scope_after = remediation_row["scope_after"]
    # DataFrame.iterrows()는 한 행에 float 컬럼(예: hybrid_risk_score)과
    # None이 섞여 있으면 그 행 전체를 object Series로 만들면서 None을 NaN으로
    # 바꿔버립니다. "scope_before is not None" 만으로는 이 NaN을 걸러내지 못해
    # "Reduce the resource scope from nan to nan." 같은 문구가 나갈 수 있으므로
    # pd.notna()로 None/NaN을 모두 결측으로 취급합니다.
    if (
        pd.notna(scope_before)
        and pd.notna(scope_after)
        and scope_before != scope_after
    ):
        recommendation.append(
            f"Reduce the resource scope from {scope_before} "
            f"to {scope_after}."
        )
        manual_steps.append(
            "Verify that the proposed resource scope contains "
            "all legitimately required resources."
        )

    if metadata_changes.get("mfa_enabled") is True:
        recommendation.append(
            "Enable MFA for this administrative identity."
        )
        manual_steps.extend([
            "Complete MFA device registration and verification "
            "with the identity owner.",
            "Do not claim that Terraform alone completed "
            "the MFA enrollment.",
        ])

    if behavior_followup:
        recommendation.append(
            "Perform a behavior security investigation."
        )
        manual_steps.extend(behavior_followup)

    if remediation_row["final_action"] == "ALERT":
        manual_steps.append(
            "Obtain security administrator approval before "
            "applying any policy change to an ALERT identity."
        )

    if not recommendation:
        recommendation.append(
            "Perform a manual security review before "
            "changing this identity."
        )

    return {
        "actions_to_remove": actions_to_remove,
        "actions_to_keep": actions_to_keep,
        "metadata_changes": metadata_changes,
        "recommendation": list(dict.fromkeys(recommendation)),
        "manual_steps": list(dict.fromkeys(manual_steps)),
    }


def build_remediation_plan_record(remediation_row):
    """한 대상의 권고·Terraform·Remediation Type을 생성합니다."""
    identity = str(remediation_row["identity"])
    source_csp = str(remediation_row["source_csp"])
    plan_parts = build_recommendation_and_steps(remediation_row)

    terraform_supported = (
        source_csp.upper() == "AWS"
        and bool(plan_parts["actions_to_remove"])
        and bool(plan_parts["actions_to_keep"])
        and remediation_row["scope_after"] is not None
    )
    terraform_code = None

    if terraform_supported:
        terraform_code = _build_aws_policy_draft(
            identity=identity,
            candidate_actions=plan_parts["actions_to_keep"],
            resource_scope=remediation_row["scope_after"],
        )
        plan_parts["manual_steps"].extend([
            "Review the Terraform draft before attaching it "
            "to an IAM user or role.",
            "Detach or replace the old risky policy only after "
            "the new policy has been approved.",
        ])

    has_mfa_change = (
        plan_parts["metadata_changes"].get("mfa_enabled") is True
    )
    if terraform_supported and has_mfa_change:
        remediation_type = "POLICY_DRAFT_AND_MANUAL_MFA"
    elif terraform_supported:
        remediation_type = "POLICY_DRAFT"
    elif has_mfa_change:
        remediation_type = "MANUAL_MFA_SIMULATION_READY"
    else:
        remediation_type = "MANUAL_REVIEW"

    return {
        "remediation_priority": int(
            remediation_row["remediation_priority"]
        ),
        "identity": identity,
        "source_csp": source_csp,
        "final_action": remediation_row["final_action"],
        "hybrid_risk_score": remediation_row["hybrid_risk_score"],
        "triggered_rules": list(remediation_row["triggered_rules"]),
        "graph_evidence": list(remediation_row["graph_evidence"]),
        "raw_policy_evidence": list(
            remediation_row["raw_policy_evidence"]
        ),
        "remediation_type": remediation_type,
        "recommendation": plan_parts["recommendation"],
        "manual_steps": list(
            dict.fromkeys(plan_parts["manual_steps"])
        ),
        "terraform_supported": terraform_supported,
        "terraform_code": terraform_code,
    }


def generate_remediation_plans(remediation_source_df):
    """모든 대상의 Plan DataFrame과 Terraform 코드 사전을 생성합니다."""
    plan_records = [
        build_remediation_plan_record(row)
        for _, row in remediation_source_df.iterrows()
    ]
    plan_df = pd.DataFrame(
        plan_records,
        columns=REMEDIATION_PLAN_COLUMNS,
    )
    terraform_code_map = {
        record["identity"]: record["terraform_code"]
        for record in plan_records
        if record["terraform_supported"]
    }
    return plan_df, terraform_code_map


def select_focus_remediation(plan_df, terraform_code_map):
    """가장 우선순위가 높은 대상과 해당 Terraform 초안을 선택합니다."""
    if plan_df.empty:
        return None, None

    focus_identity = str(plan_df.iloc[0]["identity"])
    focus_code = terraform_code_map.get(focus_identity)
    return focus_identity, focus_code


def validate_remediation_plan_outputs(
    plan_df,
    targets_df,
    terraform_code_map,
):
    """생성된 Plan과 Terraform 결과의 출력 계약을 검증합니다."""
    if not isinstance(plan_df, pd.DataFrame):
        raise TypeError("plan_df는 DataFrame이어야 합니다.")
    if plan_df["identity"].duplicated().any():
        raise ValueError("plan_df는 identity당 한 행이어야 합니다.")
    if set(plan_df["identity"]) != set(targets_df["identity"]):
        raise ValueError("Plan 대상과 Remediation 대상이 다릅니다.")

    for column in [
        "triggered_rules",
        "graph_evidence",
        "raw_policy_evidence",
        "recommendation",
        "manual_steps",
    ]:
        if not plan_df[column].map(
            lambda value: isinstance(value, list)
        ).all():
            raise TypeError(f"{column}의 값은 list여야 합니다.")

    supported_identities = set(
        plan_df.loc[plan_df["terraform_supported"], "identity"]
    )
    if set(terraform_code_map) != supported_identities:
        raise ValueError(
            "Terraform 코드와 지원 대상 identity가 일치하지 않습니다."
        )


def run_remediation_plan_generation(targets_df, actions_df):
    """Cell 11-3의 병합·Plan 생성·Focus 선택을 실행합니다."""
    validate_remediation_plan_inputs(targets_df, actions_df)
    source_df = merge_remediation_sources(targets_df, actions_df)
    plan_df, terraform_code_map = generate_remediation_plans(source_df)
    focus_identity, focus_code = select_focus_remediation(
        plan_df,
        terraform_code_map,
    )
    validate_remediation_plan_outputs(
        plan_df,
        targets_df,
        terraform_code_map,
    )

    return {
        "source_df": source_df,
        "plan_df": plan_df,
        "terraform_code_map": terraform_code_map,
        "focus_identity": focus_identity,
        "focus_terraform_code": focus_code,
        "preview_columns": REMEDIATION_PLAN_PREVIEW_COLUMNS.copy(),
    }


print("Cell 11-3A completed: remediation plan functions defined.")


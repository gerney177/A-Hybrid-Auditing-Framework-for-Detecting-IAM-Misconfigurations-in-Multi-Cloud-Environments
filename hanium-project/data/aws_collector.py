# data/aws_collector.py
from datetime import datetime, timezone

import boto3


def collect_aws_iam(profile_name="haneium-sdk"):
    """실제 AWS IAM 설정과 정책 원본을 조회한다."""
    session = boto3.Session(profile_name=profile_name)

    caller = session.client("sts").get_caller_identity()

    if not caller["Arn"].endswith(":user/haneium-reader"):
        raise RuntimeError("haneium-reader 인증을 사용하세요.")

    iam = session.client("iam")

    snapshot = {
        "source": "aws",
        "account_id": caller["Account"],
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "users": [],
        "groups": [],
        "roles": [],
        "managed_policies": [],
    }

    paginator = iam.get_paginator(
        "get_account_authorization_details"
    )

    for page in paginator.paginate(
        Filter=[
            "User",
            "Group",
            "Role",
            "LocalManagedPolicy",
            "AWSManagedPolicy",
        ]
    ):
        snapshot["users"].extend(
            page.get("UserDetailList", [])
        )
        snapshot["groups"].extend(
            page.get("GroupDetailList", [])
        )
        snapshot["roles"].extend(
            page.get("RoleDetailList", [])
        )
        snapshot["managed_policies"].extend(
            page.get("Policies", [])
        )

    return snapshot
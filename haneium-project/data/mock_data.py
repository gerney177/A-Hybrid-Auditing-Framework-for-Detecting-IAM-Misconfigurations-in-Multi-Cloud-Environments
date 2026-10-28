# data/mock_data.py
# AWS / Azure / GCP 시연 데이터 생성 및 검증

import random
import numpy as np
import pandas as pd
from IPython.display import display

from config import SEED


def generate_aws_policy(identity_name, is_risky=False):
    statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{identity_name}-bucket/*",
            "Principal": {"AWS": f"arn:aws:iam::{identity_name}"}
        }
    ]

    if is_risky:
        statements.append({
            "Effect": "Allow",
            "Action": ["s3:*", "iam:PassRole"],
            "Resource": "*",
            "Principal": {"AWS": f"arn:aws:iam::{identity_name}"}
        })

    return {
        "Version": "2012-10-17",
        "Statement": statements
    }


def generate_azure_policy(identity_name, is_risky=False):
    actions = [
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    ]

    if is_risky:
        actions.append("Microsoft.Authorization/roleAssignments/write")

    return {
        "principal": identity_name,
        "role": "Reader",
        "actions": actions
    }


def generate_gcp_policy(identity_name, is_risky=False):
    permissions = ["storage.objects.get"]

    if is_risky:
        permissions.append("resourcemanager.projects.setIamPolicy")

    return {
        "binding": {
            "members": [f"user:{identity_name}@example.com"],
            "role": "roles/viewer",
            "permissions": permissions
        }
    }


def generate_mock_data(seed=SEED):
    # 같은 seed로 데이터 생성 결과를 재현한다.
    random.seed(seed)
    np.random.seed(seed)
    print(f"Random seeds re-initialized to {seed} for Cell 4.")

    # --- 1. Identity 및 CSP 매핑 정의 ---
    # 사용자 25명 목록
    identities = [
        'developer01', 'admin01', 'auditor01', 'dataanalyst01', 'devops01',
        'guest01', 'testuser01', 'serviceaccount01', 'monitor01',
        'securityadmin01',
        'userA', 'userB', 'userC', 'userD', 'userE',
        'userF', 'userG', 'userH', 'userI', 'userJ',
        'userK', 'userL', 'userM', 'userN', 'userO'
    ]

    csp_options = ['AWS', 'Azure', 'GCP']

    # developer01은 AWS로 고정한다.
    identity_to_csp = {'developer01': 'AWS'}

    # 나머지 사용자는 AWS → Azure → GCP 순서로 반복 배정한다.
    remaining_identities = [
        id for id in identities if id != 'developer01'
    ]

    for id_idx, identity in enumerate(remaining_identities):
        identity_to_csp[identity] = csp_options[
            id_idx % len(csp_options)
        ]

    assert all(
        csp in identity_to_csp.values() for csp in csp_options
    ), "All CSPs must be represented."

    print(
        f"Generated {len(identities)} identities "
        "with consistent CSP assignments."
    )

    # --- 1-b. 위험 시나리오 정의 ---
    # 정책 위험과 행동 이상을 나눠 각 분석 레이어의 탐지를 확인한다.
    RISK_SCENARIOS = {
        # AWS: 위험 정책 + 관리자/MFA 설정 문제 + 행동 이상
        "developer01": "wildcard_and_passrole",

        # Azure: 정책에 권한 상승 액션 포함, 메타데이터·행동은 정상
        "auditor01": "role_assignment_write",

        # GCP: 정책에 권한 상승 권한 포함, 메타데이터·행동은 정상
        "dataanalyst01": "set_iam_policy",

        # AWS: 정책·메타데이터는 정상이고 행동 로그만 이상
        "serviceaccount01": "behavior_only",
    }

    # 비정상 행동 로그를 생성할 사용자
    ANOMALOUS_BEHAVIOR_IDENTITIES = {
        identity
        for identity, scenario in RISK_SCENARIOS.items()
        if scenario in ("wildcard_and_passrole", "behavior_only")
    }

    print(
        f"Risk scenarios defined for {len(RISK_SCENARIOS)} identities:"
    )
    for identity, scenario in RISK_SCENARIOS.items():
        print(
            f"  - {identity} ({identity_to_csp[identity]}): {scenario}"
        )

    # behavior_only는 정책이 정상이어야 하므로 정책 위험 대상에서 제외한다.
    POLICY_RISK_SCENARIOS = {
        identity
        for identity, scenario in RISK_SCENARIOS.items()
        if scenario != "behavior_only"
    }

    # --- 2. Multi-Cloud IAM Policy Data 생성 ---
    mock_iam_policy_data = []

    for identity in identities:
        csp = identity_to_csp[identity]
        is_risky = identity in POLICY_RISK_SCENARIOS

        if csp == 'AWS':
            policy_doc = generate_aws_policy(identity, is_risky)
        elif csp == 'Azure':
            policy_doc = generate_azure_policy(identity, is_risky)
        else:
            policy_doc = generate_gcp_policy(identity, is_risky)

        mock_iam_policy_data.append({
            "identity": identity,
            "csp": csp,
            "raw_policy_document": policy_doc
        })

    print(
        f"Generated {len(mock_iam_policy_data)} IAM Policy Data entries."
    )

    # --- 3. Identity Security Metadata 생성 ---
    identity_metadata_list = []
    privilege_levels = {'Low': 1, 'Medium': 2, 'High': 3}

    # 시연 대상 계정에 사용할 보안 설정을 미리 지정한다.
    # developer01은 관리자급 권한에 맞춰 is_admin=True를 사용한다.
    SCENARIO_METADATA_OVERRIDES = {
        'developer01': {
            'role': 'Developer',
            'is_admin': True,
            'mfa_enabled': False,
            'has_api_key': True,
            'privilege_level': 'High',
        },
        'auditor01': {
            # 정책 위험만으로 탐지되는지 확인하기 위한 설정
            'role': 'Auditor',
            'is_admin': False,
            'mfa_enabled': True,
            'has_api_key': False,
            'privilege_level': 'Medium',
        },
        'dataanalyst01': {
            'role': 'DataAnalyst',
            'is_admin': False,
            'mfa_enabled': True,
            'has_api_key': False,
            'privilege_level': 'Medium',
        },
        'serviceaccount01': {
            # 행동 로그만 이상한 시나리오
            'role': 'Operator',
            'is_admin': False,
            'mfa_enabled': True,
            'has_api_key': False,
            'privilege_level': 'Low',
        },
    }

    for identity in identities:
        csp = identity_to_csp[identity]
        scenario = RISK_SCENARIOS.get(identity)

        if identity in SCENARIO_METADATA_OVERRIDES:
            # 시연 대상은 미리 지정한 설정을 사용한다.
            override = SCENARIO_METADATA_OVERRIDES[identity]
            level_name = override['privilege_level']

            identity_metadata_list.append({
                'identity': identity,
                'cloud_provider': csp,
                'role': override['role'],
                'is_admin': override['is_admin'],
                'mfa_enabled': override['mfa_enabled'],
                'has_api_key': override['has_api_key'],
                'privilege_level': level_name,
                'privilege_level_numeric': privilege_levels[level_name],
                'is_true_risk': scenario is not None,
                'risk_scenario': scenario,
            })
        else:
            # 일반 사용자는 원본의 선택 범위에서 무작위 생성한다.
            is_admin = random.choice([False, False, False, True])
            mfa_enabled = random.choice([True, True, True, False])
            has_api_key = random.choice([False, False, False, True])
            role = random.choice([
                'Viewer', 'Auditor', 'Developer', 'Operator'
            ])

            level_name = (
                random.choice(['Low', 'Medium'])
                if not is_admin else 'High'
            )

            identity_metadata_list.append({
                'identity': identity,
                'cloud_provider': csp,
                'role': role,
                'is_admin': is_admin,
                'mfa_enabled': mfa_enabled,
                'has_api_key': has_api_key,
                'privilege_level': level_name,
                'privilege_level_numeric': privilege_levels[level_name],
                'is_true_risk': scenario is not None,
                'risk_scenario': scenario,
            })

    mock_identity_security_metadata = pd.DataFrame(
        identity_metadata_list
    )

    print(
        f"Generated {len(mock_identity_security_metadata)} "
        "Identity Security Metadata entries."
    )

    # --- 4. User Behavior Log Data 생성 ---
    behavior_log_list = []

    for identity in identities:
        csp = identity_to_csp[identity]

        if identity in ANOMALOUS_BEHAVIOR_IDENTITIES:
            # 심야 로그인, 높은 API 호출 수, 높은 로그인 실패 수
            behavior_log_list.append({
                'identity': identity,
                'cloud_provider': csp,
                'login_hour': random.choice([0, 1, 2, 22, 23]),
                'api_call_count': random.randint(5000, 10000),
                'failed_login_count': random.randint(8, 20)
            })
        else:
            # 정상 범위로 정한 값에서 행동 로그를 생성한다.
            behavior_log_list.append({
                'identity': identity,
                'cloud_provider': csp,
                'login_hour': random.randint(7, 19),
                'api_call_count': random.randint(100, 1000),
                'failed_login_count': random.randint(0, 2)
            })

    mock_behavior_log_data = pd.DataFrame(behavior_log_list)

    print(
        f"Generated {len(mock_behavior_log_data)} "
        "Behavior Log Data entries."
    )

    # 생성 데이터와 검증에 필요한 정보를 호출한 쪽에 전달한다.
    return {
        "policies": mock_iam_policy_data,
        "metadata": mock_identity_security_metadata,
        "behavior": mock_behavior_log_data,

        # 원본 검증에서 사용하는 정보
        "identities": identities,
        "identity_to_csp": identity_to_csp,
        "risk_scenarios": RISK_SCENARIOS,
    }

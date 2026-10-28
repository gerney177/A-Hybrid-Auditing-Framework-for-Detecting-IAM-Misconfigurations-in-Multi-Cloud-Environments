# checks/check_mock_data.py
# 원본 Cell 4의 데이터 생성 결과를 검증한다.

import pandas as pd
from IPython.display import display

from data.mock_data import generate_mock_data
# 데이터를 생성하고, 원본 검증에서 쓰던 변수 이름으로 연결한다.
data = generate_mock_data()

mock_iam_policy_data = data["policies"]
mock_identity_security_metadata = data["metadata"]
mock_behavior_log_data = data["behavior"]

identities = data["identities"]
identity_to_csp = data["identity_to_csp"]
RISK_SCENARIOS = data["risk_scenarios"]
   
# --- 5. 검증 코드 ---
print("\n--- Mock Data Generation Verification ---")

# 1. 전체 identity 수
print(f"Total Identities: {len(identities)}")

# 2. CSP별 identity 개수
csp_counts = pd.Series(identity_to_csp).value_counts()
print(f"CSP-wise Identity Counts:\n{csp_counts}")

# developer01 데이터 추출
developer01_iam = next(
    (
        item for item in mock_iam_policy_data
        if item['identity'] == 'developer01'
    ),
    None
)
developer01_meta = mock_identity_security_metadata[
    mock_identity_security_metadata['identity'] == 'developer01'
].iloc[0]
developer01_bh = mock_behavior_log_data[
    mock_behavior_log_data['identity'] == 'developer01'
].iloc[0]

# 3. developer01의 CSP
print(f"\ndeveloper01's CSP: {identity_to_csp['developer01']}")
assert identity_to_csp['developer01'] == 'AWS', (
    "developer01의 CSP는 AWS여야 합니다."
)

# 4. developer01의 raw AWS IAM Policy
print("\ndeveloper01's Raw AWS IAM Policy:")
display(developer01_iam['raw_policy_document'])

assert 'Statement' in developer01_iam['raw_policy_document'], (
    "developer01 AWS Policy에 'Statement' 키가 있어야 합니다."
)

# s3:*와 iam:PassRole 포함 여부 검증
aws_actions = []
for stmt in developer01_iam['raw_policy_document']['Statement']:
    actions = stmt.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    aws_actions.extend(actions)

assert 's3:*' in aws_actions, (
    "developer01 AWS Policy에 's3:*' 액션이 포함되어야 합니다."
)
assert 'iam:PassRole' in aws_actions, (
    "developer01 AWS Policy에 'iam:PassRole' 액션이 포함되어야 합니다."
)
print(
    "developer01 AWS Policy에 's3:*'와 'iam:PassRole'이 "
    "모두 존재합니다. (검증 완료)"
)

# 5. developer01의 Identity Security Metadata
print("\ndeveloper01's Identity Security Metadata:")
display(developer01_meta)

assert developer01_meta['mfa_enabled'] == False, (
    "developer01의 MFA는 False여야 합니다."
)
assert developer01_meta['is_admin'] == True, (
    "developer01은 관리자급 권한(High privilege)이므로 "
    "is_admin은 True여야 합니다."
)
assert developer01_meta['has_api_key'] == True, (
    "developer01의 has_api_key는 True여야 합니다."
)
print(
    "developer01 메타데이터 "
    "(mfa_enabled, is_admin, has_api_key) 검증 완료."
)

# 6. developer01의 Behavior Log
print("\ndeveloper01's Behavior Log:")
display(developer01_bh)

# 모든 데이터에서 사용자의 CSP가 일치하는지 검증
for identity in identities:
    expected_csp = identity_to_csp[identity]

    iam_csp = next(
        (
            item['csp'] for item in mock_iam_policy_data
            if item['identity'] == identity
        ),
        None
    )
    assert iam_csp == expected_csp, (
        f"IAM Policy Data의 {identity} CSP 불일치: "
        f"{iam_csp} != {expected_csp}"
    )

    meta_csp = mock_identity_security_metadata[
        mock_identity_security_metadata['identity'] == identity
    ]['cloud_provider'].iloc[0]
    assert meta_csp == expected_csp, (
        f"Identity Metadata의 {identity} CSP 불일치: "
        f"{meta_csp} != {expected_csp}"
    )

    bh_csp = mock_behavior_log_data[
        mock_behavior_log_data['identity'] == identity
    ]['cloud_provider'].iloc[0]
    assert bh_csp == expected_csp, (
        f"Behavior Log Data의 {identity} CSP 불일치: "
        f"{bh_csp} != {expected_csp}"
    )

print("모든 identity의 CSP 일관성 검증 완료.")

# 7. 신규 위험 시나리오 검증
print("\n--- Additional Risk Scenario Verification ---")

# 7-1. auditor01 (Azure): 권한 상승 액션 확인
auditor01_iam = next(
    (
        item for item in mock_iam_policy_data
        if item['identity'] == 'auditor01'
    ),
    None
)
assert auditor01_iam is not None, (
    "auditor01 IAM policy를 찾을 수 없습니다."
)

auditor01_actions = auditor01_iam[
    'raw_policy_document'
].get('actions', [])

assert (
    'Microsoft.Authorization/roleAssignments/write'
    in auditor01_actions
), "auditor01 Azure Policy에 권한 상승 액션이 포함되어야 합니다."

print("auditor01 (Azure) 권한 상승 시나리오 검증 완료.")

# 7-2. dataanalyst01 (GCP): 권한 상승 permission 확인
dataanalyst01_iam = next(
    (
        item for item in mock_iam_policy_data
        if item['identity'] == 'dataanalyst01'
    ),
    None
)
assert dataanalyst01_iam is not None, (
    "dataanalyst01 IAM policy를 찾을 수 없습니다."
)

dataanalyst01_permissions = dataanalyst01_iam[
    'raw_policy_document'
]['binding'].get('permissions', [])

assert (
    'resourcemanager.projects.setIamPolicy'
    in dataanalyst01_permissions
), "dataanalyst01 GCP Policy에 권한 상승 permission이 포함되어야 합니다."

print("dataanalyst01 (GCP) 권한 상승 시나리오 검증 완료.")

# 7-3. serviceaccount01: 행동 이상 시나리오 검증
serviceaccount01_iam = next(
    (
        item for item in mock_iam_policy_data
        if item['identity'] == 'serviceaccount01'
    ),
    None
)
serviceaccount01_meta = mock_identity_security_metadata[
    mock_identity_security_metadata['identity'] == 'serviceaccount01'
].iloc[0]
serviceaccount01_bh = mock_behavior_log_data[
    mock_behavior_log_data['identity'] == 'serviceaccount01'
].iloc[0]

assert serviceaccount01_meta['is_admin'] == False, (
    "serviceaccount01의 is_admin은 False여야 합니다 (정책상 정상)."
)
assert serviceaccount01_meta['mfa_enabled'] == True, (
    "serviceaccount01의 mfa_enabled는 True여야 합니다 (정책상 정상)."
)
assert serviceaccount01_bh['api_call_count'] >= 5000, (
    "serviceaccount01은 AI 단독 탐지 케이스이므로 "
    "행동 로그가 이상 패턴이어야 합니다."
)

print(
    "serviceaccount01 (AI 단독 탐지 케이스) "
    "정책/메타데이터 정상 + 행동 이상 검증 완료."
)

# 7-4. 정답 라벨이 위험 시나리오 사용자 목록과 일치하는지 확인
labelled_risky = set(
    mock_identity_security_metadata.loc[
        mock_identity_security_metadata['is_true_risk'],
        'identity'
    ]
)

assert labelled_risky == set(RISK_SCENARIOS.keys()), (
    "is_true_risk 라벨이 RISK_SCENARIOS와 일치하지 않습니다: "
    f"{labelled_risky} != {set(RISK_SCENARIOS.keys())}"
)

print(
    f"is_true_risk 정답 라벨 검증 완료 "
    f"({len(labelled_risky)}개 identity)."
)

print(
    "\nCell 4 Mock Multi-Cloud IAM Data Generation "
    "completed successfully."
)

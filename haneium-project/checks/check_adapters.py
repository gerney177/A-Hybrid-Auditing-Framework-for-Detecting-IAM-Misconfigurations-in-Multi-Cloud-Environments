# 원본 Cell 5의 정책 추출 결과 검증
# 원본 Cell 5의 정책 추출 결과 검증

from data.mock_data import generate_mock_data
from preprocessing.adapters import extract_statements


# 원본 검증에서 사용하는 정책 데이터 준비
data = generate_mock_data()
mock_iam_policy_data = data["policies"]

print("Defined `extract_statements` function and helper adapters.")

# --- 검증 테스트 ---
print("\n--- Cell 5 CSP Policy Adapter Validation ---")

# 1. AWS Adapter Result (developer01)
print("\n--- AWS Adapter Result (developer01) ---")
developer01_iam_policy = next((p for p in mock_iam_policy_data if p['identity'] == 'developer01' and p['csp'] == 'AWS'), None)
if developer01_iam_policy:
    aws_statements = extract_statements(developer01_iam_policy['csp'], developer01_iam_policy['raw_policy_document'])
    for stmt in aws_statements:
        print(f"Principal: {stmt['principal']}, Actions: {stmt['actions']}, Scope: {stmt['scope']}, Effect: {stmt['effect']}")
        # Contract Validation
        assert isinstance(stmt['principal'], str) and stmt['principal'] == 'developer01', f"Invalid principal: {stmt['principal']}"
        assert isinstance(stmt['actions'], list), f"Actions must be list: {stmt['actions']}"
        assert all(isinstance(a, str) for a in stmt['actions']), f"Actions elements must be str: {stmt['actions']}"
        assert isinstance(stmt['scope'], str), f"Invalid scope: {stmt['scope']}"
        assert isinstance(stmt['effect'], str), f"Invalid effect: {stmt['effect']}"

    # developer01 specific actions validation
    all_dev01_actions = [a for stmt in aws_statements for a in stmt['actions']]
    assert 's3:*' in all_dev01_actions, "developer01 AWS Policy에 's3:*'가 없습니다."
    assert 'iam:PassRole' in all_dev01_actions, "developer01 AWS Policy에 'iam:PassRole'이 없습니다."
    print("developer01 AWS Policy (s3:*, iam:PassRole) 및 Principal Canonicalization 검증 완료.")
else:
    print("developer01 AWS IAM Policy not found.")

# 2. Azure Adapter Result (샘플)
print("\n--- Azure Adapter Result (Sample) ---")
azure_sample_policy = next((p for p in mock_iam_policy_data if p['csp'] == 'Azure'), None)
if azure_sample_policy:
    azure_statements = extract_statements(azure_sample_policy['csp'], azure_sample_policy['raw_policy_document'])
    for stmt in azure_statements:
        print(f"Principal: {stmt['principal']}, Actions: {stmt['actions']}, Scope: {stmt['scope']}, Effect: {stmt['effect']}")
        # Contract Validation (대표로 한 번만)
        assert isinstance(stmt['principal'], str)
        assert isinstance(stmt['actions'], list)
        assert all(isinstance(a, str) for a in stmt['actions'])
        assert isinstance(stmt['scope'], str)
        assert isinstance(stmt['effect'], str)
else:
    print("Azure IAM Policy sample not found.")


# 3. GCP Adapter Result (샘플)
print("\n--- GCP Adapter Result (Sample) ---")
gcp_sample_policy = next((p for p in mock_iam_policy_data if p['csp'] == 'GCP'), None)
if gcp_sample_policy:
    gcp_statements = extract_statements(gcp_sample_policy['csp'], gcp_sample_policy['raw_policy_document'])
    for stmt in gcp_statements:
        print(f"Principal: {stmt['principal']}, Actions: {stmt['actions']}, Scope: {stmt['scope']}, Effect: {stmt['effect']}")
        # Contract Validation (대표로 한 번만)
        assert isinstance(stmt['principal'], str)
        assert isinstance(stmt['actions'], list)
        assert all(isinstance(a, str) for a in stmt['actions'])
        assert isinstance(stmt['scope'], str)
        assert isinstance(stmt['effect'], str)

    # GCP Principal Canonicalization 및 Action/Scope 분리 검증 강화
    for stmt in gcp_statements:
        # user principal은 'user:' 접두사와 '@' 이메일 형식을 포함하지 않아야 함
        if not stmt['principal'].startswith('serviceAccount:'):
            assert 'user:' not in stmt['principal'], f"GCP user principal에 'user:'가 남아있습니다: {stmt['principal']}"
            assert '@' not in stmt['principal'], f"GCP user principal에 '@'가 남아있습니다: {stmt['principal']}"
        # actions에 role이 포함되지 않고 permissions만 포함되는지 검증
        assert 'roles/viewer' not in stmt['actions'], f"GCP actions에 role이 포함되어 있습니다: {stmt['actions']}"
        assert 'storage.objects.get' in stmt['actions'], f"GCP actions에 'storage.objects.get'이 없습니다: {stmt['actions']}"
        # scope는 role만 포함하는지 검증
        assert stmt['scope'] == 'roles/viewer', f"GCP scope가 'roles/viewer'가 아닙니다: {stmt['scope']}"

    print("GCP User Principal Canonicalization 및 Action/Scope 분리 검증 완료.")
else:
    print("GCP IAM Policy sample not found.")


# 4. GCP Multi-Member Validation (Local Test Object)
print("\n--- GCP Multi-Member Validation (Local Test Object) ---")
gcp_multi_member_raw = {
    "binding": {
        "members": [
            "user:testuser1@example.com",
            "serviceAccount:testsa@project.iam.gserviceaccount.com"
        ],
        "role": "roles/editor",
        "permissions": [
            "compute.instances.start",
            "compute.instances.stop"
        ]
    }
}
multi_member_statements = extract_statements('GCP', gcp_multi_member_raw)
assert len(multi_member_statements) == 2, "Multi-member GCP policy should produce 2 statements."
assert multi_member_statements[0]['principal'] == 'testuser1', "First principal should be 'testuser1'."
assert 'user:' not in multi_member_statements[0]['principal'], f"GCP user principal에 'user:'가 남아있습니다: {multi_member_statements[0]['principal']}"
assert '@' not in multi_member_statements[0]['principal'], f"GCP user principal에 '@'가 남아있습니다: {multi_member_statements[0]['principal']}"

assert multi_member_statements[1]['principal'] == 'testsa@project.iam.gserviceaccount.com', "Second principal should be 'testsa@project.iam.gserviceaccount.com'."
assert '@' in multi_member_statements[1]['principal'], "GCP serviceAccount principal에 '@'가 있어야 합니다."

# Action/Scope 분리 검증
assert multi_member_statements[0]['scope'] == 'roles/editor', "GCP multi-member scope가 'roles/editor'가 아닙니다."
assert 'roles/editor' not in multi_member_statements[0]['actions'], "GCP multi-member actions에 role이 포함되어 있습니다."
assert 'compute.instances.start' in multi_member_statements[0]['actions'], "GCP multi-member actions에 'compute.instances.start'가 없습니다."
assert 'compute.instances.stop' in multi_member_statements[0]['actions'], "GCP multi-member actions에 'compute.instances.stop'이 없습니다."

print("GCP Multi-Member 정책 처리 및 Principal Canonicalization 검증 완료.")


# 5. AWS Action Robustness Validation (Local Test Object - Single Action String)
print("\n--- AWS Single Action String Validation (Local Test Object) ---")
aws_single_action_raw = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject", # 단일 문자열 액션
            "Resource": "arn:aws:s3:::single-action-bucket/*",
            "Principal": {"AWS": "arn:aws:iam::singleuser"}
        }
    ]
}
aws_single_action_statements = extract_statements('AWS', aws_single_action_raw)
assert len(aws_single_action_statements) == 1, "Single action policy should produce 1 statement."
assert aws_single_action_statements[0]['actions'] == ['s3:GetObject'], "Single action string should be converted to list."
print("AWS 단일 액션 문자열 처리 검증 완료.")


print("\nCell 5 CSP Policy Adapter validation completed successfully.")
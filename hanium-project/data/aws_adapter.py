# data/aws_adapter.py
import copy
import json
from urllib.parse import unquote


def decode_policy_document(document):
    """정책 본문을 딕셔너리로 변환."""
    if isinstance(document, dict):
        return copy.deepcopy(document)

    if isinstance(document, str):
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError:
            parsed = json.loads(unquote(document))

        if isinstance(parsed, dict):
            return parsed

    raise ValueError("정책 본문이 올바른 JSON 객체가 아닙니다.")


def extract_aws_user_policies(snapshot, allow_group_membership=False):
    """사용자에게 직접 연결된 정책 본문을 추출."""
    managed_map = {
        policy["Arn"]: policy
        for policy in snapshot["managed_policies"]
    }

    policy_items = []

    for user in snapshot["users"]:
        # 직접 정책만 요청한 호출에서는 그룹 권한 누락을 명시적으로 알린다.
        # 통합 추출기는 별도 그룹 연결 함수를 호출한다.
        if user.get("GroupList") and not allow_group_membership:
            raise NotImplementedError(
                f"{user['UserName']}: 그룹 정책 연결 처리가 필요합니다."
            )

        # 사용자에게 직접 연결된 관리형 정책
        for attached in user.get("AttachedManagedPolicies", []):
            policy_arn = attached["PolicyArn"]

            if policy_arn not in managed_map:
                raise ValueError(f"정책 본문을 찾을 수 없습니다: {policy_arn}")

            managed = managed_map[policy_arn]

            default_versions = [
                version
                for version in managed.get("PolicyVersionList", [])
                if version.get("IsDefaultVersion")
            ]

            if len(default_versions) != 1:
                raise ValueError(
                    f"기본 정책 버전을 확인할 수 없습니다: {policy_arn}"
                )

            document = decode_policy_document(
                default_versions[0]["Document"]
            )

            policy_items.append({
                "identity": user["Arn"],
                "identity_name": user["UserName"],
                "csp": "AWS",
                "policy_name": attached["PolicyName"],
                "policy_arn": policy_arn,
                "policy_type": "managed",
                "raw_policy_document": document,
            })

        # 사용자에게 직접 작성한 인라인 정책
        for inline in user.get("UserPolicyList", []):
            policy_items.append({
                "identity": user["Arn"],
                "identity_name": user["UserName"],
                "csp": "AWS",
                "policy_name": inline["PolicyName"],
                "policy_arn": None,
                "policy_type": "inline",
                "raw_policy_document": decode_policy_document(
                    inline["PolicyDocument"]
                ),
            })

    return policy_items


def extract_aws_role_policies(snapshot):
    """역할의 권한 정책만 추출한다. AssumeRolePolicyDocument는 신뢰 정책이다."""
    managed_map = {p['Arn']: p for p in snapshot['managed_policies']}
    items = []
    for role in snapshot.get('roles', []):
        identity = role['Arn']
        common = {
            'identity': identity,
            'identity_name': role['RoleName'],
            'identity_type': 'role',
            'attachment_type': 'role_direct',
            'policy_source_identity': identity,
            'csp': 'AWS',
        }
        for attached in role.get('AttachedManagedPolicies', []):
            arn = attached['PolicyArn']
            if arn not in managed_map:
                raise ValueError(f"역할 {role['RoleName']}: 정책 본문을 찾을 수 없습니다: {arn}")
            versions = [v for v in managed_map[arn].get('PolicyVersionList', []) if v.get('IsDefaultVersion')]
            if len(versions) != 1:
                raise ValueError(f"역할 {role['RoleName']}: 기본 정책 버전을 확인할 수 없습니다: {arn}")
            items.append({
                **common,
                'policy_name': attached['PolicyName'],
                'policy_arn': arn,
                'policy_type': 'managed',
                'policy_version': versions[0].get('VersionId'),
                'raw_policy_document': decode_policy_document(versions[0]['Document']),
            })
        for inline in role.get('RolePolicyList', []):
            items.append({
                **common,
                'policy_name': inline['PolicyName'],
                'policy_arn': None,
                'policy_id': f"{identity}:policy/{inline['PolicyName']}",
                'policy_type': 'inline',
                'policy_version': None,
                'raw_policy_document': decode_policy_document(inline['PolicyDocument']),
            })
    return items


def extract_aws_group_policies(snapshot):
    """그룹 자체가 아닌 소속 사용자에게 그룹의 권한 정책을 연결한다."""
    groups = {}
    for group in snapshot.get('groups', []):
        name = group['GroupName']
        if name in groups:
            raise ValueError(f'중복된 그룹 이름: {name}')
        groups[name] = group
    managed = {p['Arn']: p for p in snapshot['managed_policies']}
    items = []
    for user in snapshot['users']:
        memberships = user.get('GroupList', [])
        if not isinstance(memberships, list) or not all(isinstance(name, str) and name for name in memberships):
            raise ValueError(f"{user['UserName']}: GroupList는 그룹 이름 목록이어야 합니다.")
        for name in dict.fromkeys(memberships):
            if name not in groups:
                raise ValueError(f"{user['UserName']}: 소속 그룹 본문을 찾을 수 없습니다: {name}")
            group = groups[name]
            common = {
                'identity': user['Arn'], 'identity_name': user['UserName'],
                'identity_type': 'user', 'csp': 'AWS',
                'attachment_type': 'group', 'policy_source_identity': group['Arn'],
                'group_name': name, 'group_arn': group['Arn'],
            }
            for attached in group.get('AttachedManagedPolicies', []):
                arn = attached['PolicyArn']
                if arn not in managed:
                    raise ValueError(f'그룹 {name}: 정책 본문을 찾을 수 없습니다: {arn}')
                versions = [v for v in managed[arn].get('PolicyVersionList', []) if v.get('IsDefaultVersion')]
                if len(versions) != 1:
                    raise ValueError(f'그룹 {name}: 기본 정책 버전을 확인할 수 없습니다: {arn}')
                items.append({
                    **common, 'policy_name': attached['PolicyName'], 'policy_arn': arn,
                    'policy_type': 'managed', 'policy_version': versions[0].get('VersionId'),
                    'permission_path': [user['Arn'], group['Arn'], arn],
                    'raw_policy_document': decode_policy_document(versions[0]['Document']),
                })
            for inline in group.get('GroupPolicyList', []):
                policy_id = f"{group['Arn']}:policy/{inline['PolicyName']}"
                items.append({
                    **common, 'policy_name': inline['PolicyName'], 'policy_arn': None,
                    'policy_id': policy_id, 'policy_type': 'inline', 'policy_version': None,
                    'permission_path': [user['Arn'], group['Arn'], policy_id],
                    'raw_policy_document': decode_policy_document(inline['PolicyDocument']),
                })
    return items


def extract_aws_identity_policies(snapshot):
    """사용자 직접·그룹 경유 정책과 역할 정책을 출처와 함께 합친다."""
    users = extract_aws_user_policies(snapshot, allow_group_membership=True)
    for item in users:
        item.update({
            'identity_type': 'user',
            'attachment_type': 'user_direct',
            'policy_source_identity': item['identity'],
        })
        if item['policy_type'] == 'inline':
            item['policy_id'] = f"{item['identity']}:policy/{item['policy_name']}"
    roles = extract_aws_role_policies(snapshot)
    for item in users + roles:
        item['permission_path'] = [item['identity'], item.get('policy_arn') or item['policy_id']]
    return users + extract_aws_group_policies(snapshot) + roles

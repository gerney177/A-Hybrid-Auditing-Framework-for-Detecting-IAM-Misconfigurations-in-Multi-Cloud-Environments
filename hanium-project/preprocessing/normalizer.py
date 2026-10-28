# preprocessing/normalizer.py
# Unified IAM Normalization Engine

import networkx as nx

from preprocessing.adapters import extract_statements


# 클라우드별 권한을 (자원 종류, 공통 작업)으로 연결
GENERIC_ACTION_MAP = {
    "s3:GetObject": ("ObjectStorage", "READ"),
    "s3:PutObject": ("ObjectStorage", "CREATE"),
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read":
        ("ObjectStorage", "READ"),
    "storage.objects.get": ("ObjectStorage", "READ"),
    "iam:PutRolePolicy": ("Identity", "MANAGE"),
}


def normalize_policy(
    csp: str,
    raw: dict,
    identity: str | None = None,
) -> list[dict]: # 수정이유 identitiy랑 aws에서 받아오는거랑 일치하지 않아서 연결시키려고 바꿧어요
    """AWS(JSON Policy) / Azure(RBAC) / GCP(IAM Binding)
    → 공통 형식의 IAM 레코드 목록
    """
    records = []

    # 클라우드별 정책에서 사용자, 권한 목록, 범위 등을 추출
    for stmt in extract_statements(csp, raw):

        # 권한 하나당 레코드 하나 생성
        for action in stmt["actions"]:

            # 대응표에 없는 권한은 Unknown / UNKNOWN으로 기록
            resource, op = GENERIC_ACTION_MAP.get(
                action, ("Unknown", "UNKNOWN")
            )

            records.append({
                "identity": (
                    identity
                    if csp == "AWS" and identity is not None
                    else stmt["principal"]
                ),#AWS정책이고, 전달받은 사용자의 식별자가 있으면 그 값을 사용
                "operation": op,
                "original_action": action,#추가
                "target": f"{resource}:{stmt['scope']}",
                "original_resources": stmt.get("original_resources"),#추가:AWS 어댑터가 전달한 목록을 그대로 저장, 다른 클라우드는 아직 필드 전달안해서 None으로 남음
                "condition": stmt.get("condition", {}),
                "effect": stmt.get("effect", "Allow"),
                "is_wildcard": "*" in action,
                "source_csp": csp,
            })

    return records


def to_graph(records):
    """사용자 → 대상 방향으로 권한 정보를 가진 간선을 생성한다."""

    # 같은 사용자와 대상 사이에 여러 권한 간선을 저장할 수 있는 방향 그래프
    g = nx.MultiDiGraph()

    for r in records:
        g.add_edge(
            r["identity"],
            r["target"],
            op=r["operation"],
            effect=r["effect"],
            wildcard=r["is_wildcard"]
        )

    return g


def normalize_policy_dataset(policy_items: list[dict], strict=False) -> list[dict]:
    """
    정책 목록을 순회하며 normalize_policy()를 호출하고,
    모든 변환 결과를 하나의 리스트로 모아 반환한다.
    """
    all_normalized_records = []

    for item in policy_items:
        csp = item['csp']
        raw_policy_document = item['raw_policy_document']

        try:
            if strict and csp == 'AWS':
                statements = raw_policy_document.get('Statement')
                if isinstance(statements, dict):
                    statements = [statements]
                if not isinstance(statements, list) or not statements:
                    raise ValueError('Statement가 비어 있거나 목록/객체 형식이 아닙니다.')
                for statement in statements:
                    if not isinstance(statement, dict):
                        raise ValueError('Statement 항목은 객체여야 합니다.')
                    if 'NotAction' in statement or 'NotResource' in statement:
                        raise ValueError('NotAction/NotResource 정책은 아직 지원하지 않습니다.')
                    actions = statement.get('Action')
                    if isinstance(actions, str):
                        actions = [actions]
                    if not isinstance(actions, list) or not actions or not all(isinstance(a, str) and a for a in actions):
                        raise ValueError('유효한 Action 문자열 또는 목록이 필요합니다.')
                    if statement.get('Effect') not in ('Allow', 'Deny'):
                        raise ValueError('Effect는 Allow 또는 Deny여야 합니다.')
                    resources = statement.get('Resource')
                    if isinstance(resources, str):
                        resources = [resources]
                    if not isinstance(resources, list) or not resources or not all(isinstance(r, str) and r for r in resources):
                        raise ValueError('유효한 Resource 문자열 또는 목록이 필요합니다.')
                    if 'Condition' in statement and not isinstance(statement['Condition'], dict):
                        raise ValueError('Condition은 객체여야 합니다.')
            records = normalize_policy(
                csp,
                raw_policy_document,
                identity=item.get("identity"),
            )

            # 각 정규화 레코드에 원본 정책의 출처를 기록
            for record in records:
                record["policy_name"] = item.get("policy_name")#정책이름
                record["policy_id"] = item.get("policy_arn") or item.get("policy_id")#정책식별자
                record["policy_type"] = item.get("policy_type")#정책유형
                for field in ('identity_name', 'identity_type', 'attachment_type', 'policy_source_identity', 'policy_version', 'group_name', 'group_arn', 'permission_path'):
                    if field in item:
                        record[field] = item[field]

            all_normalized_records.extend(records)
        
        except Exception as e:
            if strict:
                raise ValueError(
                    f"정책 분석 불가: {item.get('identity', 'N/A')} / "
                    f"{item.get('policy_name', 'N/A')}: {e}"
                ) from e
            print(
                f"Normalization failed for identity="
                f"'{item.get('identity', 'N/A')}', csp='{csp}': {e}"
            )

    return all_normalized_records

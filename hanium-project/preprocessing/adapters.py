#클라우드별 정책을 읽어 공통 항목으로 추출하는 함수들
# preprocessing/adapters.py
# 클라우드마다 다른 정책 구조를 공통 항목으로 변환한다.
# 이 파일의 함수들은 파이썬 기본 기능만 사용하므로 import가 필요 없다.


# ── 1. 여러 추출 함수에서 사용하는 보조 함수 ──

def _ensure_list(value) -> list:
    """None은 빈 리스트로, 문자열은 항목 하나짜리 리스트로 바꾼다."""
    if value is None:
        return []

    # 예: "s3:GetObject" → ["s3:GetObject"]
    # 문자열을 그대로 반복하면 글자 하나씩 처리되므로 리스트로 감싼다.
    if isinstance(value, str):
        return [value]

    # 기존 리스트 등 나머지 값은 그대로 반환한다.
    # 모든 자료형을 리스트로 바꾸는 함수는 아니다.
    return value


def _canonicalize_aws_principal(principal_raw) -> str:
    """AWS 정책에 기록된 사용자 식별자를 시연용 이름으로 정리한다."""

    # Principal이 딕셔너리이면 그 안에서 실제 식별자를 꺼낸다.
    # 예: {"AWS": "arn:aws:iam::developer01"}
    if isinstance(principal_raw, dict):
        if 'AWS' in principal_raw:
            principal_raw = principal_raw['AWS']
        elif 'Federated' in principal_raw:
            principal_raw = principal_raw['Federated']
        elif 'Service' in principal_raw:
            principal_raw = principal_raw['Service']
        else:
            # 현재 처리하지 않는 구조는 문자열로 반환한다.
            return str(principal_raw)

    # 원본의 단순화 방식: 여러 식별자가 있으면 첫 번째만 사용한다.
    # 빈 리스트나 여러 사용자를 모두 처리하는 기능은 추후 개선 대상이다.
    if isinstance(principal_raw, list):
        principal_raw = principal_raw[0]

    if isinstance(principal_raw, str) and 'arn:aws:iam::' in principal_raw:
        # 예: "...:user/developer01" → "developer01"
        parts = principal_raw.split('/')
        if len(parts) > 1:
            return parts[-1]

        # 현재 시연 데이터: "arn:aws:iam::developer01" → "developer01"
        return principal_raw.split('::')[-1]

    return str(principal_raw)


def _canonicalize_gcp_member(member_raw) -> str:
    """GCP 멤버 문자열에서 사용자·서비스 계정 식별자를 꺼낸다."""

    if not isinstance(member_raw, str):
        return str(member_raw)

    # 일반 사용자는 시연 데이터의 사용자 이름과 맞추기 위해
    # "user:userB@example.com"에서 "userB"만 남긴다.
    if member_raw.startswith('user:') and '@' in member_raw:
        return member_raw.split(':')[1].split('@')[0]

    # 서비스 계정은 접두사만 제거하고 이메일 전체를 유지한다.
    elif member_raw.startswith('serviceAccount:'):
        return member_raw.split(':')[1]

    # 그룹도 이메일 전체를 유지한다.
    elif member_raw.startswith('group:'):
        return member_raw.split(':')[1]

    return member_raw


# ── 2. 클라우드별 정책 추출 함수 ──

def _extract_aws_statements(raw_policy: dict) -> list[dict]:
    """AWS 정책의 Statement들을 공통 형식의 딕셔너리로 변환한다."""
    statements = []

    # 정책이 딕셔너리가 아니거나 Statement가 없으면 빈 결과를 반환한다.
    if not isinstance(raw_policy, dict) or 'Statement' not in raw_policy:
        return []

    # 현재 시연 데이터의 Statement는 리스트 형태다.
    raw_statements = raw_policy['Statement']
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    for stmt_raw in _ensure_list(raw_statements):

        # get(키, 기본값): 키가 없으면 기본값을 사용한다.
        principal_raw = stmt_raw.get('Principal', {'AWS': 'unknown'})
        principal = _canonicalize_aws_principal(principal_raw)

        # Action은 문자열 하나여도 리스트 형태로 맞춘다.
        actions = _ensure_list(stmt_raw.get('Action'))

        # 아래 기본값 처리는 원본 시연 코드의 처리 방식이다.
        scope = stmt_raw.get('Resource', '*')
        effect = stmt_raw.get('Effect', 'Allow')
        # 문자열 하나여도 목록으로 만들고, 여러 대상이면 목록 그대로 보존
        original_resources = list(_ensure_list(scope))

        # 뒤의 정규화 함수가 문자열 scope를 사용하므로,
        # 리소스가 여러 개이면 쉼표로 연결한다.
        if isinstance(scope, list):
            scope = ', '.join(_ensure_list(scope))

        statements.append({
            "principal": principal,
            "actions": actions,
            "scope": scope,
            "original_resources": original_resources,
            "condition": stmt_raw.get("Condition", {}),#조건이 없는 구문은 빈 딕셔너리로 저장
            "effect": effect
        })

    return statements


def _extract_azure_statements(raw_policy: dict) -> list[dict]:
    """현재 Azure 시연 정책에서 공통 항목을 추출한다."""
    statements = []

    if not isinstance(raw_policy, dict):
        return []

    principal = raw_policy.get('principal', 'unknown')
    actions = _ensure_list(raw_policy.get('actions'))

    # 현재 시연 구조에서는 role을 scope 자리에 넣는다.
    # 실제 리소스 적용 범위를 해석하는 구현은 아니다.
    scope = raw_policy.get('role', '*')
    effect = raw_policy.get('effect', 'Allow')

    statements.append({
        "principal": principal,
        "actions": actions,
        "scope": scope,
        "effect": effect
    })

    return statements


def _extract_gcp_statements(raw_policy: dict) -> list[dict]:
    """현재 GCP 시연 정책에서 멤버별 공통 항목을 추출한다."""
    statements = []

    if not isinstance(raw_policy, dict) or 'binding' not in raw_policy:
        return []

    # binding에는 멤버 목록, 역할, 시연용 권한 목록이 들어 있다.
    binding = raw_policy['binding']
    members_raw = _ensure_list(binding.get('members'))
    role = binding.get('role', '*')
    permissions = _ensure_list(binding.get('permissions'))

    # actions에는 역할 이름 대신 개별 권한 목록을 넣는다.
    gcp_actions = permissions

    # 하나의 binding에 여러 멤버가 있으면 멤버마다 결과를 만든다.
    for member_raw in members_raw:
        principal = _canonicalize_gcp_member(member_raw)

        statements.append({
            "principal": principal,
            "actions": gcp_actions,
            # 현재 시연 구조에서는 역할 이름을 scope로 사용한다.
            "scope": role,
            "effect": 'Allow'
        })

    return statements


# ── 3. 외부 코드에서 호출할 공통 진입 함수 ──

def extract_statements(csp: str, raw_policy: dict) -> list[dict]:
    """클라우드 종류에 맞는 추출 함수를 호출하고 결과를 반환한다."""

    # 잘못된 입력 자료형이면 원인을 알 수 있도록 예외를 발생시킨다.
    if not isinstance(raw_policy, dict):
        raise TypeError(
            f"raw_policy는 dict 타입이어야 합니다. 입력 타입: {type(raw_policy)}"
        )

    # "AWS", "aws"처럼 대소문자가 달라도 같은 클라우드로 처리한다.
    csp_normalized = csp.upper()

    if csp_normalized == 'AWS':
        return _extract_aws_statements(raw_policy)
    elif csp_normalized == 'AZURE':
        return _extract_azure_statements(raw_policy)
    elif csp_normalized == 'GCP':
        return _extract_gcp_statements(raw_policy)
    else:
        raise ValueError(f"지원하지 않는 CSP입니다: {csp}")

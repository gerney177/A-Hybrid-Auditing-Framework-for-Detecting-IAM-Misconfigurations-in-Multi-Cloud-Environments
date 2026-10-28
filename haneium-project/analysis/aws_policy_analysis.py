# analysis/aws_policy_analysis.py

from data.aws_adapter import extract_aws_identity_policies
from preprocessing.normalizer import normalize_policy_dataset
from analysis.policy_checks import find_action_wildcards
from analysis.aws_policy_checks import find_aws_passrole_candidates


def run_aws_policy_analysis(snapshot):
    """수집된 AWS 원본을 분석하고 결과를 반환한다."""

    # 1. 사용자·역할에 직접 연결된 권한 정책 본문 추출
    policy_items = extract_aws_identity_policies(snapshot)

    # 2. 기존 분석용 구조로 정규화
    records = normalize_policy_dataset(policy_items, strict=True)

    # 3. 기존 검사 실행
    wildcard_findings = find_action_wildcards(records)
    passrole_findings = find_aws_passrole_candidates(records)

    # 4. 터미널·대시보드에서 사용할 결과 반환
    return {
        "analysis_scope": "user_role_and_group_v2",
        "collected_at": snapshot.get("collected_at"),
        "policy_items": policy_items,
        "normalized_records": records,
        "wildcard_findings": wildcard_findings,
        "passrole_findings": passrole_findings,
    }

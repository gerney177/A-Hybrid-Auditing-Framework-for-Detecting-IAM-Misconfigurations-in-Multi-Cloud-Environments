# checks/check_policy_analysis.py
import json
from collections import Counter
from pathlib import Path
from analysis.aws_policy_checks import find_aws_passrole_candidates
from analysis.aws_policy_analysis import run_aws_policy_analysis

def main():
    project_root = Path(__file__).resolve().parents[1]
    snapshot_path = project_root / "data" / "aws_iam_snapshot.json"

    if not snapshot_path.is_file():
        raise FileNotFoundError(
            "AWS 원본 파일이 없습니다. "
            "먼저 py -m checks.check_aws_collection을 실행하세요."
        )

    # 저장된 원본을 읽는다. AWS API 호출은 하지 않는다.
    with snapshot_path.open("r", encoding="utf-8") as file:
        snapshot = json.load(file)

    state = run_aws_policy_analysis(snapshot)

    policy_items = state["policy_items"]
    records = state["normalized_records"]
    findings = state["wildcard_findings"]
    passrole_findings = state["passrole_findings"]

    print("저장된 AWS 정책 분석")
    print(f"수집 시각: {snapshot.get('collected_at', '알 수 없음')}")
    print(f"정책 본문: {len(policy_items)}개")
    print(f"정규화 레코드: {len(records)}개")
    print(f"Action 와일드카드 후보: {len(findings)}개")

    type_counts = Counter(
        finding["wildcard_type"]
        for finding in findings
    )

    print("\n와일드카드 범위별 개수")

    for wildcard_type in [
        "ALL_ACTIONS",
        "SERVICE_ALL_ACTIONS",
        "ACTION_PATTERN",
    ]:
        print(f"- {wildcard_type}: {type_counts[wildcard_type]}개")

    print("\n후보 미리보기 — 최대 10개")

    for finding in findings[:10]:
        print(
            f"- {finding['policy_name']} / "
            f"{finding['original_action']} / "
            f"분류: {finding['wildcard_type']} / "
            f"상태: {finding['status']}"
        )
        print(f"  Resource: {finding['original_resources']}")
        print(f"  Condition: {finding['condition']}")

    if not findings:
        print("현재 검사에서 Action 와일드카드 후보가 없습니다.")

    
    print("\nAWS PassRole 검토 후보")


    print(f"PassRole을 포함하는 구문 레코드: {len(passrole_findings)}개")

    for finding in passrole_findings:
        print(
            f"- {finding['policy_name']} / "
            f"원래 Action: {finding['original_action']} / "
            f"상태: {finding['status']}"
        )
        print(f"  Resource: {finding['original_resources']}")
        print(f"  Condition: {finding['condition']}")

    if not passrole_findings:
        print("현재 검사 범위에서 PassRole 후보가 없습니다.")
        
        print("\nPassRole 검사 예제 검증")

    test_cases = [
        ("iam:PassRole", "Allow", 1),
        ("iam:*", "Allow", 1),
        ("*", "Allow", 1),
        ("iam:ListRoles", "Allow", 0),
        ("iam:PassRole", "Deny", 0),
    ]

    for action, effect, expected_count in test_cases:
        test_record = {
            "identity": "test-user",
            "source_csp": "AWS",
            "policy_name": "passrole-test",
            "original_action": action,
            "effect": effect,
            "original_resources": ["*"],
            "condition": {},
        }

        actual_count = len(
            find_aws_passrole_candidates([test_record])
        )

        assert actual_count == expected_count, (
            f"{action} / {effect}: "
            f"예상={expected_count}, 실제={actual_count}"
        )

        print(f"- {action} / {effect}: 통과")

    print("PassRole 검사 예제 검증 완료.")
    print("\n저장된 정책 분석 완료.")

if __name__ == "__main__":
    main()
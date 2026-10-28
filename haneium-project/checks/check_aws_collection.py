# checks/check_aws_collection.py
import json
from datetime import datetime
from pathlib import Path
from collections import Counter
from preprocessing.normalizer import normalize_policy_dataset
from analysis.policy_checks import (
    find_action_wildcards,
    classify_action_wildcard,
)
from data.aws_collector import collect_aws_iam
from data.aws_adapter import extract_aws_user_policies


def serialize_datetime(value):
    """AWS 응답의 datetime을 JSON 문자열로 변환."""
    if isinstance(value, datetime):
        return value.isoformat()

    raise TypeError(
        f"JSON으로 변환할 수 없는 자료형: {type(value).__name__}"
    )


def main():
    snapshot = collect_aws_iam()

    project_root = Path(__file__).resolve().parents[1]
    output_path = project_root / "data" / "aws_iam_snapshot.json"

    # 변환에 성공한 뒤 파일 저장
    content = json.dumps(
        snapshot,
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
        default=serialize_datetime,
    )

    output_path.write_text(content, encoding="utf-8")

    print(f"수집 시각: {snapshot['collected_at']}")
    print(f"사용자: {len(snapshot['users'])}명")
    print(f"그룹: {len(snapshot['groups'])}개")
    print(f"역할: {len(snapshot['roles'])}개")
    print(f"관리형 정책: {len(snapshot['managed_policies'])}개")
    print(f"원본 저장 위치: {output_path}")
    print("AWS IAM 원본 수집·저장 완료.")
    print("\n사용자별 정책 연결")

    for user in snapshot["users"]:
        print(f"\n사용자: {user['UserName']}")

        print("직접 연결된 관리형 정책:")
        for policy in user.get("AttachedManagedPolicies", []):
            print(f"  - {policy['PolicyName']}")

        print("직접 작성된 인라인 정책:")
        for policy in user.get("UserPolicyList", []):
            print(f"  - {policy['PolicyName']}")

        print(f"소속 그룹: {user.get('GroupList', [])}")
    
    policy_items = extract_aws_user_policies(snapshot)
    print("\n추출한 사용자 정책 본문")
    for item in policy_items:
        statements = item["raw_policy_document"].get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        print(
            f"- {item['identity_name']} / "
            f"{item['policy_name']} / "
            f"Statement {len(statements)}개"
        )

    print(f"정책 본문 추출 완료: {len(policy_items)}개")
    
    normalized_records = normalize_policy_dataset(policy_items)

    identities = sorted({
        record["identity"]
        for record in normalized_records
    })

    unknown_count = sum(
        record["identity"] == "unknown"
        for record in normalized_records
    )

    print("\n정규화 결과 확인")
    print(f"정규화 레코드: {len(normalized_records)}개")
    print(f"사용자 식별자: {identities}")
    print(f"unknown 사용자: {unknown_count}개")

    expected_identities = {
        item["identity"] for item in policy_items
    }

    assert normalized_records, "정규화 결과가 비어 있습니다."
    assert set(identities) == expected_identities, (
        "정책의 사용자와 정규화 결과의 사용자가 다릅니다."
    )
    assert unknown_count == 0, "사용자 연결에 실패했습니다."

    print("사용자 식별자 연결 확인 완료.")
    
    print("\n원래 Action 보존 확인")

    for record in normalized_records[:5]:
        print(
            f"원래 Action: {record['original_action']} / "
            f"공통 작업: {record['operation']}"
        )

    assert all(
        record.get("original_action")
        for record in normalized_records
    ), "원래 Action이 누락된 레코드가 있습니다."

    print("원래 Action 보존 확인 완료.")
    
    print("\n정책 출처 보존 확인")

    policy_names = sorted({
        record["policy_name"]
        for record in normalized_records
        if record["policy_name"] is not None
    })

    print(f"정책 이름: {policy_names}")

    for record in normalized_records[:3]:
        print(
            f"{record['policy_name']} / "
            f"{record['policy_type']} / "
            f"{record['original_action']}"
        )

    assert all(
        record.get("policy_name") and record.get("policy_id")
        for record in normalized_records
    ), "현재 AWS 관리형 정책의 출처 정보가 누락됐습니다."

    print("정책 출처 보존 확인 완료.")
    
    print("\n원래 Resource 보존 확인")

    for record in normalized_records[:5]:
        print(
            f"{record['policy_name']} / "
            f"{record['original_action']} / "
            f"Resource: {record['original_resources']}"
        )

    assert all(
        isinstance(record.get("original_resources"), list)
        and record["original_resources"]
        for record in normalized_records
    ), "현재 AWS 정책의 Resource 목록이 누락됐습니다."

    print("원래 Resource 보존 확인 완료.")
    
    print("\nCondition 보존 확인")

    for record in normalized_records[:5]:
        print(
            f"{record['policy_name']} / "
            f"{record['original_action']} / "
            f"Condition: {record['condition']}"
        )

    assert all(
        isinstance(record.get("condition"), dict)
        for record in normalized_records
    ), "Condition 저장 형식이 올바르지 않습니다."

    print("Condition 보존 확인 완료.")
    print("\n조건이 있는 예제 정책 검증")

    test_condition = {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true"
        }
    }

    test_resources = [
        "arn:aws:s3:::example-bucket-a/*",
        "arn:aws:s3:::example-bucket-b/*",
    ]

    test_policy = {
        "identity": "test-user",
        "csp": "AWS",
        "policy_name": "condition-test",
        "policy_id": "local-condition-test",
        "policy_type": "test",
        "raw_policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                    ],
                    "Resource": test_resources,
                    "Condition": test_condition,
                }
            ],
        },
    }

    test_records = normalize_policy_dataset([test_policy])

    assert len(test_records) == 2, "Action별 레코드 생성 실패"

    assert {
        record["original_action"] for record in test_records
    } == {"s3:GetObject", "s3:PutObject"}, "Action 보존 실패"

    for record in test_records:
        assert record["identity"] == "test-user"
        assert record["effect"] == "Allow"
        assert record["policy_name"] == "condition-test"
        assert record["policy_id"] == "local-condition-test"
        assert record["original_resources"] == test_resources
        assert record["condition"] == test_condition

    print("사용자·Action·정책 출처·Resource·Condition 검증 완료.")
    
    print("\n정책 와일드카드 검토 후보")

    findings = find_action_wildcards(normalized_records)

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

    print("정책 와일드카드 검사 완료.")
    
    
    print("\n와일드카드 분류 예제 검증")

    test_cases = [
        ("*", "ALL_ACTIONS"),
        ("s3:*", "SERVICE_ALL_ACTIONS"),
        ("s3:Get*", "ACTION_PATTERN"),
    ]

    for action, expected in test_cases:
        actual = classify_action_wildcard("AWS", action)

        assert actual == expected, (
            f"{action}: 예상={expected}, 실제={actual}"
        )

        print(f"- {action} → {actual}: 통과")

    print("와일드카드 분류 검증 완료.")

if __name__ == "__main__":
    main()
    
    
#ARN:AWS자원의 고유 식별자, Amazone Resource Name
#흐름 :AWS 사용자->정책항목의idenentity에 저장->정규화 레코드의 identity에 저장
#즉 현재까지는  사용자 1명, 직접연결된 정책 3개, Action들을 펼친 정규화 레코드 1200개정도
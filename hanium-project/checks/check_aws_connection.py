# checks/check_aws_connection.py
import boto3


def main():
    session = boto3.Session(
        profile_name="haneium-sdk",
    )

    # 현재 인증된 사용자 확인
    sts = session.client("sts")
    identity = sts.get_caller_identity()

    arn = identity["Arn"]
    print(f"인증 사용자: {arn}")

    if not arn.endswith(":user/haneium-reader"):
        raise RuntimeError(
            "haneium-reader가 아닙니다. 로그인 프로필을 확인하세요."
        )

    # AWS에 실제로 등록된 IAM 사용자 조회
    iam = session.client("iam")
    paginator = iam.get_paginator("list_users") #사용자 목록이 여러페이지로 나뉘어 와도 빠짐없이 읽게 해줌

    user_count = 0

    for page in paginator.paginate():
        for user in page["Users"]:
            user_count += 1
            print(f"- {user['UserName']}")

    print(f"조회한 IAM 사용자 수: {user_count}")
    print("검증 성공: Python에서 AWS IAM API 조회 완료.")


if __name__ == "__main__":
    main()
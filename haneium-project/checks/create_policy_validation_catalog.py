"""Curated synthetic policy cases; expected outcomes are authored independently."""
import copy
import json
from pathlib import Path
from urllib.parse import quote

ACCOUNT = 'arn:aws:iam::000000000000'
RESOURCE = 'arn:aws:s3:::validation-data/*'


def statement(action='s3:GetObject', effect='Allow', resource=RESOURCE, **extra):
    return {'Effect': effect, 'Action': action, 'Resource': resource, **extra}


def snapshot(stmt=None, target='user'):
    document = {'Version': '2012-10-17', 'Statement': [stmt or statement()]}
    result = {'source': 'synthetic_policy_validation', 'collected_at': '2026-10-26T00:00:00+00:00',
              'users': [], 'roles': [], 'groups': [], 'managed_policies': []}
    if target == 'role':
        result['roles'] = [{'RoleName': 'ValidationRole', 'Arn': ACCOUNT + ':role/ValidationRole',
                            'RolePolicyList': [{'PolicyName': 'ValidationPolicy', 'PolicyDocument': document}]}]
    else:
        user = {'UserName': 'validation-user', 'Arn': ACCOUNT + ':user/validation-user', 'UserPolicyList': []}
        result['users'] = [user]
        if target == 'group':
            user['GroupList'] = ['ValidationGroup']
            result['groups'] = [{'GroupName': 'ValidationGroup', 'Arn': ACCOUNT + ':group/ValidationGroup',
                                 'GroupPolicyList': [{'PolicyName': 'ValidationPolicy', 'PolicyDocument': document}]}]
        else:
            user['UserPolicyList'] = [{'PolicyName': 'ValidationPolicy', 'PolicyDocument': document}]
    return result


def make_catalog():
    cases = []

    def add(cid, title, category, purpose, data, wildcard=0, passrole=0, records=1, policies=1, **checks):
        cases.append({'id': cid, 'title': title, 'category': category, 'purpose': purpose,
                      'snapshot': copy.deepcopy(data), 'expected': {'outcome': 'analyzed',
                      'counts': {'policy_items': policies, 'normalized_records': records,
                                 'wildcard_findings': wildcard, 'passrole_findings': passrole}, **checks}})

    def reject(cid, title, data, fragment, purpose, kind='invalid'):
        cases.append({'id': cid, 'title': title, 'category': '미지원·오류 입력', 'purpose': purpose,
                      'snapshot': copy.deepcopy(data), 'expected': {'outcome': kind, 'error_type': 'ValueError', 'error_contains': fragment}})

    add('P01', '사용자 제한 읽기 정책', '기본 정상 입력', '사용자 직접 읽기 정책에 검사 대상 후보가 발생하지 않는지 확인한다.', snapshot())
    add('P02', '역할 제한 읽기 정책', '기본 정상 입력', '역할 권한 정책도 사용자와 같은 검사 기준을 적용하는지 확인한다.', snapshot(target='role'))
    add('P03', '그룹 경유 읽기 정책', '기본 정상 입력', '그룹의 읽기 정책을 소속 사용자에게 연결하고 후보가 없는지 확인한다.', snapshot(target='group'), attachment_type='group')
    add('W01', '서비스 전체 액션 s3:*', '액션 패턴', '서비스 전체 액션을 와일드카드 검토 후보로 분류한다.', snapshot(statement('s3:*')), wildcard=1, wildcard_types=['SERVICE_ALL_ACTIONS'])
    add('W02', '전체 액션 *', '액션 패턴', '전체 액션 패턴이 와일드카드와 PassRole 양쪽 후보에 포함되는지 확인한다.', snapshot(statement('*')), wildcard=1, passrole=1, wildcard_types=['ALL_ACTIONS'])
    add('W03', 'IAM 전체 액션 iam:*', '액션 패턴', 'iam:*에 포함되는 PassRole 후보를 누락하지 않는지 확인한다.', snapshot(statement('iam:*')), wildcard=1, passrole=1)
    add('W04', '조회 액션 패턴 ec2:Describe*', '액션 패턴', '조회 패턴도 검토 후보로 표시하되 위험 확정으로 해석하지 않는다.', snapshot(statement('ec2:Describe*')), wildcard=1, wildcard_types=['ACTION_PATTERN'])
    add('W05', '부분 패턴 iam:Pass*', '액션 패턴', '정확한 액션명이 아니어도 PassRole을 포함하는 패턴을 검사한다.', snapshot(statement('iam:Pass*')), wildcard=1, passrole=1)
    add('W06', 'PassRole 액션 대소문자', '액션 패턴', '액션의 대소문자가 달라도 PassRole 후보를 찾는지 확인한다.', snapshot(statement('IAM:pAsSrOlE')), passrole=1)
    add('D01', 'Deny PassRole', 'Allow·Deny', 'Deny 구문을 Allow PassRole 후보로 잘못 분류하지 않는지 확인한다.', snapshot(statement('iam:PassRole', effect='Deny')))
    add('D02', 'Deny 전체 액션', 'Allow·Deny', 'Deny의 와일드카드 액션을 허용 후보로 잘못 분류하지 않는지 확인한다.', snapshot(statement('*', effect='Deny')))
    data = snapshot(statement('iam:PassRole'))
    data['users'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'].append(statement('iam:PassRole', effect='Deny'))
    add('D03', 'Allow와 Deny가 함께 존재', 'Allow·Deny', 'Allow 후보는 보존하지만 명시적 Deny를 종합한 최종 유효 권한을 판정한 것은 아님을 확인한다.', data, passrole=1, records=2)
    condition = {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}}
    restricted = ACCOUNT + ':role/ApprovedRole'
    add('C01', 'Resource·Condition 제한 PassRole', '조건·리소스 범위', '제한된 후보도 조건과 리소스를 잃지 않고 검토 근거로 보존한다.', snapshot(statement('iam:PassRole', resource=restricted, Condition=condition)), passrole=1, resources=[restricted], condition=condition)
    add('C02', 'Resource만 *인 읽기 정책', '조건·리소스 범위', 'Resource 와일드카드와 Action 와일드카드를 구분한다. 후보 없음이 최소 권한 충족을 뜻하지는 않는다.', snapshot(statement(resource='*')))
    data = snapshot()
    data['users'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'] = statement()
    add('F01', 'Statement 단일 객체', '입력 형식', '목록이 아닌 단일 Statement 객체가 누락되지 않는지 확인한다.', data)
    add('F02', '여러 Action을 가진 구문', '입력 형식', 'Action별로 레코드를 만들고 서로 다른 후보를 각각 탐지한다.', snapshot(statement(['s3:GetObject', 's3:*', 'iam:PassRole'])), wildcard=1, passrole=1, records=3)
    add('F03', '여러 리소스를 가진 구문', '입력 형식', 'Resource 목록이 정규화 뒤에도 원래 값으로 유지되는지 확인한다.', snapshot(statement(resource=[RESOURCE, 'arn:aws:s3:::second-data/*'])), resources=[RESOURCE, 'arn:aws:s3:::second-data/*'])
    data = snapshot(statement('iam:PassRole'))
    inline = data['users'][0]['UserPolicyList'][0]
    inline['PolicyDocument'] = quote(json.dumps(inline['PolicyDocument']))
    add('F04', 'URL 인코딩된 정책 본문', '입력 형식', '인코딩된 JSON 정책도 해독하여 동일하게 검사하는지 확인한다.', data, passrole=1)
    data = snapshot()
    user = data['users'][0]
    user['UserPolicyList'] = []
    user['AttachedManagedPolicies'] = [{'PolicyName': 'VersionedPolicy', 'PolicyArn': ACCOUNT + ':policy/VersionedPolicy'}]
    data['managed_policies'] = [{'Arn': ACCOUNT + ':policy/VersionedPolicy', 'PolicyVersionList': [
        {'IsDefaultVersion': False, 'VersionId': 'v1', 'Document': {'Statement': [statement('*')]}},
        {'IsDefaultVersion': True, 'VersionId': 'v2', 'Document': {'Statement': [statement()]}},
    ]}]
    add('M01', '관리형 정책의 기본 버전', '정책 출처·연결', '과거 버전의 *를 검사하지 않고 현재 기본 버전의 읽기 정책만 검사한다.', data)
    add('G01', '그룹을 통한 PassRole', '정책 출처·연결', '그룹 정책 후보가 그룹 자체가 아닌 실제 사용자에 연결되는지 확인한다.', snapshot(statement('iam:PassRole'), target='group'), passrole=1, attachment_type='group', permission_paths=True)
    data = snapshot(statement('iam:PassRole'), target='group')
    data['users'][0]['UserPolicyList'] = copy.deepcopy(data['groups'][0]['GroupPolicyList'])
    add('G02', '동일 권한의 직접·그룹 경유', '정책 출처·연결', '같은 사용자에게 직접·그룹으로 연결된 권한을 별도 출처 경로로 보존한다. 후보 수는 경로별 건수다.', data, passrole=2, records=2, policies=2, unique_paths=2)
    data = snapshot(statement('s3:*'), target='group')
    group = copy.deepcopy(data['groups'][0]); group.update(GroupName='SecondGroup', Arn=ACCOUNT + ':group/SecondGroup')
    data['groups'].append(group); data['users'][0]['GroupList'].append('SecondGroup')
    add('G03', '여러 그룹의 같은 인라인 정책 이름', '정책 출처·연결', '정책 이름이 같아도 그룹 ARN과 경로로 출처를 구별한다.', data, wildcard=2, records=2, policies=2, unique_paths=2)
    data = snapshot(); doc = data['users'][0]['UserPolicyList'][0]['PolicyDocument']
    doc['Statement'][0].pop('Action'); doc['Statement'][0]['NotAction'] = 'iam:*'
    reject('E01', '미지원 NotAction', data, 'NotAction/NotResource', '해석하지 못하는 구문을 정상 또는 후보 없음으로 숨기지 않고 거부한다.', 'unsupported')
    data = snapshot(); stmt = data['users'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'][0]
    stmt.pop('Resource'); stmt['NotResource'] = RESOURCE
    reject('E02', '미지원 NotResource', data, 'NotAction/NotResource', '미지원 리소스 제외 구문을 부분 분석으로 통과시키지 않는다.', 'unsupported')
    data = snapshot(); data['users'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'][0].pop('Action')
    reject('E03', 'Action 누락', data, 'Action', '필수 액션이 없는 입력을 분석 실패로 명시한다.')
    data = snapshot(); data['users'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'] = []
    reject('E04', '빈 Statement', data, 'Statement', '검사할 구문이 없는 정책을 성공 분석으로 간주하지 않는다.')
    reject('E05', '잘못된 Effect', snapshot(statement(effect='Permit')), 'Effect', 'Allow/Deny가 아닌 Effect를 거부한다.')
    data = snapshot(); data['users'][0]['UserPolicyList'][0]['PolicyDocument']['Statement'][0].pop('Resource')
    reject('E06', 'Resource 누락', data, 'Resource', '리소스가 없는 정책을 임의로 *로 바꾸어 분석하지 않는다.')
    data = snapshot(); data['users'][0]['GroupList'] = ['MissingGroup']
    reject('E07', '소속 그룹 본문 누락', data, '그룹 본문', '직접 정책이 있어도 그룹 권한을 누락한 불완전 분석을 막는다.')
    data = snapshot(); data['users'][0]['AttachedManagedPolicies'] = [{'PolicyName': 'MissingPolicy', 'PolicyArn': ACCOUNT + ':policy/MissingPolicy'}]
    reject('E08', '관리형 정책 본문 누락', data, '정책 본문', '가져오지 못한 정책을 검사에서 조용히 제외하지 않는다.')
    assert len(cases) == 30
    return {'version': 'policy-cases-v1', 'source': 'synthetic_only', 'cases': cases}


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'data/policy_validation_cases.json'
    path.write_text(json.dumps(make_catalog(), ensure_ascii=False, indent=2), encoding='utf-8')
    print('Created 30 policy validation cases.')

"""Extend the existing 25 identities, preserving baseline behavior and metadata."""
import copy
import json
from pathlib import Path
import pandas as pd
from data import storage
from data.aws_adapter import extract_aws_identity_policies

DATA_PATH = Path(__file__).with_name('mock25_extended.json')
SNAPSHOT_PATH = Path(__file__).with_name('mock25_extended_aws.json')
ACCOUNT = '111122223333'  # synthetic account namespace; never a live AWS call


def build_extended(dataset_id, original=None, large=False):
    original = storage.load_dataset(dataset_id) if original is None else original
    aws = [p for p in original['policies'] if p['csp'] == 'AWS']
    user_arn = lambda name: f'arn:aws:iam::{ACCOUNT}:user/{name}'
    role_arn = lambda name: f'arn:aws:iam::{ACCOUNT}:role/{name}'
    def document(actions, resource='*', condition=None):
        statement = {'Effect':'Allow','Action':actions,'Resource':resource}
        if condition: statement['Condition'] = condition
        return {'Version':'2012-10-17','Statement':[statement]}
    groups = [
        ('ProjectReaders', ['admin01','userD'], document(['s3:GetObject'],'arn:aws:s3:::project-documents/*')),
        ('StorageOperators', ['userA','userG'], document(['s3:*'],'arn:aws:s3:::project-storage/*')),
        ('AutomationOperators', ['devops01','userJ'], document(['iam:PassRole'],role_arn('application-*'),
            {'StringEquals':{'iam:PassedToService':'lambda.amazonaws.com'}})),
    ]
    assignments = [('admin01','ReadOnlyRole'),('userM','StorageMaintenanceRole'),('userD','DeploymentRole')]
    if large:
        for index, policy in enumerate(p for p in aws if p['identity'].startswith('mock_')):
            name=policy['identity']
            group_index=1 if index % 10 == 0 else (2 if index % 10 == 1 else 0)
            groups[group_index][1].append(name)
            role=['ReadOnlyRole','StorageMaintenanceRole','DeploymentRole'][index % 3]
            assignments.append((name,role))
    role_docs = {
        'ReadOnlyRole': document(['s3:GetObject'],'arn:aws:s3:::project-documents/*'),
        'StorageMaintenanceRole': document(['s3:*'],'arn:aws:s3:::project-storage/*'),
        'DeploymentRole': document(['iam:PassRole'],role_arn('application-*'),
            {'StringEquals':{'iam:PassedToService':'lambda.amazonaws.com'}}),
    }
    snapshot = {'source':'existing_mock25_extended','users':[], 'groups':[], 'roles':[], 'managed_policies':[]}
    for name, members, doc in groups:
        snapshot['groups'].append({'GroupName':name,'Arn':f'arn:aws:iam::{ACCOUNT}:group/{name}',
            'GroupPolicyList':[{'PolicyName':name+'Policy','PolicyDocument':doc}]})
    for policy in aws:
        name = policy['identity']
        inline = [{'PolicyName':'OriginalDirectPolicy','PolicyDocument':copy.deepcopy(policy['raw_policy_document'])}]
        for user, role in assignments:
            if name == user:
                inline.append({'PolicyName':'Assume'+role,'PolicyDocument':document(['sts:AssumeRole'],role_arn(role))})
        snapshot['users'].append({'UserName':name,'Arn':user_arn(name),
            'GroupList':[group for group,members,_ in groups if name in members], 'UserPolicyList':inline})
    for role, doc in role_docs.items():
        principals = [user_arn(user) for user,target in assignments if target==role]
        snapshot['roles'].append({'RoleName':role,'Arn':role_arn(role),
            'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{
                'Effect':'Allow','Principal':{'AWS':principals},'Action':'sts:AssumeRole'}]},
            'RolePolicyList':[{'PolicyName':role+'Policy','PolicyDocument':doc}]})
    # Single aggregate document per user keeps the existing remediation engine from
    # taking only the first directly attached policy. Source paths stay in snapshot.
    items = extract_aws_identity_policies(snapshot)
    policies = []
    for policy in original['policies']:
        item = copy.deepcopy(policy)
        if policy['csp']=='AWS':
            statements=[]
            for source in items:
                if source['identity_type']=='user' and source['identity_name']==policy['identity']:
                    value=source['raw_policy_document']['Statement']
                    statements.extend(copy.deepcopy(value if isinstance(value,list) else [value]))
            item['raw_policy_document']={'Version':'2012-10-17','Statement':statements}
        policies.append(item)
    return {'baseline_dataset_id':dataset_id,'source':'mock25_extended',
        'baseline_input':{'policies':copy.deepcopy(original['policies']),
            'metadata':storage.dataframe_to_records(original['metadata']),
            'behavior':storage.dataframe_to_records(original['behavior'])},
        'policies':policies,'metadata':storage.dataframe_to_records(original['metadata']),
        'behavior':storage.dataframe_to_records(original['behavior']), 'aws_snapshot':snapshot,
        'role_assignments':[{'user':user,'role':role,'user_arn':user_arn(user),'role_arn':role_arn(role)} for user,role in assignments],
        'changes':[{'group':group,'members':members,'policy':doc} for group,members,doc in groups],
        'notes':['기존 25개 Mock에 추가한 로컬 설정이며 논문 원래 실험이나 실제 AWS 수집 결과가 아닙니다.',
            '사용자 점수는 직접·그룹 정책을 합쳐 계산합니다. 역할 정책은 별도 대상으로 검사하며 사용자 점수에 자동 합산하지 않습니다.',
            '역할 전환 연결은 사용자 AssumeRole 허용과 역할 신뢰 정책에 설정했습니다. 전체 STS·SCP·권한 경계 평가는 수행하지 않습니다.',
            '조치 후 비교는 사용자에게 전달된 정책 묶음에 대한 시뮬레이션입니다. 공유 그룹·역할 원본 수정 및 전체 사용자 전파 시뮬레이션은 아닙니다.']}


def write_extended(dataset_id):
    data=build_extended(dataset_id)
    DATA_PATH.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    SNAPSHOT_PATH.write_text(json.dumps(data['aws_snapshot'],ensure_ascii=False,indent=2),encoding='utf-8')
    return data


def load_extended():
    data=json.loads(DATA_PATH.read_text(encoding='utf-8'))
    data['metadata']=pd.DataFrame(data['metadata'])
    data['behavior']=pd.DataFrame(data['behavior'])
    return data

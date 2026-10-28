"""Deterministic 300-identity dataset including the original 25."""
import copy,json,random
from pathlib import Path
import pandas as pd
from data.extended_mock import DATA_PATH as OLD_PATH, build_extended
from data.mock_data import generate_aws_policy,generate_azure_policy,generate_gcp_policy

DATA_PATH=Path(__file__).with_name('mock300.json')
SNAPSHOT_PATH=Path(__file__).with_name('mock300_aws.json')

def build_mock300():
    base=json.loads(OLD_PATH.read_text(encoding='utf-8'))['baseline_input']
    original=copy.deepcopy(base)
    rng=random.Random(42)
    makers={'AWS':generate_aws_policy,'Azure':generate_azure_policy,'GCP':generate_gcp_policy}
    for cloud in ['AWS','Azure','GCP']:
        count=sum(m['cloud_provider']==cloud for m in original['metadata'])
        for index in range(1,101-count):
            name=f'mock_{cloud.lower()}_{index:03d}'
            policy_risk=index % 20 == 0
            anomaly=index % 23 == 0
            original['policies'].append({'identity':name,'csp':cloud,'raw_policy_document':makers[cloud](name,policy_risk)})
            admin=index % 9 == 0
            original['metadata'].append({'identity':name,'cloud_provider':cloud,'role':'Operator' if admin else 'Viewer',
                'is_admin':admin,'mfa_enabled':index % 11 != 0,'has_api_key':index % 7 == 0,
                'privilege_level':'High' if admin else 'Low','privilege_level_numeric':3 if admin else 1,
                'is_true_risk':policy_risk or anomaly,'risk_scenario':'policy_and_behavior' if policy_risk and anomaly else ('policy' if policy_risk else ('behavior' if anomaly else None))})
            original['behavior'].append({'identity':name,'cloud_provider':cloud,
                'login_hour':rng.choice([0,1,2,22,23]) if anomaly else rng.randint(7,19),
                'api_call_count':rng.randint(5000,10000) if anomaly else rng.randint(100,1000),
                'failed_login_count':rng.randint(8,20) if anomaly else rng.randint(0,2)})
    data=build_extended(None,original={**original,'metadata':pd.DataFrame(original['metadata']),
        'behavior':pd.DataFrame(original['behavior'])},large=True)
    data.pop('baseline_input');data.pop('baseline_dataset_id')
    data.update(source='mock300',seed=42,dataset_version='mock300-v1',
        notes=['기존 25개를 포함한 300개 Mock이며 AWS·Azure·GCP 각각 100개입니다. 실제 운영 데이터나 논문의 기존 25개 실험 결과가 아닙니다.',
            '규칙/그룹/역할 구성은 고정이며 추가 행동 값은 시드 42로 재현합니다. 모집단 확대로 AI 상대 점수는 25개 분석 때와 달라질 수 있습니다.',
            '사용자는 직접·그룹 정책으로 분석합니다. 역할 정책은 별도 후보 검사이며 사용자 점수에 자동 합산하지 않습니다.',
            'UNKNOWN도 그래프 점수에 포함됩니다. 최종 유효 권한·역할 세션·다단계 권한 상승은 계산하지 않습니다.'])
    data['aws_snapshot']['source']='mock300'
    return data

def write_mock300():
    data=build_mock300()
    DATA_PATH.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    SNAPSHOT_PATH.write_text(json.dumps(data['aws_snapshot'],ensure_ascii=False,indent=2),encoding='utf-8')
    return data

def load_mock300():
    data=json.loads(DATA_PATH.read_text(encoding='utf-8'))
    return {**data,'metadata':pd.DataFrame(data['metadata']),'behavior':pd.DataFrame(data['behavior'])}

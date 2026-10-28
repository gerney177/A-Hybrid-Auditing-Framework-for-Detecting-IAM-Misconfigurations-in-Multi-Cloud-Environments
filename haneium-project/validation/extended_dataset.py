import contextlib
import io
from datetime import datetime, timezone
import pandas as pd
from data import storage
from data.extended_mock import load_extended, DATA_PATH


def run_extended_analysis():
    from pipeline import run_pipeline
    from analysis.aws_policy_analysis import run_aws_policy_analysis
    from validation.dataset_cases import STAGE_KEYS
    data=load_extended()
    baseline={**data['baseline_input'],
        'metadata':pd.DataFrame(data['baseline_input']['metadata']),
        'behavior':pd.DataFrame(data['baseline_input']['behavior'])}
    with contextlib.redirect_stdout(io.StringIO()):
        before=run_pipeline(data=baseline)
        after=run_pipeline(data=data)
    aws=run_aws_policy_analysis(data['aws_snapshot'])
    rows=[]
    for old in before['integrated_risk_df'].to_dict('records'):
        new=after['integrated_risk_df'].loc[lambda frame:frame['identity'].eq(old['identity'])].iloc[0]
        group_names=[u['GroupList'] for u in data['aws_snapshot']['users'] if u['UserName']==old['identity']]
        roles=[r['role'] for r in data['role_assignments'] if r['user']==old['identity']]
        rows.append({'대상':old['identity'],'클라우드':old['source_csp'],
            '추가 전 판정':old['final_action'],'추가 후 판정':new['final_action'],
            '추가 전 점수':old['hybrid_risk_score'],'추가 후 점수':new['hybrid_risk_score'],
            '점수 변화':round(new['hybrid_risk_score']-old['hybrid_risk_score'],3),
            '추가 전 R':old['rule_score'],'추가 후 R':new['rule_score'],
            '추가 전 A':old['ai_anomaly_score_raw'],'추가 후 A':new['ai_anomaly_score_raw'],
            '추가 전 G':old['graph_score'],'추가 후 G':new['graph_score'],
            '소속 그룹':group_names[0] if group_names else [],'전환 가능 역할 설정':roles,
            '판정 변경':old['final_action']!=new['final_action']})
    return {'executed_at':datetime.now(timezone.utc).isoformat(),
        'baseline_dataset_id':data['baseline_dataset_id'],'input_file':DATA_PATH.name,
        'summary':{'users':len(rows),'groups':len(data['aws_snapshot']['groups']),'roles':len(data['aws_snapshot']['roles']),
            'before':before['integrated_risk_df']['final_action'].value_counts().to_dict(),
            'after':after['integrated_risk_df']['final_action'].value_counts().to_dict(),
            'changed_decisions':sum(r['판정 변경'] for r in rows)},
        'comparison':rows,'aws_analysis':aws,'role_assignments':data['role_assignments'],'changes':data['changes'],
        'notes':data['notes'],
        'stages_before':{key:storage.dataframe_to_records(before[key]) for key in STAGE_KEYS},
        'stages_after':{key:storage.dataframe_to_records(after[key]) for key in STAGE_KEYS},
        'input':{'policies':data['policies'],'metadata':storage.dataframe_to_records(data['metadata']),
            'behavior':storage.dataframe_to_records(data['behavior']),'aws_snapshot':data['aws_snapshot']}}

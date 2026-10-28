import contextlib,io,json
from datetime import datetime,timezone
from pathlib import Path
from data.mock300 import load_mock300
from data import storage

REPORT_PATH=Path(__file__).resolve().parents[1]/'validation/reports/mock300-analysis-report.json'

def run_current_analysis(save=False):
    from pipeline import run_pipeline
    from analysis.aws_policy_analysis import run_aws_policy_analysis
    from validation.dataset_cases import STAGE_KEYS
    data=load_mock300()
    with contextlib.redirect_stdout(io.StringIO()):
        state=run_pipeline(data=data)
    aws=run_aws_policy_analysis(data['aws_snapshot'])
    users={u['UserName']:u for u in data['aws_snapshot']['users']}
    rows=[]
    for row in state['integrated_risk_df'].to_dict('records'):
        name=row['identity']
        rows.append({'대상':name,'클라우드':row['source_csp'],'판정':row['final_action'],'위험 점수':row['hybrid_risk_score'],
            '규칙 R':row['rule_score'],'행동 이상 A':row['ai_anomaly_score_raw'],'그래프 G':row['graph_score'],
            '소속 그룹':users.get(name,{}).get('GroupList',[]),
            '전환 역할 설정':[r['role'] for r in data['role_assignments'] if r['user']==name],
            '판정 근거':row['decision_reasons']})
    ids={}
    if save:
        dataset_id=storage.save_dataset(data,source='mock300')
        ids={'dataset_id':dataset_id,'run_id':storage.save_analysis_run(dataset_id,state)}
    report={'executed_at':datetime.now(timezone.utc).isoformat(),'source':'mock300','dataset_version':data['dataset_version'],
        **ids,'summary':{'users':len(rows),'clouds':data['metadata']['cloud_provider'].value_counts().to_dict(),
            'groups':len(data['aws_snapshot']['groups']),'roles':len(data['aws_snapshot']['roles']),
            'verdicts':state['integrated_risk_df']['final_action'].value_counts().to_dict()},
        'identities':rows,'aws_analysis':aws,'role_assignments':data['role_assignments'],'notes':data['notes'],
        'stages':{key:storage.dataframe_to_records(state[key]) for key in STAGE_KEYS},
        'input':{**data,'metadata':storage.dataframe_to_records(data['metadata']),'behavior':storage.dataframe_to_records(data['behavior'])}}
    REPORT_PATH.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return report

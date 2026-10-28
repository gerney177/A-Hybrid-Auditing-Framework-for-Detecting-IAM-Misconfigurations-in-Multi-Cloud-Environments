"""Re-run persisted inputs; compare with persisted results and published paper values."""
import contextlib
import hashlib
import io
import json
import sqlite3
from datetime import datetime, timezone

import pandas as pd
from data import storage

TABLE_KEYS = ['integrated_risk_df', 'post_integrated_risk_df', 'remediation_plan_df', 'remediation_effect_df']
STAGE_KEYS = ['normalized_df', 'rule_identity_summary_df', 'ai_analysis_df', 'graph_identity_summary_df',
              'graph_findings_df', 'raw_privilege_findings_df', 'integrated_risk_df',
              'remediation_plan_df', 'remediation_effect_df', 'post_integrated_risk_df']


def saved_inputs():
    """Read only saved 25-identity inputs with an existing comparison run."""
    with contextlib.closing(sqlite3.connect(storage.DB_PATH.as_uri() + '?mode=ro', uri=True)) as db:
        rows = db.execute('''SELECT d.id,d.created_at,d.source,d.payload_json,MAX(r.id)
            FROM datasets d JOIN analysis_runs r ON d.id=r.dataset_id
            GROUP BY d.id ORDER BY d.id DESC''').fetchall()
    result = []
    for dataset_id, created_at, source, payload_json, run_id in rows:
        if source == 'mock_extended':
            continue
        payload = json.loads(payload_json)
        if len({r['identity'] for r in payload['metadata']}) == 25:
            result.append(dict(dataset_id=dataset_id, created_at=created_at, source=source,
                               baseline_run_id=run_id, input_sha256=hashlib.sha256(payload_json.encode()).hexdigest()))
    return result


def compare_identity(state, baseline, identity):
    differences = []
    for key in TABLE_KEYS:
        actual = state[key].loc[state[key]['identity'].eq(identity)].reset_index(drop=True)
        expected = baseline[key].loc[baseline[key]['identity'].eq(identity)].reset_index(drop=True)
        try:
            pd.testing.assert_frame_equal(actual, expected, check_dtype=False, check_exact=False, rtol=1e-9, atol=1e-9)
        except AssertionError as error:
            differences.append({'table': key, 'detail': str(error)})
    return differences


def run_saved_dataset(dataset_id):
    selected = next((r for r in saved_inputs() if r['dataset_id'] == dataset_id), None)
    if selected is None:
        raise ValueError('비교할 이전 분석 결과가 있는 25개 데이터셋을 선택해 주세요.')
    data = storage.load_dataset(dataset_id)
    baseline = storage.load_analysis_run(selected['baseline_run_id'])['results']
    from pipeline import run_pipeline
    from analysis.policy_checks import find_action_wildcards
    from analysis.aws_policy_checks import find_aws_passrole_candidates
    with contextlib.redirect_stdout(io.StringIO()):
        state = run_pipeline(data=data)
    before, after = state['integrated_risk_df'], state['post_integrated_risk_df']
    identities = []
    for row in before.to_dict('records'):
        identity = row['identity']
        old = baseline['integrated_risk_df'].loc[lambda frame: frame['identity'].eq(identity)]
        post = after.loc[after['identity'].eq(identity)]
        differences = compare_identity(state, baseline, identity)
        identities.append({'identity': identity, '클라우드': row['source_csp'],
            '비교 결과': '불일치' if differences else '일치',
            '규칙 점수 R': row['rule_score'], '행동 이상 점수 A': row['ai_anomaly_score_raw'],
            '그래프 점수 G': row['graph_score'], '이전 저장 점수': None if old.empty else old.iloc[0]['hybrid_risk_score'],
            '이번 점수': row['hybrid_risk_score'], '이전 저장 판정': None if old.empty else old.iloc[0]['final_action'],
            '이번 판정': row['final_action'], '조치 후 점수': None if post.empty else post.iloc[0]['hybrid_risk_score'],
            '조치 후 판정': None if post.empty else post.iloc[0]['final_action'], 'differences': differences})
    # Coverage includes missing/unexpected identities, not just rows produced by the engine.
    for identity in sorted(set(data['metadata']['identity']) - set(before['identity'])):
        identities.append({'identity': identity, '비교 결과': '불일치', 'differences': [{'detail': '분석 결과에서 대상 누락'}]})
    paper_checks = []
    def paper(name, expected, actual):
        paper_checks.append({'확인 항목': name, '논문 기준': str(expected), '이번 결과': str(actual), '비교 결과': '일치' if expected == actual else '불일치'})
    paper('식별자 수', 25, len(before))
    paper('원시 정책 수', 25, len(data['policies']))
    paper('정규화 레코드 수', 38, len(state['normalized_df']))
    for cloud, count in [('AWS', 9), ('Azure', 8), ('GCP', 8)]:
        paper(f'{cloud} 식별자 수', count, int(before['source_csp'].eq(cloud).sum()))
    for action, count in [('BLOCK', 1), ('ALERT', 4), ('ALLOW', 20)]:
        paper(f'조치 전 {action}', count, int(before['final_action'].eq(action).sum()))
    # These five rounded scores/actions are explicitly listed in the supplied HWP, section 4.3.
    # Explicit spelling correspondence only; report the literal name difference separately.
    paper_names = {'serviceAccount01':'serviceaccount01', 'dataAnalyst01':'dataanalyst01'}
    for identity, risk, action in [('developer01',1.0,'BLOCK'),('userK',.504,'ALERT'),
            ('serviceAccount01',.294,'ALERT'),('auditor01',.159,'ALERT'),('dataAnalyst01',.138,'ALERT')]:
        data_identity = paper_names.get(identity, identity)
        if data_identity != identity:
            paper(identity + ' 이름 표기', identity, data_identity)
        found = before.loc[before['identity'].eq(data_identity)]
        paper(identity + ' 위험도/판정', f'{risk:.3f} / {action}',
              '대상 없음' if found.empty else f"{found.iloc[0]['hybrid_risk_score']:.3f} / {found.iloc[0]['final_action']}")
    effect = state['remediation_effect_df']
    paper('시뮬레이션 조치 대상 수', 4, len(effect))
    paper('조치 대상 평균 위험도 (전)', '0.450', f"{effect['before_risk_score'].mean():.3f}")
    paper('조치 대상 평균 위험도 (후)', '0.096', f"{effect['after_risk_score'].mean():.3f}")
    aws_records = [r for r in state['normalized_records'] if r['source_csp'] == 'AWS']
    return {'executed_at': datetime.now(timezone.utc).isoformat(), 'source': selected,
        'input': {'policies':data['policies'],'metadata':storage.dataframe_to_records(data['metadata']),
                  'behavior':storage.dataframe_to_records(data['behavior'])},
        'summary': {'identities':len(identities), 'matched':sum(not r['differences'] for r in identities),
                    'mismatched':sum(bool(r['differences']) for r in identities),
                    'verdicts':before['final_action'].value_counts().to_dict()},
        'identities':identities, 'paper_checks':paper_checks,
        'stages':{key:storage.dataframe_to_records(state[key]) for key in STAGE_KEYS},
        'aws_checks':{'identity_count':int(before['source_csp'].eq('AWS').sum()),
            'wildcard_findings':find_action_wildcards(aws_records),
            'passrole_findings':find_aws_passrole_candidates(aws_records)},
        'limits':['기존 25개는 논문용 Mock 데이터이며 운영 실측 데이터가 아닙니다.',
                  '이전 저장 결과 일치는 재현성 확인이며 독립적인 보안 정답 검증은 아닙니다.',
                  '역할·그룹 연결 원본이 없어 역할·그룹 경로 검증은 이 데이터로 수행하지 않습니다.',
                  '조치 후 결과는 시뮬레이션이며 실제 클라우드 권한은 변경하지 않습니다.']}

"""Compare declared expectations with the real AWS policy inspection pipeline."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from analysis.aws_policy_analysis import run_aws_policy_analysis

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / 'data/policy_validation_cases.json'
ENGINE_FILES = ['analysis/aws_policy_analysis.py', 'analysis/policy_checks.py',
                'analysis/aws_policy_checks.py', 'data/aws_adapter.py',
                'preprocessing/adapters.py', 'preprocessing/normalizer.py',
                'validation/policy_cases.py']


def load_catalog():
    catalog = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    cases = catalog['cases']
    if not cases or len({c['id'] for c in cases}) != len(cases):
        raise ValueError('검증 사례 ID는 비어 있지 않고 고유해야 합니다.')
    return catalog


def signatures():
    return {
        'catalog_sha256': hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest(),
        'engine_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ENGINE_FILES},
    }


def run_case(case):
    expected = copy.deepcopy(case['expected'])
    result = {key: copy.deepcopy(case[key]) for key in ('id', 'title', 'category', 'purpose', 'snapshot')}
    result.update(expected=expected, checks=[], status='ERROR')

    def compare(name, actual, target):
        result['checks'].append({'name': name, 'expected': target, 'actual': actual, 'passed': actual == target})

    try:
        state = run_aws_policy_analysis(copy.deepcopy(case['snapshot']))
    except Exception as error:
        result['actual'] = {'outcome': 'rejected', 'error_type': type(error).__name__, 'message': str(error)}
        if expected['outcome'] in ('unsupported', 'invalid'):
            compare('예상 오류 유형', type(error).__name__, expected['error_type'])
            compare('거부 사유 일치', expected['error_contains'] in str(error), True)
            result['status'] = 'PASS' if all(c['passed'] for c in result['checks']) else 'FAIL'
        else:
            result['checks'].append({'name': '분석 완료', 'expected': True, 'actual': False, 'passed': False})
        return result

    counts = {key: len(state[key]) for key in ('policy_items', 'normalized_records', 'wildcard_findings', 'passrole_findings')}
    result['actual'] = {'outcome': 'analyzed', 'counts': counts, 'analysis': state}
    compare('분석/거부 처리', 'analyzed', expected['outcome'])
    for key, value in expected.get('counts', {}).items():
        compare(key, counts[key], value)
    records = state['normalized_records']
    if 'resources' in expected:
        compare('원본 Resource 보존', [r['original_resources'] for r in records], [expected['resources']] * len(records))
    if 'condition' in expected:
        compare('원본 Condition 보존', [r['condition'] for r in records], [expected['condition']] * len(records))
        findings = state['passrole_findings'] + state['wildcard_findings']
        compare('후보 Condition 보존', [r['condition'] for r in findings], [expected['condition']] * len(findings))
    if 'wildcard_types' in expected:
        compare('와일드카드 유형', [r['wildcard_type'] for r in state['wildcard_findings']], expected['wildcard_types'])
    if 'attachment_type' in expected:
        compare('연결 방식', [r['attachment_type'] for r in records], [expected['attachment_type']] * len(records))
    if expected.get('permission_paths'):
        compare('사용자-그룹-정책 경로', all(len(r['permission_path']) == 3 and r['permission_path'][0] == r['identity'] and r['permission_path'][1] == r['group_arn'] for r in records), True)
        compare('후보 그룹 출처', all(r['policy_source_identity'] == r['group_arn'] for r in state['passrole_findings']), True)
    if 'unique_paths' in expected:
        compare('고유한 권한 연결 경로 수', len({tuple(p['permission_path']) for p in state['policy_items']}), expected['unique_paths'])
    result['status'] = 'PASS' if all(c['passed'] for c in result['checks']) else 'FAIL'
    return result


def run_validation_cases():
    catalog = load_catalog()
    results = [run_case(case) for case in catalog['cases']]
    return {
        'schema_version': 1, 'catalog_version': catalog['version'],
        'executed_at': datetime.now(timezone.utc).isoformat(), 'source': 'synthetic_only',
        **signatures(), 'summary': {'total': len(results),
            'passed': sum(r['status'] == 'PASS' for r in results),
            'failed': sum(r['status'] == 'FAIL' for r in results),
            'errors': sum(r['status'] == 'ERROR' for r in results),
            'expected_rejections': sum(r['expected']['outcome'] != 'analyzed' for r in results)},
        'results': results,
    }


def outcome_text(outcome):
    if outcome['outcome'] == 'analyzed':
        counts = outcome['counts']
        return f"정책 {counts['policy_items']} / 레코드 {counts['normalized_records']} / 와일드카드 {counts['wildcard_findings']} / PassRole {counts['passrole_findings']}"
    if outcome['outcome'] == 'rejected':
        return f"입력 거부: {outcome['error_type']} · {outcome['message']}"
    label = '미지원 입력 거부' if outcome['outcome'] == 'unsupported' else '잘못된 입력 거부'
    return f"{label}: {outcome['error_contains']}"


def report_rows(report):
    return [{'ID': r['id'], '결과': {'PASS': '통과', 'FAIL': '실패', 'ERROR': '실행 오류'}[r['status']], '분류': r['category'], '사례': r['title'],
             '기대 결과': outcome_text(r['expected']), '실제 결과': outcome_text(r['actual']),
             '설명': r['purpose']} for r in report['results']]


if __name__ == '__main__':
    import csv
    report = run_validation_cases()
    destination = ROOT / 'validation/reports'
    destination.mkdir(exist_ok=True)
    (destination / 'policy-validation-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    rows = report_rows(report)
    with (destination / 'policy-validation-report.csv').open('w', encoding='utf-8-sig', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(report['summary']))
    raise SystemExit(0 if report['summary']['failed'] == report['summary']['errors'] == 0 else 1)

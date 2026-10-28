"""Offline role policy tests. Run: python -m unittest checks.check_aws_role_policies -v"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

from data.aws_adapter import extract_aws_role_policies, extract_aws_user_policies
from analysis.aws_policy_analysis import run_aws_policy_analysis
from data import storage


def demo_snapshot():
    account = 'arn:aws:iam::000000000000'
    read = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::demo-data/*', 'Condition': {'Bool': {'aws:SecureTransport': 'true'}}}]}
    attached = [{'PolicyArn': account + ':policy/ReadSafe', 'PolicyName': 'ReadSafe'}]
    return {
        'source': 'synthetic_role_validation', 'collected_at': '2026-10-26T00:00:00+00:00',
        'users': [{'UserName': 'demo-reader', 'Arn': account + ':user/demo-reader', 'AttachedManagedPolicies': copy.deepcopy(attached)}],
        'groups': [],
        'managed_policies': [{'Arn': account + ':policy/ReadSafe', 'PolicyVersionList': [
            {'IsDefaultVersion': False, 'VersionId': 'v1', 'Document': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}},
            {'IsDefaultVersion': True, 'VersionId': 'v2', 'Document': read},
        ]}],
        'roles': [
            {'RoleName': 'NormalRole', 'Arn': account + ':role/team/NormalRole', 'AttachedManagedPolicies': copy.deepcopy(attached),
             'AssumeRolePolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Principal': '*'}]}},
            {'RoleName': 'WildcardRole', 'Arn': account + ':role/WildcardRole', 'RolePolicyList': [
                {'PolicyName': 'WildcardInline', 'PolicyDocument': {'Statement': {'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'}}}]},
            {'RoleName': 'PassRoleRole', 'Arn': account + ':role/PassRoleRole', 'RolePolicyList': [
                {'PolicyName': 'PassRoleInline', 'PolicyDocument': {'Statement': [
                    {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': account + ':role/ApprovedRole'},
                    {'Effect': 'Deny', 'Action': 'iam:PassRole', 'Resource': '*'},
                ]}}]},
        ],
    }


class RolePolicyTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = demo_snapshot()

    def test_normal_role_uses_only_default_version_and_not_trust_policy(self):
        state = run_aws_policy_analysis(self.snapshot)
        arn = self.snapshot['roles'][0]['Arn']
        self.assertEqual([r['original_action'] for r in state['normalized_records'] if r['identity'] == arn], ['s3:GetObject'])
        self.assertFalse(any(f['identity'] == arn for key in ('wildcard_findings', 'passrole_findings') for f in state[key]))

    def test_wildcard_and_passrole_expected_candidates(self):
        state = run_aws_policy_analysis(self.snapshot)
        self.assertEqual(len(state['policy_items']), 4)
        self.assertEqual(len(state['normalized_records']), 5)
        self.assertEqual([f['identity_name'] for f in state['wildcard_findings']], ['WildcardRole'])
        self.assertEqual([f['identity_name'] for f in state['passrole_findings']], ['PassRoleRole'])
        self.assertEqual(state['passrole_findings'][0]['original_resources'], ['arn:aws:iam::000000000000:role/ApprovedRole'])

    def test_provenance_survives_findings_and_normalization(self):
        state = run_aws_policy_analysis(self.snapshot)
        for key in ('normalized_records', 'wildcard_findings', 'passrole_findings'):
            for record in state[key]:
                self.assertIn(record['identity_type'], ('user', 'role'))
                self.assertEqual(record['policy_source_identity'], record['identity'])
                self.assertTrue(record['policy_id'])
                self.assertEqual(record['attachment_type'], record['identity_type'] + '_direct')
        safe = next(r for r in state['normalized_records'] if r['identity_type'] == 'role' and r['policy_type'] == 'managed')
        self.assertEqual(safe['policy_version'], 'v2')
        self.assertEqual(safe['condition'], {'Bool': {'aws:SecureTransport': 'true'}})

    def test_encoded_policy_and_single_statement(self):
        inline = self.snapshot['roles'][1]['RolePolicyList'][0]
        inline['PolicyDocument'] = quote(json.dumps(inline['PolicyDocument']))
        self.assertEqual(len(run_aws_policy_analysis(self.snapshot)['wildcard_findings']), 1)

    def test_missing_managed_policy_fails_loudly(self):
        self.snapshot['managed_policies'] = []
        with self.assertRaisesRegex(ValueError, '政策|정책 본문'):
            extract_aws_role_policies(self.snapshot)

    def test_missing_or_ambiguous_default_version_fails(self):
        for count in (0, 2):
            with self.subTest(count=count):
                snapshot = demo_snapshot()
                versions = snapshot['managed_policies'][0]['PolicyVersionList']
                for i, version in enumerate(versions):
                    version['IsDefaultVersion'] = i < count
                with self.assertRaisesRegex(ValueError, '기본 정책 버전'):
                    extract_aws_role_policies(snapshot)

    def test_no_roles_preserves_user_analysis(self):
        self.snapshot.pop('roles')
        state = run_aws_policy_analysis(self.snapshot)
        self.assertEqual(len(state['policy_items']), 1)
        self.assertTrue(all(r['identity_type'] == 'user' for r in state['normalized_records']))

    def test_missing_group_fails_loudly(self):
        self.snapshot['users'][0]['GroupList'] = ['UnimplementedGroup']
        with self.assertRaisesRegex(ValueError, '그룹 본문'):
            run_aws_policy_analysis(self.snapshot)

    def test_notaction_is_reported_not_silently_dropped(self):
        self.snapshot['roles'][1]['RolePolicyList'][0]['PolicyDocument'] = {'Statement': {'Effect': 'Allow', 'NotAction': 'iam:*', 'Resource': '*'}}
        with self.assertRaisesRegex(ValueError, 'NotAction'):
            run_aws_policy_analysis(self.snapshot)

    def test_source_is_not_mutated(self):
        before = copy.deepcopy(self.snapshot)
        run_aws_policy_analysis(self.snapshot)
        self.assertEqual(self.snapshot, before)

    def test_database_roundtrip(self):
        state = run_aws_policy_analysis(self.snapshot)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'data') as temp:
            with patch.object(storage, 'DB_PATH', Path(temp) / 'roles.db'):
                run_id = storage.save_aws_policy_run(self.snapshot, state)
                restored = storage.load_aws_policy_run(run_id)
                self.assertEqual(restored['snapshot'], self.snapshot)
                self.assertEqual(restored['state'], state)
                self.assertEqual(len(storage.list_aws_policy_runs()), 1)

    @unittest.skipUnless(
        (Path(__file__).resolve().parents[1] / 'data/aws_iam_snapshot.json').exists(),
        '실제 AWS 수집본(data/aws_iam_snapshot.json)이 없어 건너뜁니다. 계정 정보가 들어 있어 저장소에는 올리지 않는 파일입니다.',
    )
    def test_collected_user_results_unchanged(self):
        snapshot = json.loads((Path(__file__).resolve().parents[1] / 'data/aws_iam_snapshot.json').read_text(encoding='utf-8'))
        users_only = copy.deepcopy(snapshot)
        users_only['roles'] = []
        combined = run_aws_policy_analysis(snapshot)
        old_items = extract_aws_user_policies(snapshot)
        actual = [p for p in combined['policy_items'] if p['identity_type'] == 'user']
        self.assertEqual([{k:p[k] for k in old_items[i]} for i,p in enumerate(actual)], old_items)
        reference = run_aws_policy_analysis(users_only)
        for key in ('normalized_records', 'wildcard_findings', 'passrole_findings'):
            self.assertEqual([r for r in combined[key] if r['identity_type'] == 'user'], reference[key])


if __name__ == '__main__':
    unittest.main()

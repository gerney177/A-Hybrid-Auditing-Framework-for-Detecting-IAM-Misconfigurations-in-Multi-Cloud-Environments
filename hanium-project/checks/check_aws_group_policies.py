"""사용자-그룹-정책 연결의 오프라인 검증."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from checks.check_aws_role_policies import demo_snapshot as role_snapshot
from analysis.aws_policy_analysis import run_aws_policy_analysis
from data.aws_adapter import extract_aws_group_policies
from data import storage


def demo_snapshot():
    snapshot = role_snapshot()
    snapshot['source'] = 'synthetic_group_validation'
    snapshot['roles'] = []
    account = 'arn:aws:iam::000000000000'
    alice = snapshot['users'][0]
    alice.update(UserName='demo-alice', Arn=account + ':user/demo-alice', GroupList=['Readers', 'Operators'])
    snapshot['users'].append({'UserName': 'demo-bob', 'Arn': account + ':user/demo-bob', 'GroupList': ['Readers']})
    snapshot['groups'] = [
        {'GroupName': 'Readers', 'Arn': account + ':group/team/Readers',
         'AttachedManagedPolicies': copy.deepcopy(alice['AttachedManagedPolicies'])},
        {'GroupName': 'Operators', 'Arn': account + ':group/Operators', 'GroupPolicyList': [
            {'PolicyName': 'RestrictedPassRole', 'PolicyDocument': {'Statement': [
                {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': account + ':role/ApprovedRole', 'Condition': {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}}},
                {'Effect': 'Deny', 'Action': 'iam:*', 'Resource': '*'},
            ]}}]},
        {'GroupName': 'UnusedGroup', 'Arn': account + ':group/UnusedGroup', 'GroupPolicyList': [
            {'PolicyName': 'UnassignedWildcard', 'PolicyDocument': {'Statement': {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}}}]},
    ]
    return snapshot


class GroupPolicyTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = demo_snapshot()

    def test_group_permissions_belong_to_members_not_group_identity(self):
        state = run_aws_policy_analysis(self.snapshot)
        self.assertEqual(len(state['policy_items']), 4)
        self.assertEqual(len(state['normalized_records']), 5)
        self.assertEqual(len(state['wildcard_findings']), 0)
        self.assertEqual(len(state['passrole_findings']), 1)
        self.assertTrue(all(p['identity_type'] == 'user' for p in state['policy_items']))
        self.assertEqual({p['identity'] for p in state['policy_items']}, {u['Arn'] for u in self.snapshot['users']})

    def test_group_inline_candidate_preserves_user_group_conditions_and_path(self):
        candidate = run_aws_policy_analysis(self.snapshot)['passrole_findings'][0]
        self.assertEqual(candidate['identity_name'], 'demo-alice')
        self.assertEqual(candidate['attachment_type'], 'group')
        self.assertEqual(candidate['group_name'], 'Operators')
        self.assertEqual(candidate['policy_source_identity'], self.snapshot['groups'][1]['Arn'])
        self.assertEqual(candidate['permission_path'], [candidate['identity'], candidate['group_arn'], candidate['policy_id']])
        self.assertEqual(candidate['condition'], {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}})
        self.assertEqual(candidate['original_resources'], ['arn:aws:iam::000000000000:role/ApprovedRole'])

    def test_shared_policy_keeps_direct_and_each_membership_path(self):
        state = run_aws_policy_analysis(self.snapshot)
        rows = [p for p in state['policy_items'] if p['policy_name'] == 'ReadSafe']
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(p['attachment_type'] == 'group' for p in rows), 2)
        self.assertEqual(len({tuple(p['permission_path']) for p in rows}), 3)

    def test_default_managed_version_is_used(self):
        rows = run_aws_policy_analysis(self.snapshot)['normalized_records']
        readers = [r for r in rows if r.get('group_name') == 'Readers']
        self.assertEqual(len(readers), 2)
        self.assertTrue(all(r['original_action'] == 's3:GetObject' and r['policy_version'] == 'v2' for r in readers))

    def test_unassigned_group_does_not_grant_any_user_permissions(self):
        rows = extract_aws_group_policies(self.snapshot)
        self.assertFalse(any(p['group_name'] == 'UnusedGroup' for p in rows))

    def test_multiple_groups_with_shared_policy_keep_distinct_paths(self):
        self.snapshot['groups'][1]['AttachedManagedPolicies'] = copy.deepcopy(self.snapshot['groups'][0]['AttachedManagedPolicies'])
        rows = [p for p in extract_aws_group_policies(self.snapshot) if p['identity_name'] == 'demo-alice' and p['policy_name'] == 'ReadSafe']
        self.assertEqual({p['group_name'] for p in rows}, {'Readers', 'Operators'})
        self.assertEqual(len({tuple(p['permission_path']) for p in rows}), 2)

    def test_duplicate_membership_does_not_duplicate_findings(self):
        self.snapshot['users'][0]['GroupList'].append('Operators')
        self.assertEqual(len(run_aws_policy_analysis(self.snapshot)['passrole_findings']), 1)

    def test_missing_group_is_not_silently_ignored(self):
        self.snapshot['groups'].pop(0)
        with self.assertRaisesRegex(ValueError, '그룹 본문'):
            run_aws_policy_analysis(self.snapshot)

    def test_missing_group_managed_document_fails(self):
        self.snapshot['managed_policies'] = []
        with self.assertRaisesRegex(ValueError, '정책 본문'):
            extract_aws_group_policies(self.snapshot)

    def test_ambiguous_group_policy_version_fails(self):
        self.snapshot['managed_policies'][0]['PolicyVersionList'][0]['IsDefaultVersion'] = True
        with self.assertRaisesRegex(ValueError, '기본 정책 버전'):
            extract_aws_group_policies(self.snapshot)

    def test_same_inline_name_in_different_groups_keeps_source(self):
        inline = copy.deepcopy(self.snapshot['groups'][1]['GroupPolicyList'])
        inline[0]['PolicyDocument'] = quote(json.dumps(inline[0]['PolicyDocument']))
        self.snapshot['groups'][0]['GroupPolicyList'] = inline
        state = run_aws_policy_analysis(self.snapshot)
        rows = [p for p in state['policy_items'] if p['identity_name'] == 'demo-alice' and p['policy_type'] == 'inline']
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({p['policy_id'] for p in rows}), 2)

    def test_input_unchanged(self):
        before = copy.deepcopy(self.snapshot)
        run_aws_policy_analysis(self.snapshot)
        self.assertEqual(self.snapshot, before)

    def test_database_preserves_group_source(self):
        state = run_aws_policy_analysis(self.snapshot)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'data') as temp:
            with patch.object(storage, 'DB_PATH', Path(temp) / 'groups.db'):
                rid = storage.save_aws_policy_run(self.snapshot, state)
                saved = storage.load_aws_policy_run(rid)
                self.assertEqual(saved['snapshot'], self.snapshot)
                self.assertEqual(saved['state'], state)

    def test_empty_group_is_valid_and_grants_no_policy(self):
        self.snapshot['groups'][0].pop('AttachedManagedPolicies')
        self.assertFalse(any(p['group_name'] == 'Readers' for p in extract_aws_group_policies(self.snapshot)))

    def test_duplicate_group_names_fail(self):
        self.snapshot['groups'].append(copy.deepcopy(self.snapshot['groups'][0]))
        with self.assertRaisesRegex(ValueError, '중복된 그룹'):
            extract_aws_group_policies(self.snapshot)


if __name__ == '__main__':
    unittest.main()

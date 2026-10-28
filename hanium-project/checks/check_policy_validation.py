import copy
import unittest
from unittest.mock import patch
from validation.policy_cases import load_catalog, run_case


class PolicyMatrixTests(unittest.TestCase):
    pass


def make_test(case):
    def test(self):
        before = copy.deepcopy(case)
        result = run_case(case)
        self.assertEqual(result['status'], 'PASS', result)
        self.assertTrue(all(c['passed'] for c in result['checks']))
        self.assertEqual(case, before)
    return test


for case in load_catalog()['cases']:
    setattr(PolicyMatrixTests, 'test_' + case['id'], make_test(case))


class ValidationRunnerTests(unittest.TestCase):
    def test_wrong_expected_count_fails(self):
        case = copy.deepcopy(load_catalog()['cases'][0])
        case['expected']['counts']['passrole_findings'] = 1
        self.assertEqual(run_case(case)['status'], 'FAIL')

    def test_unexpected_runtime_error_is_not_a_pass(self):
        with patch('validation.policy_cases.run_aws_policy_analysis', side_effect=RuntimeError('unexpected')):
            self.assertEqual(run_case(load_catalog()['cases'][0])['status'], 'ERROR')

    def test_wrong_rejection_reason_fails(self):
        case = next(c for c in load_catalog()['cases'] if c['id'] == 'E01')
        with patch('validation.policy_cases.run_aws_policy_analysis', side_effect=ValueError('unrelated')):
            self.assertEqual(run_case(case)['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()

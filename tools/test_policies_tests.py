#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Check policy parsing, rule isolation and focused CI selection. The test.yml planning job runs
# this standalone test entry point before generating its matrix.

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_policies as policies


class PolicyTests(unittest.TestCase):
  def load(self, source):
    with tempfile.TemporaryDirectory() as directory:
      Path(directory, 'm00001.py').write_text(source)
      return policies.load_policies(Path(directory))

  def test_declarations_do_not_import_or_execute_oracles(self):
    result = self.load("raise RuntimeError('must not execute')\n"
                       "def module_test_properties():\n"
                       "  return {'tests': {'ordinary': {12: {'exclude': 'No matching fixture.'}}}}\n")
    self.assertEqual(result[1]['ordinary'][12]['exclude'], 'No matching fixture.')

  def test_invalid_declarations_fail_instead_of_dropping_rules(self):
    bodies = ["return dict()", "return []", "return {'unknown': {}}",
              "return {'edge': {2: {'exclude': 'No kernel.'}}}",
              "return {'edge': {4: {'exclude': ''}}}",
              "return {'edge': {4: {'ignore_failure': 'Unsafe.'}}}",
              "return {'edge': {'all': {'skip_output': 'No match.'}, 4: {'verify_output': 'Verify.'}}}",
              "print('side effect')\n  return {}"]
    for body in bodies:
      with self.subTest(body=body), self.assertRaises((ValueError, TypeError)):
        declaration = 'return {\"tests\": ' + body.removeprefix('return ') + '}' if body.startswith('return ') else body
        self.load('def module_test_properties():\n  ' + declaration + '\n')

  def test_attack_and_suite_rules_do_not_leak(self):
    data = {1: {'edge': {'all': {'verify_output': 'Check the oracle.'},
                         4: {'exclude_empty': 'No empty grammar word.'}},
                'ordinary': {12: {'exclude': 'No hybrid fixture.'}}}}
    with patch.object(policies, 'load_policies', return_value=data):
      self.assertTrue(policies.has_rule(1, 'edge', 4, 'exclude_empty'))
      self.assertFalse(policies.has_rule(1, 'edge', 0, 'exclude_empty'))
      self.assertTrue(policies.has_rule(1, 'edge', 0, 'verify_output'))
      self.assertFalse(policies.has_rule(1, 'ordinary', 0, 'verify_output'))
      self.assertFalse(policies.has_rule(2, 'ordinary', 12, 'exclude'))

  def test_inventory_distinguishes_exclusions_from_verification(self):
    rows = policies.inventory({14000, 37400})
    self.assertTrue(any(r['mode'] == 14000 and r['suite'] == 'ordinary' and
                        r['attack'] == 12 and r['rule'] == 'exclude' for r in rows))
    self.assertTrue(any(r['mode'] == 37400 and r['rule'] == 'verify_output' for r in rows))
    self.assertFalse(any(r['mode'] == 37400 and r['rule'] == 'skip_output' for r in rows))

  def test_focused_width_does_not_duplicate_split_jobs(self):
    root = Path(__file__).resolve().parent.parent
    output = subprocess.check_output([sys.executable, '.github/workflows/ci_matrix.py',
                                      'test', 'list', '34000', '--kinds', 'edge',
                                      '--vector-width', '2'], cwd=root, text=True)
    matrix = json.loads(next(line[7:] for line in output.splitlines() if line.startswith('matrix=')))
    self.assertEqual(len(matrix['include']), 1)
    self.assertEqual(matrix['include'][0]['vector_width'], 2)


if __name__ == '__main__':
  unittest.main()

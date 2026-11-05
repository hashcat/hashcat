#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Check policy parsing, incomplete coverage and CI selection without running hashcat.
# The test.yml planning job runs this standalone entry point before generating its matrix.

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_policies as policies
import test as runner
import test_bridge


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

  def test_shared_reasons_expand_and_custom_reasons_survive(self):
    result = self.load("def module_test_properties():\n"
                       "  return {'tests': {'edge': {'all': {'verify_output': True}},\n"
                       "                    'ordinary': {1: {'exclude': 'whole_word_candidates'},\n"
                       "                                 3: {'exclude': 'This format needs a custom candidate.'}}}}\n")
    self.assertEqual(result[1]['edge']['all']['verify_output'], policies.DEFAULT_REASONS['verify_output'])
    self.assertEqual(result[1]['ordinary'][1]['exclude'],
                     policies.NAMED_REASONS['exclude']['whole_word_candidates'])
    self.assertEqual(result[1]['ordinary'][3]['exclude'], 'This format needs a custom candidate.')

  def test_invalid_shared_reasons_fail(self):
    for action, reason in [('verify_output', False), ('verify_output', 1),
                           ('verify_output', 'whole_word_candidates'),
                           ('exclude', True), ('exclude', 'whole_word_candidate')]:
      with self.subTest(action=action, reason=reason), self.assertRaises(ValueError):
        self.load("def module_test_properties():\n  return " +
                  repr({'tests': {'edge': {0: {action: reason}}}}) + "\n")

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

  def test_des_two_key_policy_preserves_alternative_key_verification(self):
    self.assertTrue(policies.has_rule(14300, 'ordinary', 12, 'exclude'))
    self.assertTrue(policies.has_rule(14300, 'edge', 3, 'verify_output'))
    self.assertFalse(policies.has_rule(14300, 'edge', 3, 'skip_output'))

  def test_explicit_edge_exclusion_is_not_hidden_by_successful_cells(self):
    hh = dict(deprecated=False, slow=False, salt_present=True, salt_virtual=False,
              pw_type='ASCII', keep_guessing=False, kernel_types=['pure'])
    cfg = dict(attacks=[0, 3], attacks_set={0, 3}, kernel_filter=0, exec_filter=None,
               widths=[1], targets={0})
    with patch.object(runner, 'edge_hh', return_value=hh), \
         patch.object(runner, 'edge_oracle', return_value=([{'hash': b'hash'}], 0)), \
         patch.object(runner, 'edge_opts', return_value=[]), \
         patch.object(runner, 'edge_single', return_value=(0, 1)), \
         contextlib.redirect_stdout(io.StringIO()):
      self.assertEqual(runner.edge_process_mode(SimpleNamespace(attack='0,3'), 37000, cfg, '/tmp'), (1, 1))
      self.assertEqual(runner.edge_process_mode(SimpleNamespace(attack='all'), 37000, cfg, '/tmp'), (0, 1))

  def test_explicit_slow_attacks_are_not_filtered_in_a_mode_range(self):
    hh = dict(deprecated=False, slow=True, salt_present=True, salt_virtual=False,
              pw_type='ASCII', keep_guessing=False, kernel_types=['pure'])
    cfg = dict(attacks=[0, 3], attacks_set={0, 3}, kernel_filter=0, exec_filter=None, all_scope=True,
               all_attacks=False, widths=[1], targets={0})
    with patch.object(runner, 'edge_hh', return_value=hh), \
         patch.object(runner, 'edge_oracle', return_value=([{'hash': b'hash'}], 0)), \
         patch.object(runner, 'edge_opts', return_value=[]), \
         patch.object(runner, 'edge_single', return_value=(0, 1)):
      self.assertEqual(runner.edge_process_mode(SimpleNamespace(attack='0,3'), 40021, cfg, '/tmp'), (0, 2))
      self.assertEqual(runner.edge_process_mode(SimpleNamespace(attack='all'), 40021, cfg, '/tmp'), (0, 1))

  def test_bridge_rejects_partial_vector_coverage(self):
    result = SimpleNamespace(returncode=0, stdout=(
      b"echo word | ./hashcat ${OPTS} -a 0 -m 0 'short'\n"
      b"echo word | ./hashcat ${OPTS} -a 0 -m 0 'oversized'\n"))
    with tempfile.TemporaryDirectory() as directory, \
         patch.object(test_bridge.subprocess, 'run', return_value=result), \
         patch.object(test_bridge, 'bridge_line', side_effect=[b'hash*salt', None]), \
         contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
      test_bridge.vectors(0, False, str(Path(directory, 'hashes')), str(Path(directory, 'words')))

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

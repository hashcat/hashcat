#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Read oracle test rules without importing their crypto dependencies and generate the inventory.
# test.py, ci_matrix.py and test_policies_tests.py depend on this module.

# Read per-mode test policies for test.py and CI without importing optional oracle dependencies.

import argparse
import ast
import functools
import json
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent / "test_modules"
ATTACKS = (0, 1, 3, 4, 6, 7, 8, 9, 12)
ACTIONS = {
  "ordinary": {"exclude", "password_only", "hash_only", "whole_word", "single_hash"},
  "edge": {"exclude", "skip_output", "verify_output", "allow_same_salt", "exclude_empty", "single_hash"},
  "selftest": {"exclude", "mask_only"},
}


@functools.lru_cache(maxsize=None)
def load_policies(directory=DIRECTORY):
  policies = {}

  for path in sorted(Path(directory).glob("m[0-9][0-9][0-9][0-9][0-9].py")):
    source = path.read_text(encoding="utf-8")

    if "module_test_properties" not in source:
      continue

    hooks = [node for node in ast.parse(source, filename=str(path)).body
             if isinstance(node, ast.FunctionDef) and node.name == "module_test_properties"]

    if len(hooks) != 1 or len(hooks[0].body) != 1 or not isinstance(hooks[0].body[0], ast.Return):
      raise ValueError("%s: module_test_properties must return one literal dictionary" % path)

    properties = hooks[0].body[0].value
    if not isinstance(properties, ast.Dict):
      raise ValueError("%s: test properties must be a dictionary" % path)
    entries = {ast.literal_eval(key): value for key, value in zip(properties.keys, properties.values)}
    policy = ast.literal_eval(entries["tests"]) if "tests" in entries else {}

    if not isinstance(policy, dict):
      raise ValueError("%s: test constraints must be a dictionary" % path)

    for suite, attacks in policy.items():
      if suite not in ACTIONS or not isinstance(attacks, dict):
        raise ValueError("%s: invalid test suite %r" % (path, suite))

      for attack, rules in attacks.items():
        if attack != "all" and (type(attack) is not int or attack not in ATTACKS):
          raise ValueError("%s: invalid attack %r" % (path, attack))

        if not isinstance(rules, dict):
          raise ValueError("%s: attack rules must be a dictionary" % path)

        for action, reason in rules.items():
          if action not in ACTIONS[suite] or not isinstance(reason, str) or not reason.strip():
            raise ValueError("%s: invalid rule or missing reason for %r" % (path, action))
          if (action == "whole_word" or suite == "selftest" and action == "exclude") and attack != "all":
            raise ValueError("%s: %s is a suite-wide rule" % (path, action))
          if action == "mask_only" and attack != 3:
            raise ValueError("%s: mask-only self-tests require attack 3" % path)

      for attack in ATTACKS:
        merged = dict(attacks.get("all", {}))
        merged.update(attacks.get(attack, {}))
        if "skip_output" in merged and "verify_output" in merged:
          raise ValueError("%s: output cannot be both unchecked and oracle-verified" % path)

    policies[int(path.stem[1:])] = policy

  return policies


def rules_for(mode, suite, attack):
  attacks = load_policies().get(mode, {}).get(suite, {})
  rules = dict(attacks.get("all", {}))
  rules.update(attacks.get(attack, {}))
  return rules


def has_rule(mode, suite, attack, action):
  return action in rules_for(mode, suite, attack)


def modes_with_rule(suite, attack, action):
  return {mode for mode in load_policies() if has_rule(mode, suite, attack, action)}


def derived_inventory(modes=None):
  rows = []
  root = DIRECTORY.parent.parent

  for path in sorted(DIRECTORY.glob("m[0-9][0-9][0-9][0-9][0-9].py")):
    mode = int(path.stem[1:])

    if modes is not None and mode not in modes:
      continue

    tree = ast.parse(path.read_text(encoding="utf-8"))
    hook = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "module_test_properties")
    returned = next(node.value for node in hook.body if isinstance(node, ast.Return))
    entries = {ast.literal_eval(key): value for key, value in zip(returned.keys, returned.values)}
    constraints = entries["constraints"]
    families = {ast.literal_eval(key): value for key, value in zip(constraints.keys, constraints.values)}
    unavailable = {family: isinstance(value, ast.Constant) and value.value is None
                   for family, value in families.items()}
    module = root / "src" / "modules" / ("module_%05d.c" % mode)
    source = module.read_text(encoding="utf-8") if module.exists() else ""
    host = "ATTACK_EXEC_OUTSIDE_KERNEL" in source
    kern_type = None

    for line in source.splitlines():
      declaration, separator, value = line.partition("=")
      if separator and declaration.split()[-1:] == ["KERN_TYPE"]:
        try:
          kern_type = int(value.split(";", 1)[0].strip())
        except ValueError:
          pass

    for suite in ("ordinary", "edge"):
      for attack in ATTACKS:
        for family, slot in (("pure", 0), ("optimized", 2)):
          reason = None

          if unavailable[family]:
            reason = "The oracle declares no %s kernel family." % family
          elif attack == 4 and family == "optimized" and not host and kern_type is not None:
            if not (root / "OpenCL" / ("m%05d_a4-optimized.cl" % kern_type)).exists():
              reason = "There is no optimized PCFG kernel for this kernel type."

          if reason:
            rows.append({"mode": mode, "suite": suite, "attack": attack, "rule": "exclude_" + family,
                         "reason": reason, "source": str(path.relative_to(root)) + " / kernel capabilities"})

        if suite == "ordinary" and host and mode != 400 and attack not in (0, 4, 8, 9):
          rows.append({"mode": mode, "suite": suite, "attack": attack, "rule": "exclude",
                       "reason": "Host-engine modes use whole-word attacks in the ordinary suite.",
                       "source": str(module.relative_to(root))})

  return rows


def inventory(modes=None):
  rows = []

  for mode, policy in sorted(load_policies().items()):
    if modes is not None and mode not in modes:
      continue

    for suite, attacks in policy.items():
      for attack in ATTACKS:
        for action, reason in rules_for(mode, suite, attack).items():
          rows.append({"mode": mode, "suite": suite, "attack": attack, "rule": action,
                       "reason": reason, "source": "tools/test_modules/m%05d.py" % mode})

  shared = [
    ("ordinary", (0, 4, 8, 9), "exclude_multi", "When Hashes.Count.Max is 1, no multi-target case is run."),
    ("ordinary", (3, 6, 7, 12), "exclude_short_vector", "A vector is omitted when its password cannot supply the required mask and dictionary portions."),
    ("edge", (4,), "exclude_vector", "PCFG cannot represent an empty password or one containing a tab."),
    ("edge", ATTACKS, "exclude_multi", "Binary container fixtures and modes with Hashes.Count.Max == 1 have no multi-target case."),
    ("edge", (9,), "exclude_multi", "Association requires separate salts. Unsalted or virtual-salt fixtures have no multi-target case."),
    ("edge", ATTACKS, "limit_multi", "Multi-target fixtures obey Hashes.Count.Max and omit duplicate salts when shared salts are unsupported. Fewer than two selected hashes produces no multi-target case."),
    ("edge", ATTACKS, "skip_output", "Modes advertising keep-guessing skip literal output matching after a successful exit."),
    ("edge", (1, 3, 6, 7, 12), "exclude_in_sweep", "A default all-mode or range sweep omits expensive mask/combinator attacks for host-engine modes except mode 400. An individual-mode run retains them."),
  ]

  for suite, attacks, action, reason in shared:
    for attack in attacks:
      rows.append({"mode": "all", "suite": suite, "attack": attack, "rule": action,
                   "reason": reason, "source": "tools/test.py / shared conditional filters"})

  return rows + derived_inventory(modes)


def print_inventory(rows, output_format="markdown"):
  if output_format == "json":
    print(json.dumps(rows, indent=2))
  else:
    print("| Mode | Suite | Attack | Rule | Reason | Source |")
    print("| --- | --- | --- | --- | --- | --- |")
    for row in rows:
      values = [str(row[k]).replace("|", "\\|") for k in ("mode", "suite", "attack", "rule", "reason", "source")]
      print("| " + " | ".join(values) + " |")


def main():
  parser = argparse.ArgumentParser(description="List declared per-mode test exclusions and verification rules.")
  parser.add_argument("-m", "--mode", type=int, action="append", help="select a mode, repeat for several")
  parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
  args = parser.parse_args()
  print_inventory(inventory(set(args.mode) if args.mode else None), args.format)


if __name__ == "__main__":
  main()

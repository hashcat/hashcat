#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Shared by test.py and test_module_runner.py to select reduced-count hash generators.
# ci_matrix.py also reads the modules' CI timing declarations here. Neither path imports
# optional oracle dependencies. Explicit runtime policies also select matching oracle and hashcat costs.

import ast
import os
from functools import lru_cache

ITERATION_ENV = "ARTIFICIALLY_LOW_ITERATION_COUNT"
ITERATION_RUNTIME_ENV = "HASHCAT_ITER_OVERRIDE"


@lru_cache(maxsize=None)
def load_test_properties(mode):
  # Read iteration and timing metadata without evaluating constraints or importing crypto libraries.
  directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_modules")
  filename = "m%05d.py" % mode
  hook = "module_test_properties"
  settings = {}

  if not os.path.isfile(os.path.join(directory, filename)):
    return {}

  with open(os.path.join(directory, filename), encoding="utf-8") as source:
    text = source.read()

  if hook not in text:
    return {}

  for node in ast.parse(text, filename=filename).body:
    if not isinstance(node, ast.FunctionDef) or node.name != hook:
      continue

    if len(node.body) != 1 or not isinstance(node.body[0], ast.Return) or not isinstance(node.body[0].value, ast.Dict):
      raise ValueError("%s: %s must return a literal dictionary" % (filename, hook))

    properties = node.body[0].value
    keys = [ast.literal_eval(key) for key in properties.keys]
    if "constraints" not in keys or set(keys) - {"constraints", "normal", "reduced", "runtime"}:
      raise ValueError("%s: test properties require constraints and allow normal, reduced and runtime entries" % filename)
    settings = {
      key: ast.literal_eval(value) for key, value in zip(keys, properties.values) if key != "constraints"
    }

  if not isinstance(settings, dict) or set(settings) - {"normal", "reduced", "runtime"}:
    raise ValueError("m%05d.py: test settings allow normal, reduced and runtime entries" % mode)
  if "reduced" in settings and "runtime" in settings:
    raise ValueError("m%05d.py: choose encoded or runtime reduction, not both" % mode)
  for name, section in settings.items():
    allowed = {"limit", "compiled_cost", "scrypt", "parameters"} if name == "runtime" else {"ci_seconds", "parameters"}
    if not isinstance(section, dict) or set(section) - allowed:
      raise ValueError("m%05d.py: invalid %s test settings" % (mode, name))
    if name == "runtime":
      limit = section.get("limit")
      if type(limit) is not int or not 1 <= limit <= 4294967295:
        raise ValueError("m%05d.py: runtime limit must be a positive uint32" % mode)
      if any(type(section[key]) is not bool for key in ("compiled_cost", "scrypt") if key in section):
        raise ValueError("m%05d.py: runtime flags must be booleans" % mode)
    if name == "reduced" and section.get("parameters") != {"iterations": 2}:
      raise ValueError("m%05d.py: reduced testing requires 2 encoded iterations" % mode)
    parameters = section.get("parameters", {})
    allowed_parameters = {"iterations", "scrypt_n", "user_hash_iterations"} if name == "normal" else {"iterations"}
    if not isinstance(parameters, dict) or set(parameters) - allowed_parameters:
      raise ValueError("m%05d.py: invalid iteration parameters" % mode)
    if any(type(value) is not int or value < 1 for value in parameters.values()):
      raise ValueError("m%05d.py: iteration counts must be positive integers" % mode)
    seconds = section.get("ci_seconds", {})
    if not isinstance(seconds, dict) or set(seconds) - {"opt", "pure", "bridge", "edge"}:
      raise ValueError("m%05d.py: invalid CI timing kinds" % mode)
    if any(type(value) is not int or value < 1 for value in seconds.values()):
      raise ValueError("m%05d.py: CI timings must be positive integer seconds" % mode)
  return settings


def reduced_iteration_parameters(mode):
  # Read only the selected mode's reduced parameters, caching its declaration for later calls.
  return load_test_properties(mode).get("reduced", {}).get("parameters", {})


def reduced_ci_timings(modes):
  # Index selected modes' reduced-count timing estimates by test kind for the CI planner.
  timings = {}
  for mode in modes:
    settings = load_test_properties(mode)
    for kind, seconds in settings.get("reduced", {}).get("ci_seconds", {}).items():
      timings.setdefault(kind, {})[mode] = seconds
  return timings


def iteration_reduction_requested(source=None):
  env = os.environ if source is None else source
  value = env.get(ITERATION_ENV, "false").lower()

  if value not in ("true", "false"):
    raise ValueError("%s must be true or false" % ITERATION_ENV)

  return value == "true"


def iteration_reduction_enabled(mode):
  return iteration_reduction_requested() and (bool(reduced_iteration_parameters(mode)) or bool(runtime_iteration_policy(mode)))


def iteration_copy_hash(mode):
  # Preserve the custom count that this mode's hash encoder omits from its output.
  return iteration_reduction_enabled(mode) and (mode == 40041 or bool(runtime_iteration_policy(mode)))


def generate_iteration_hash(mod, word, salt, iterations=None, **extra):
  # Apply reduced generator defaults while letting explicit arguments take precedence.
  kwargs = dict(getattr(mod, "ITERATION_PARAMETERS", {})) if iterations is None else {"iterations": iterations}
  kwargs.update(extra)

  if mod.__name__ == "m33700":
    return mod.module_generate_hash(word, **kwargs)

  return mod.module_generate_hash(word, salt, **kwargs)


def runtime_iteration_policy(mode):
  # A runtime declaration explicitly opts this mode into nonstandard test costs.
  return load_test_properties(mode).get("runtime", {})


def iteration_parameters(mode):
  # Read encoded defaults or runtime-specific generator parameters in the oracle process.
  if not iteration_reduction_requested():
    return {}
  policy = runtime_iteration_policy(mode)
  return dict(reduced_iteration_parameters(mode) or policy.get("parameters", {}))


def iteration_disable_selftest(mode):
  return iteration_reduction_enabled(mode) and runtime_iteration_policy(mode).get("compiled_cost", False)


def iteration_environment(mode, source=None, generated=True):
  # Remove inherited overrides and enable only the selected generated hash policy.
  env = dict(os.environ if source is None else source)
  env.pop(ITERATION_RUNTIME_ENV, None)

  if generated and iteration_reduction_requested(env) and bool(runtime_iteration_policy(mode)):
    env[ITERATION_RUNTIME_ENV] = str(runtime_iteration_policy(mode)["limit"])

  return env

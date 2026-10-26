#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Shared by test.py and test_module_runner.py to select reduced-count hash generators.
# ci_matrix.py also reads the modules' CI timing declarations here. Neither path imports
# optional oracle dependencies. Hashcat reads the generated counts without a runtime override.

import ast
import os
from functools import lru_cache

ITERATION_ENV = "ARTIFICIALLY_LOW_ITERATION_COUNT"


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
    if "constraints" not in keys or set(keys) - {"constraints", "normal", "reduced"}:
      raise ValueError("%s: test properties require constraints and allow normal and reduced entries" % filename)
    settings = {
      key: ast.literal_eval(value) for key, value in zip(keys, properties.values) if key != "constraints"
    }

  if not isinstance(settings, dict) or set(settings) - {"normal", "reduced"}:
    raise ValueError("m%05d.py: test settings allow normal and reduced entries" % mode)
  for name, section in settings.items():
    allowed = {"ci_seconds", "parameters"}
    if not isinstance(section, dict) or set(section) - allowed:
      raise ValueError("m%05d.py: invalid %s test settings" % (mode, name))
    if name == "reduced" and section.get("parameters") != {"iterations": 2}:
      raise ValueError("m%05d.py: reduced testing requires 2 encoded iterations" % mode)
    parameters = section.get("parameters", {})
    if not isinstance(parameters, dict) or set(parameters) - {"iterations"}:
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


def iteration_reduction_requested():
  value = os.environ.get(ITERATION_ENV, "false").lower()

  if value not in ("true", "false"):
    raise ValueError("%s must be true or false" % ITERATION_ENV)

  return value == "true"


def iteration_reduction_enabled(mode):
  return iteration_reduction_requested() and bool(reduced_iteration_parameters(mode))


def iteration_copy_hash(mode):
  # Preserve the custom count that this mode's hash encoder omits from its output.
  return mode == 40041 and iteration_reduction_enabled(mode)


def generate_iteration_hash(mod, word, salt, iterations=None, **extra):
  # Apply reduced generator defaults while letting explicit arguments take precedence.
  kwargs = dict(getattr(mod, "ITERATION_PARAMETERS", {})) if iterations is None else {"iterations": iterations}
  kwargs.update(extra)

  if mod.__name__ == "m33700":
    return mod.module_generate_hash(word, **kwargs)

  return mod.module_generate_hash(word, salt, **kwargs)

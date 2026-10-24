#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Part of tools/test.py. Shared iteration selection and child-process settings for its oracle runner.

import ast
import hashlib
import json
import os


def load_iteration_policies():
  parameters = {}
  runtime_limits = {}
  compiled_cost_modes = set()
  directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_modules")
  hook = "module_reduced_iteration_constraints"

  # Read literal declarations without importing optional oracle dependencies or evaluating defaults.
  for filename in sorted(os.listdir(directory)):
    if not filename.startswith("m") or not filename.endswith(".py") or not filename[1:-3].isdigit():
      continue

    with open(os.path.join(directory, filename), encoding="utf-8") as source:
      text = source.read()

    if hook not in text:
      continue

    mode = int(filename[1:-3])

    for node in ast.parse(text, filename=filename).body:
      if not isinstance(node, ast.FunctionDef) or node.name != hook:
        continue

      if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
        raise ValueError("%s: %s must return a literal dictionary" % (filename, hook))

      policy = ast.literal_eval(node.body[0].value)

      if not isinstance(policy, dict) or set(policy) - {"parameters", "runtime_limits", "compiled_cost"}:
        raise ValueError("%s: invalid reduced-iteration policy" % filename)

      if "parameters" in policy:
        parameters[mode] = policy["parameters"]
      if "runtime_limits" in policy:
        runtime_limits[mode] = policy["runtime_limits"]
      if policy.get("compiled_cost", False):
        compiled_cost_modes.add(mode)

  return parameters, runtime_limits, compiled_cost_modes


ARTIFICIAL_ITERATION_PARAMETERS, RUNTIME_ITERATION_LIMITS, COMPILED_COST_MODES = load_iteration_policies()
RUNTIME_ITERATION_MODES = set(RUNTIME_ITERATION_LIMITS)
RUNTIME_SCRYPT_MODES = {mode for mode, limits in RUNTIME_ITERATION_LIMITS.items() if "scrypt_N" in limits}
ITERATION_ENV = "ARTIFICIALLY_LOW_ITERATION_COUNT"
ITERATION_RUNTIME_ENV = "HASHCAT_ITER_OVERRIDE"
ITERATION_PARAMETER_ENV = "HASHCAT_TEST_ITERATION_PARAMETERS"

ITERATION_SKIP_REASONS = {500: 'md5crypt kernels require the full round schedule',
 501: 'md5crypt kernels require the full round schedule',
 1600: 'md5crypt kernels require the full round schedule',
 2501: 'candidate supplies the already-derived PMK',
 3300: 'md5sun starts at its minimum round count',
 4000: 'hash recipe defines its own iteration contract',
 10500: 'PDF requires the complete MD5 and RC4 stage schedule',
 10510: 'PDF requires the complete MD5 and RC4 stage schedule',
 10700: 'PDF revision 6 has a data-dependent stopping condition',
 12500: 'RAR3 requires the full round schedule to construct its IV',
 14600: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 16801: 'candidate supplies the already-derived PMK',
 22001: 'candidate supplies the already-derived PMK',
 22100: 'BitLocker requires its fixed round table and kernel chunk schedule',
 23700: 'RAR3 requires the full round schedule to construct its IV',
 23900: 'BestCrypt v3 hashes a fixed input buffer rather than an iterative KDF',
 25000: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 25100: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 25200: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 25400: 'PDF requires the complete MD5 and RC4 stage schedule',
 26700: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 26800: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 26900: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 27000: 'candidate supplies the already-derived NT hash',
 27100: 'candidate supplies the already-derived NT hash',
 27300: 'SNMPv3 kernels finalize with a fixed one-megabyte padding length',
 28501: 'candidate supplies a private key rather than an iterative password KDF',
 28502: 'candidate supplies a private key rather than an iterative password KDF',
 28503: 'candidate supplies a private key rather than an iterative password KDF',
 28504: 'candidate supplies a private key rather than an iterative password KDF',
 28505: 'candidate supplies a private key rather than an iterative password KDF',
 28506: 'candidate supplies a private key rather than an iterative password KDF',
 29511: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29512: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29513: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29521: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29522: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29523: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29531: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29532: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29533: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29541: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29542: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 29543: "no round-trip oracle, container generation already uses cryptsetup's 1000-round minimum",
 30901: 'candidate supplies a private key rather than an iterative password KDF',
 30902: 'candidate supplies a private key rather than an iterative password KDF',
 30903: 'candidate supplies a private key rather than an iterative password KDF',
 30904: 'candidate supplies a private key rather than an iterative password KDF',
 30905: 'candidate supplies a private key rather than an iterative password KDF',
 30906: 'candidate supplies a private key rather than an iterative password KDF',
 31500: 'candidate supplies the already-derived NT hash',
 32700: 'Kremlin kernels require complete 1000-round chunks',
 34100: "no round-trip oracle, container generation already uses cryptsetup's four-pass minimum",
 34700: 'wallet derivation already uses one PBKDF2 iteration',
 35300: 'candidate supplies the already-derived NT hash',
 35400: 'candidate supplies the already-derived NT hash',
 36000: 'BIP39 loop count enumerates derivation paths rather than PBKDF2 rounds',
 38000: 'EC-SRP5 performs scalar multiplication rather than an iterative KDF',
 73000: 'generic bridge owns the complete hashing operation',
 74000: 'generic bridge owns the complete hashing operation'}


def iteration_reduction_requested(source=None):
  env = os.environ if source is None else source
  value = env.get(ITERATION_ENV, "false").lower()

  if value not in ("true", "false"):
    raise ValueError("%s must be true or false" % ITERATION_ENV)

  return value == "true"


def initialize_iteration_seed():
  if iteration_reduction_requested() and not os.environ.get("HCTEST_SEED"):
    os.environ["HCTEST_SEED"] = str(int.from_bytes(os.urandom(8), "big"))


def select_iteration_parameters(table, mode, channel, source=None):
  env = os.environ if source is None else source
  seed = str(int(env.get("HCTEST_SEED") or "0"))
  selected = {}

  for name, bounds in table.get(mode, {}).items():
    if isinstance(bounds, int):
      selected[name] = bounds
      continue

    if len(bounds) not in (2, 3):
      raise ValueError("invalid iteration bounds for mode %d, parameter %s" % (mode, name))

    lower, upper = bounds[:2]
    step = bounds[2] if len(bounds) == 3 else 1

    if not isinstance(lower, int) or not isinstance(upper, int) or lower < 0 or upper < lower:
      raise ValueError("invalid iteration bounds for mode %d, parameter %s" % (mode, name))

    if step == "power2":
      if lower < 1:
        raise ValueError("power-of-two bounds must be positive")
      first = (lower - 1).bit_length()
      count = upper.bit_length() - first
    else:
      if not isinstance(step, int) or step < 1:
        raise ValueError("iteration step must be a positive integer")
      count = (upper - lower) // step + 1

    if count < 1:
      raise ValueError("iteration bounds contain no valid values")

    key = "%s:%d:%s:%s" % (seed, mode, channel, name)
    index = int.from_bytes(hashlib.sha256(key.encode("ascii")).digest(), "big") % count
    selected[name] = (1 << (first + index)) if step == "power2" else lower + index * step

  return selected


def iteration_parameters(mode, source=None):
  return select_iteration_parameters(ARTIFICIAL_ITERATION_PARAMETERS, mode, "encoded", source) if iteration_reduction_requested(source) else {}


def iteration_reduction_enabled(mode, source=None):
  return iteration_reduction_requested(source) and (mode in ARTIFICIAL_ITERATION_PARAMETERS or mode in RUNTIME_ITERATION_MODES)


def iteration_runtime_limit(mode, source=None):
  if not iteration_reduction_requested(source) or mode not in RUNTIME_ITERATION_LIMITS:
    return 0

  selected = select_iteration_parameters(RUNTIME_ITERATION_LIMITS, mode, "runtime", source)

  if len(selected) != 1:
    raise ValueError("a runtime override must select exactly one parameter")

  return next(iter(selected.values()))


def iteration_copy_hash(mode):
  return iteration_reduction_enabled(mode) and (mode in RUNTIME_ITERATION_MODES or mode in (6300, 13000, 28100, 40041))


def iteration_disable_selftest(mode):
  return iteration_reduction_enabled(mode) and mode in COMPILED_COST_MODES


def iteration_environment(mode, source=None, generated=True):
  env = dict(os.environ if source is None else source)

  if iteration_reduction_requested(env):
    env["HCTEST_SEED"] = env.get("HCTEST_SEED") or "0"

  env.pop(ITERATION_RUNTIME_ENV, None)
  env.pop(ITERATION_PARAMETER_ENV, None)

  if generated and mode in RUNTIME_ITERATION_MODES and iteration_reduction_requested(env):
    env[ITERATION_RUNTIME_ENV] = str(iteration_runtime_limit(mode, env))

  return env


def iteration_oracle_environment(mode, source=None):
  env = iteration_environment(mode, source)

  if iteration_reduction_enabled(mode, env):
    env[ITERATION_PARAMETER_ENV] = json.dumps({str(mode): iteration_parameters(mode, env)})

  return env


def iteration_full_cost_reason(mode):
  return ITERATION_SKIP_REASONS.get(mode, "no reduced-iteration generator contract")


def generate_iteration_hash(mod, word, salt, iterations=None, **extra):
  mode = int(mod.__name__[1:])
  keyword = next(iter(ARTIFICIAL_ITERATION_PARAMETERS.get(mode, {})), "iterations")
  kwargs = dict(getattr(mod, "ITERATION_PARAMETERS", {})) if iterations is None else {keyword: iterations}
  kwargs.update(extra)

  if mode == 33700:
    return mod.module_generate_hash(word, **kwargs)

  return mod.module_generate_hash(word, salt, **kwargs)

#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
import os

ENV = "ARTIFICIALLY_LOW_ITERATION_COUNT"
RUNTIME_ENV = "HASHCAT_ITER_OVERRIDE"
PARAMETER_ENV = "HASHCAT_TEST_ITERATION_PARAMETERS"
PARAMETERS = {}
RUNTIME_LIMITS = {}
RUNTIME_MODES = set()
RUNTIME_SCRYPT = {9300, 22700, 24000, 38200}
COMPILED_COST_MODES = set()


def configure(parameters, runtime_limits, compiled_cost_modes):
  global PARAMETERS, RUNTIME_LIMITS, RUNTIME_MODES, COMPILED_COST_MODES

  PARAMETERS = parameters
  RUNTIME_LIMITS = runtime_limits
  RUNTIME_MODES = set(runtime_limits)
  COMPILED_COST_MODES = compiled_cost_modes


SKIP = {500: 'md5crypt kernels require the full round schedule',
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


def requested(source=None):
  env = os.environ if source is None else source
  value = env.get(ENV, "false").lower()

  if value not in ("true", "false"):
    raise ValueError("%s must be true or false" % ENV)

  return value == "true"


def parameters(mode, source=None):
  return dict(PARAMETERS.get(mode, {})) if requested(source) else {}


def enabled(mode, source=None):
  return requested(source) and (mode in PARAMETERS or mode in RUNTIME_MODES)


def runtime_limit(mode, source=None):
  return RUNTIME_LIMITS.get(mode, 0) if requested(source) else 0


def copy_hash(mode):
  return enabled(mode) and (mode in RUNTIME_MODES or mode in (6300, 13000, 28100, 40041))


def disable_selftest(mode):
  return enabled(mode) and mode in COMPILED_COST_MODES


def environment(mode, source=None, generated=True):
  env = dict(os.environ if source is None else source)
  env.pop(RUNTIME_ENV, None)
  env.pop(PARAMETER_ENV, None)

  if generated and mode in RUNTIME_MODES and requested(env):
    env[RUNTIME_ENV] = str(runtime_limit(mode, env))

  return env


def oracle_environment(mode, source=None):
  env = environment(mode, source)

  if enabled(mode, env):
    env[PARAMETER_ENV] = json.dumps({str(mode): parameters(mode, env)})

  return env


def reason(mode):
  return SKIP.get(mode, "no reduced-iteration generator contract")


def generate(mod, word, salt, iterations=None, **extra):
  mode = int(mod.__name__[1:])
  keyword = next(iter(PARAMETERS.get(mode, {})), "iterations")
  kwargs = dict(getattr(mod, "ITERATION_PARAMETERS", {})) if iterations is None else {keyword: iterations}
  kwargs.update(extra)

  if mode == 33700:
    return mod.module_generate_hash(word, **kwargs)

  return mod.module_generate_hash(word, salt, **kwargs)

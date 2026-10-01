#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Unit test for test.py's depth -j device resolution: the parse of "hashcat -I --machine-readable" and
# the GPU-type inference, memory cap and alias dedup built on top of it. The fixtures are machine
# readable -I output, so this runs with no GPU and reproduces a CUDA plus HIP box no single machine here
# has. Run it with no argument to check the fixtures, or point it at a real binary to also print what the
# live box resolves, old parse versus new, so the fix is visible on the GPU box:
#
#   python3 tools/test_backend_devices.py
#   python3 tools/test_backend_devices.py ./hashcat
#
# Exit status is 0 only when every fixture assertion holds.

import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_testpy():
  # Import tools/test.py as a module. Its main() is guarded by __name__, so importing runs no suite.
  spec = importlib.util.spec_from_file_location("testpy", os.path.join(HERE, "test.py"))
  mod  = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)

  return mod


# A box with an RTX A400 on CUDA, a Radeon Pro W7800 on HIP, both again through OpenCL, plus a Xeon. The
# CUDA and HIP device objects carry no Type (hashcat prints none); the OpenCL twins carry an Alias back
# to their native id. This is jsteube's reported box.
MIXED = {
  "CUDAInfo":   {"Version": "12.2", "BackendDevices": [
    {"DeviceID": "01", "Alias": "03", "Name": "NVIDIA RTX A400", "MemoryFree": "3702 MB"}]},
  "HIPInfo":    {"Version": "6.2",  "BackendDevices": [
    {"DeviceID": "02", "Alias": "04", "Name": "AMD Radeon Pro W7800", "MemoryFree": "32710 MB"}]},
  "OpenCLInfo": {"Platforms": [{"PlatformID": "1", "BackendDevices": [
    {"DeviceID": "03", "Alias": "01", "Type": "GPU", "MemoryFree": "3702 MB"},
    {"DeviceID": "04", "Alias": "02", "Type": "GPU", "MemoryFree": "32710 MB"},
    {"DeviceID": "05", "Type": "CPU", "MemoryFree": "96064 MB"}]}]},
}

# A box with only the CUDA runtime: two cards, neither carrying a Type. The old parser typed both None
# and resolved no GPU, so the depth split fell through to one unpinned worker.
CUDA_ONLY = {"CUDAInfo": {"Version": "12.2", "BackendDevices": [
  {"DeviceID": "01", "Name": "NVIDIA RTX A400", "MemoryFree": "3702 MB"},
  {"DeviceID": "02", "Name": "NVIDIA RTX A400", "MemoryFree": "3600 MB"}]}}

# An OpenCL-only CPU host (what a PoCL dev box looks like): no GPU, so the depth split has nothing to
# pin and must say so.
OPENCL_CPU = {"OpenCLInfo": {"Platforms": [{"PlatformID": "1", "BackendDevices": [
  {"DeviceID": "01", "Type": "CPU", "Name": "some CPU", "MemoryFree": "16000 MB"}]}]}}

# device -> (expected backend_ids_for, expected min_device_free_mib)
CASES = [
  ("MIXED CUDA+HIP+OpenCL twins", MIXED, {
    "2": ([1, 2], 3702),     # the two native GPUs, OpenCL twins dropped; cap from the smaller card
    "1": ([5], 96064),       # the Xeon; a CPU run caps from the CPU's own free, not a GPU's
    "":  ([1, 2, 5], 3702)}),
  ("CUDA-only", CUDA_ONLY, {
    "2": ([1, 2], 3600),     # one slot per card, not the old empty fall-through
    "1": ([], None)}),
  ("OpenCL CPU only", OPENCL_CPU, {
    "2": ([], None),         # no GPU: depth split warns and runs one unpinned worker
    "1": ([1], 16000)}),
]


def run_fixtures(tp):
  ok = True

  for label, info, wants in CASES:
    devs = tp.parse_backend_devices(json.dumps(info))
    print("== %s ==" % label)

    for device, (want_ids, want_free) in wants.items():
      got_ids  = tp.backend_ids_for(device, devs)
      got_free = tp.min_device_free_mib(device, devs)
      status   = "ok " if (got_ids == want_ids and got_free == want_free) else "BAD"

      if status == "BAD":
        ok = False

      print("  %s -D %-3r ids=%-10s (want %-10s)  min_free=%-6s (want %s)"
            % (status, device or "<all>", got_ids, want_ids, got_free, want_free))

    print()

  return ok


def wanted(device):
  type_of = {"1": "CPU", "2": "GPU", "3": "FPGA"}

  return {type_of[c] for c in device.replace(",", " ").split() if c in type_of}


def old_resolve(text, device):
  # What the pre-fix code resolved, re-derived from the same -I so the before/after is concrete: a device
  # is typed only from an explicit Type field, so CUDA and HIP (which print none) are untyped and
  # dropped, and there is no alias dedup. On a box where a card shows on both its native backend and
  # OpenCL this picks the OpenCL twin or drops the native one; the fix picks the native card instead.
  try:
    info = json.loads(text)
  except Exception:
    return []

  want = wanted(device)
  ids  = []

  def walk(lst):
    for d in lst:
      t = d.get("Type")
      t = t.upper() if t else None
      if not want or t in want:
        try:
          ids.append(int(d["DeviceID"]))
        except (KeyError, TypeError, ValueError):
          pass

  for body in info.values():
    if not isinstance(body, dict):
      continue
    walk(body.get("BackendDevices", []))
    for plat in body.get("Platforms", []):
      if isinstance(plat, dict):
        walk(plat.get("BackendDevices", []))

  return ids


def run_live(tp, binary):
  print("== live: %s -I --machine-readable ==" % binary)

  try:
    out = subprocess.run([binary, "-I", "--machine-readable"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode("utf-8", "replace")
  except Exception as e:
    print("  could not run the binary: %s" % e)
    return

  devs = tp.parse_backend_devices(out)

  if not devs:
    print("  no devices parsed (is this a hashcat that supports -I --machine-readable?)")
    return

  for d in devs:
    print("  id=%s backend=%-7s type=%-5s free=%-7s alias=%s"
          % (d["id"], d["backend"], d["type"], d["free"], d["alias"]))

  for device in ("2", "1"):
    # On a box where an NVIDIA or AMD card appears on both its native backend and OpenCL, new resolves
    # to the native card while old dropped it (untyped) or picked the OpenCL twin.
    print("  -D %s  old ids=%-12s  new ids=%s"
          % (device, old_resolve(out, device), tp.backend_ids_for(device, devs)))

  print()


tp = load_testpy()

if __name__ == "__main__":
  passed = run_fixtures(tp)

  if len(sys.argv) > 1:
    run_live(tp, sys.argv[1])
  else:
    print("(pass a hashcat binary path to also print what this box resolves)\n")

  print("RESULT:", "all fixtures passed" if passed else "FIXTURE FAILURE")
  sys.exit(0 if passed else 1)

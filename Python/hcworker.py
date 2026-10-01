#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The process hashcat starts for every Python bridge unit. It loads the plugin named on the command
# line and then serves batches of candidates over its standard input and output until hashcat closes
# them.
#
# Every message in either direction is a frame: a u32 type, a u32 payload length and the payload. Both
# ends of the pipe are the same machine, so the two numbers travel in the machine's own byte order and
# neither side has to convert. hashcat sends INIT once and then a BATCH per launch. This side answers
# HELLO at startup, READY for the INIT, a RESULT for every BATCH, and an ERROR in place of any of them
# when something fails. An ERROR is the last frame a worker writes.

import importlib.util
import os
import signal
import struct
import sys
import traceback

PROTOCOL_VERSION = 2

# Anything the interpreter itself printed to its standard output before this script ran, a .pth file in
# site-packages or a sitecustomize.py that prints, would otherwise be read as the first frame. hashcat
# scans for this word, reports whatever came before it as the interpreter's own output, and starts the
# protocol after it.

MAGIC = b"HCPY"

FRAME_HELLO  = 1
FRAME_ERROR  = 2
FRAME_RESULT = 3
FRAME_READY  = 4
FRAME_INIT   = 10
FRAME_BATCH  = 11

# the limits of generic_io_tmp_t on the hashcat side

OUT_LEN_MAX = 256
OUT_CNT_MAX = 32

U32  = struct.Struct("=I")
HEAD = struct.Struct("=II")


def read_exact(stream, size: int) -> bytes:
  buf = bytearray()

  while len(buf) < size:
    chunk = stream.read(size - len(buf))

    if len(chunk) == 0:
      return b""

    buf += chunk

  return bytes(buf)


def read_frame(stream):
  head = read_exact(stream, HEAD.size)

  if len(head) == 0:
    return None, None

  ftype, size = HEAD.unpack(head)

  payload = read_exact(stream, size) if size > 0 else b""

  if len(payload) != size:
    return None, None

  return ftype, payload


# hashcat closes the pipe to end the run, and a worker that was in the middle of a batch then has a
# result nobody will read. That is an ordinary end of run, not a fault, so it leaves quietly instead of
# printing a BrokenPipeError for every unit.

def write_frame(stream, ftype: int, payload: bytes) -> None:
  try:
    stream.write(HEAD.pack(ftype, len(payload)))
    stream.write(payload)
    stream.flush()
  except (BrokenPipeError, OSError):
    os._exit(0)


def pack_str(value) -> bytes:
  data = value.encode("utf-8") if isinstance(value, str) else bytes(value)

  return U32.pack(len(data)) + data


def unpack_blob(payload: bytes, pos: int):
  size = U32.unpack_from(payload, pos)[0]

  pos += 4

  return payload[pos:pos + size], pos + size


def no_esalts(esalts_buf: bytes) -> list:
  return []


# There is one salt per distinct salt and one esalt per hash, so the two lists are only the same length
# when every salt holds exactly one hash. A salt names its first hash with digests_offset, and that is
# the esalt carrying its own salt value; every other hash in the group carries the same one.
#
# Pairing them by position instead loses every salt after the first that holds more than one hash. On a
# list of 10 hashes over 5 salts, 2 hashes each, it cracked 2 of the 10 and said nothing.

def merge_esalts(salts: list, esalts: list) -> None:
  if len(esalts) == 0:
    return

  for salt in salts:
    pos = salt["digests_offset"]

    if pos >= len(esalts):
      raise IndexError("salt names hash %d but hashcat sent %d esalt(s)" % (pos, len(esalts)))

    salt["esalt"] = esalts[pos]


def no_hook(ctx: dict) -> None:
  return


def fail(out, message: str) -> None:
  write_frame(out, FRAME_ERROR, message.encode("utf-8", "replace"))

  sys.exit(1)


def load_plugin(path: str):
  if os.path.isfile(path) == False:
    raise FileNotFoundError("%s: no such file" % path)

  name = os.path.splitext(os.path.basename(path))[0]

  spec = importlib.util.spec_from_file_location(name, path)

  if spec is None:
    raise ImportError("%s is not a Python source file" % path)

  module = importlib.util.module_from_spec(spec)

  sys.modules[name] = module

  spec.loader.exec_module(module)

  return module


def parse_init(payload: bytes, plugin, hcshared) -> dict:
  pos = 0

  salt_per_pw = U32.unpack_from(payload, pos)[0]

  pos += 4

  salt_t_size = U32.unpack_from(payload, pos)[0]

  pos += 4

  esalt_size = U32.unpack_from(payload, pos)[0]

  pos += 4

  if salt_t_size != hcshared.SALT_T.size:
    raise ValueError("hashcat's salt_t is %d bytes and hcshared.SALT_T is %d. The Python folder does not belong to this build." % (salt_t_size, hcshared.SALT_T.size))

  blobs = []

  for i in range(4):
    blob, pos = unpack_blob(payload, pos)

    blobs.append(blob)

  params = []

  for i in range(4):
    blob, pos = unpack_blob(payload, pos)

    params.append(blob.decode("utf-8", "replace") if len(blob) > 0 else None)

  salts_buf, esalts_buf, st_salts_buf, st_esalts_buf = blobs

  extract_esalts = getattr(plugin, "extract_esalts", no_esalts)

  salts    = hcshared.extract_salts(salts_buf)
  st_salts = hcshared.extract_salts(st_salts_buf)

  merge_esalts(salts, extract_esalts(esalts_buf))
  merge_esalts(st_salts, extract_esalts(st_esalts_buf))

  ctx = {
    "salts":             salts,
    "st_salts":          st_salts,
    "salt_per_pw":       salt_per_pw != 0,
    "esalt_size":        esalt_size,
    "bridge_parameter1": params[0],
    "bridge_parameter2": params[1],
    "bridge_parameter3": params[2],
    "bridge_parameter4": params[3],
  }

  getattr(plugin, "init", no_hook)(ctx)

  return ctx


# One value is a str or anything with a buffer: bytes, bytearray, memoryview, array. Anything else is
# treated as a sequence of such values. The distinction has to be made on the buffer protocol rather
# than on bytes alone, because bytes (bytearray (32)) is the digest and bytes (32) is 32 zero bytes, so
# reading a bytearray as a sequence of ints would hand hashcat well formed garbage and never say so.

def encode_one(value, pw: bytes) -> bytes:
  if isinstance(value, str):
    return value.encode("utf-8")

  try:
    return bytes(memoryview(value))
  except TypeError:
    raise TypeError("calc_hash() returned %s for %r, which is neither text nor bytes" % (type(value).__name__, pw))


def encode_result(value, pw: bytes) -> bytes:
  if isinstance(value, (str, bytes, bytearray, memoryview)):
    outs = [value]
  else:
    outs = list(value)

  if len(outs) > OUT_CNT_MAX:
    raise ValueError("calc_hash() returned %d values for %r, at most %d fit" % (len(outs), pw, OUT_CNT_MAX))

  parts = [U32.pack(len(outs))]

  for out in outs:
    data = encode_one(out, pw)

    if len(data) > OUT_LEN_MAX:
      raise ValueError("calc_hash() returned %d bytes for %r, at most %d fit" % (len(data), pw, OUT_LEN_MAX))

    parts.append(U32.pack(len(data)))
    parts.append(data)

  return b"".join(parts)


# A batch names the salt it starts at, whether it is the self test, and its candidate count. Every
# candidate uses that one salt, except under an association attack, where each one adds its own
# position to it.

def run_batch(payload: bytes, ctx: dict, calc_hash) -> bytes:
  salt_pos, is_selftest, count = struct.unpack_from("=III", payload, 0)

  pos = 12

  table  = ctx["st_salts"] if is_selftest != 0 else ctx["salts"]
  stride = 1 if (ctx["salt_per_pw"] and is_selftest == 0) else 0

  view = memoryview(payload)

  parts = [U32.pack(count)]

  for i in range(count):
    size = U32.unpack_from(payload, pos)[0]

    pos += 4

    if (pos + size) > len(payload):
      raise ValueError("candidate %d says %d bytes and the batch has %d left" % (i, size, len(payload) - pos))

    pw = bytes(view[pos:pos + size])

    pos += size

    parts.append(encode_result(calc_hash(pw, table[salt_pos + (i * stride)]), pw))

  return b"".join(parts)


def main() -> None:
  # Ctrl-C reaches every process in the terminal's group. hashcat decides when the run ends and closes
  # the pipe then, so a worker leaves the signal to hashcat rather than dying in the middle of a batch.

  signal.signal(signal.SIGINT, signal.SIG_IGN)

  # The protocol owns file descriptor 1. A plugin that prints would otherwise write into the frames, so
  # the protocol keeps a private copy and descriptor 1 is pointed at standard error.

  outfd = os.dup(sys.stdout.fileno())

  if sys.platform == "win32":
    import msvcrt

    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(outfd, os.O_BINARY)

  out = os.fdopen(outfd, "wb")

  # A Windows hashcat started without a console has no standard error to give the worker, and then
  # sys.stderr is None. Descriptor 1 is the protocol's, so the fallback is to throw the output away
  # rather than to write it into the frames.

  if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

  os.dup2(sys.stderr.fileno(), sys.stdout.fileno())

  sys.stdout = sys.stderr

  inp = sys.stdin.buffer

  # Before anything that can fail, because hashcat skips to it and an ERROR frame written ahead of it
  # would be skipped past along with the traceback it carries.

  out.write(MAGIC)
  out.flush()

  if len(sys.argv) != 2:
    fail(out, "usage: hcworker.py <plugin.py>")

  # The plugin can import hcshared from here, and its own modules from beside itself.

  sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

  plugin_path = os.path.abspath(sys.argv[1])

  sys.path.insert(1, os.path.dirname(plugin_path))

  try:
    import hcshared

    plugin = load_plugin(plugin_path)
  except BaseException:
    fail(out, traceback.format_exc())

  calc_hash = getattr(plugin, "calc_hash", None)

  if calc_hash is None:
    fail(out, "%s: no function calc_hash() found" % plugin_path)

  st_hash = getattr(plugin, "ST_HASH", "")
  st_pass = getattr(plugin, "ST_PASS", "")

  gil     = getattr(sys, "_is_gil_enabled", lambda: True)()
  version = "%s%s" % (sys.version.split()[0], "" if gil == True else " free-threading")

  write_frame(out, FRAME_HELLO, U32.pack(PROTOCOL_VERSION) + U32.pack(hcshared.SALT_T.size) + pack_str(version) + pack_str(st_hash) + pack_str(st_pass))

  ctx = None

  while True:
    ftype, payload = read_frame(inp)

    if ftype is None:
      break

    try:
      if ftype == FRAME_INIT:
        ctx = parse_init(payload, plugin, hcshared)

        write_frame(out, FRAME_READY, b"")
      elif ftype == FRAME_BATCH:
        if ctx is None:
          fail(out, "BATCH received before INIT")

        write_frame(out, FRAME_RESULT, run_batch(payload, ctx, calc_hash))
      else:
        fail(out, "unknown frame type %d" % ftype)
    except SystemExit:
      raise
    except BaseException:
      fail(out, traceback.format_exc())

  if ctx is None:
    return

  getattr(plugin, "term", no_hook)(ctx)


if __name__ == "__main__":
  main()

import struct
import sys
from pathlib import Path
import hcsp
import pickle

# Global defs
script_dir = Path(__file__).resolve().parent
example_ctx = "example.ctx"
# Extract a blob that is a list of salt_t entries and convert it to a list of dictionaries
# The salt_t is a fixed data-type so we can handle it here
def extract_salts(salts_buf) -> list:
  salts=[]
  for salt_buf, salt_buf_pc, salt_len, salt_len_pc, salt_iter, salt_iter2, salt_dimy, salt_sign, salt_repeats, orig_pos, digests_cnt, digests_done, digests_offset, scrypt_N, scrypt_r, scrypt_p in struct.iter_unpack("256s 256s I I I I I 8s I I I I I I I I", salts_buf):
    salt_buf = salt_buf[0:salt_len]
    salt_buf_pc = salt_buf_pc[0:salt_len_pc]
    salts.append({ "salt_buf":      salt_buf,     \
                   "salt_buf_pc":   salt_buf_pc,  \
                   "salt_iter":     salt_iter,    \
                   "salt_iter2":    salt_iter2,   \
                   "salt_dimy":     salt_dimy,    \
                   "salt_sign":     salt_sign,    \
                   "salt_repeats":  salt_repeats, \
                   "orig_pos":      orig_pos,     \
                   "digests_cnt":   digests_cnt,  \
                   "digests_done":  digests_done, \
                   "scrypt_N":      scrypt_N,     \
                   "scrypt_r":      scrypt_r,     \
                   "scrypt_p":      scrypt_p,     \
                   "esalt":         None })
  return salts

def get_salt_buf(salt: dict) -> bytes:
  return salt["esalt"]["salt_buf"]

def get_salt_buf_pc(salt: dict) -> bytes:
  return salt["esalt"]["salt_buf_pc"]

def get_salt_iter(salt: dict) -> int:
  return salt["esalt"]["salt_iter"]

def get_salt_iter2(salt: dict) -> int:
  return salt["esalt"]["salt_iter2"]

def get_salt_sign(salt: dict) -> bytes:
  return salt["esalt"]["salt_sign"]

def get_salt_repeats(salt: dict) -> int:
  return salt["esalt"]["salt_repeats"]

def get_orig_pos(salt: dict) -> int:
  return salt["esalt"]["orig_pos"]

def get_digests_cnt(salt: dict) -> int:
  return salt["esalt"]["digests_cnt"]

def get_digests_done(salt: dict) -> int:
  return salt["esalt"]["digests_done"]

def get_digests_offset(salt: dict) -> int:
  return salt["esalt"]["digests_offset"]

def get_scrypt_N(salt: dict) -> int:
  return salt["esalt"]["scrypt_N"]

def get_scrypt_r(salt: dict) -> int:
  return salt["esalt"]["scrypt_r"]

def _worker_batch(passwords, salt_id, is_selftest, user_fn, salts, st_salts, salt_per_pw=False):
    # salt_id is one salt for the whole batch, except under salt_per_pw, where it is the salt the
    # batch starts at and each candidate adds its own position.
    table = st_salts if is_selftest else salts
    stride = 1 if (salt_per_pw and not is_selftest) else 0
    hashes = []
    for i, pw in enumerate(passwords):
        try:
            hash=user_fn(pw, table[salt_id + (i * stride)])
            hashes.append(hash)
        except Exception as e:
            print(e, file=sys.stderr)
            hashes.append("invalid-password")
    return hashes

def dump_hashcat_ctx(ctx, source):
  if source == '__main__':
    exit(f"You are trying to dump hashcat ctx by calling the python script directly. This will not work."
         f"\n To dump the ctx run 'hashcat -m 73000 -b' or 'hashcat -m 72000 -b'"
         f"\n To debug your python bridge, comment the call to hcshared.dump_hashcat_ctx() in your script.")

  print("\nDumping hashcat ctx...")
  with open(script_dir.joinpath("hashcat.ctx"), "wb") as f:
    pickle.dump(ctx, f)
    print(f"Dumped hashcat ctx to: {script_dir.joinpath('hashcat.ctx')}\n")
  hcsp.term(ctx)

def load_ctx(selftest_hash, hashcat_ctx=script_dir.joinpath("hashcat.ctx")):
  # Empty ctx for unsalted hashes:
  ctx = {
      "salts_buf": bytes(572),
      "esalts_buf": bytes(2056),
      "st_salts_buf": bytes(572),
      "st_esalts_buf": bytes(2056),
      "parallelism": 4
    }
  if selftest_hash == "33522b0fd9812aa68586f66dba7c17a8ce64344137f9c7d8b11f32a6921c22de*9348746780603343":
    print(f"You are running the example with example selftest-hash, so {example_ctx} is loaded.", file=sys.stderr)
    with open(script_dir.joinpath(example_ctx), "rb") as f:
      return pickle.load(f)

  if hashcat_ctx.exists():
    with open(hashcat_ctx, "rb") as f:
      return pickle.load(f)
  else:
    print(f"{hashcat_ctx.name} not found, using empty ctx, assuming your hashes are unsalted.", file=sys.stderr)
  return ctx

def add_hashcat_path_to_environment():
  files = [script_dir/"hcmp.py", script_dir/"hcshared.py" ]
  missing = [f for f in files if not f.exists()]
  for m in missing:
      print(f"Cant find {m} in the same directory, so debugging of those impossible", file=sys.stderr)
  sys.path.insert(0, script_dir)

import struct
import sys

# Extract a blob that is a list of salt_t entries and convert it to a list of dictionaries
# The salt_t is a fixed data-type so we can handle it here

def extract_salts(salts_buf) -> list:
  salts=[]
  for salt_buf, salt_buf_pc, salt_len, salt_len_pc, salt_iter, salt_iter2, salt_sign, salt_repeats, orig_pos, digests_cnt, digests_done, digests_offset, scrypt_N, scrypt_r, scrypt_p in struct.iter_unpack("256s 256s I I I I 8s I I I I I I I I", salts_buf):
    salt_buf = salt_buf[0:salt_len]
    salt_buf_pc = salt_buf_pc[0:salt_len_pc]
    salts.append({ "salt_buf":      salt_buf,     \
                   "salt_buf_pc":   salt_buf_pc,  \
                   "salt_iter":     salt_iter,    \
                   "salt_iter2":    salt_iter2,   \
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

def _worker_batch(passwords, salt_id, is_selftest, user_fn, salts, st_salts):
    salt = st_salts[salt_id] if is_selftest else salts[salt_id]
    hashes = []
    for pw in passwords:
        try:
            hash=user_fn(pw, salt)
            hashes.append(hash)
        except Exception as e:
            print(e, file=sys.stderr)
            hashes.append("invalid-password")
    return hashes

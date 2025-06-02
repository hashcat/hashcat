import sys
import struct
import hashlib
import hcshared
import hcmp

ST_HASH = "33522b0fd9812aa68586f66dba7c17a8ce64344137f9c7d8b11f32a6921c22de*9348746780603343"
ST_PASS = "hashcat"

# In theory, you only have to implement this function...

def calc_hash(password: bytes, salt: dict) -> str:
  salt_buf = hcshared.get_salt_buf(salt)
  hash = hashlib.sha256(salt_buf + password)
  for i in range(10000):
    hash = hashlib.sha256(hash.digest())
  return hash.hexdigest()

# ...except when using an esalt. The esalt void* structure is both dynamic and specific to a hash mode.
# If you use an esalt, you must convert its contents into Python datatypes.
# If you don't use esalt, just return []
# For this example hash-mode, we kept it very general and pushed all salt data in a generic format of generic sizes
# As such, it has to go into esalt

def extract_esalts(esalts_buf):
  esalts=[]
  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("65536s I 65536s I", esalts_buf):
    hash_buf = hash_buf[0:hash_len]
    salt_buf = salt_buf[0:salt_len]
    esalts.append({ "hash_buf": hash_buf, "salt_buf": salt_buf })
  return esalts

# From here you really can leave things as they are
# The init function is good for converting the hashcat data type because it is only called once

def kernel_loop(ctx,passwords,salt_id,is_selftest):
  return hcmp.handle_queue(ctx,passwords,salt_id,is_selftest)

def init(ctx):
  hcmp.init(ctx,calc_hash,extract_esalts)

def term(ctx):
  hcmp.term(ctx)

# This code is only intended to enable debugging via a standalone Python interpreter.
# It makes development easier as you don't have to use a hashcat to test your changes.
# Read passwords from stdin

if __name__ == '__main__':
  ctx = { 
    "salts_buf": bytes(568), 
    "esalts_buf": bytes(131080), 
    "st_salts_buf": bytes(568), 
    "st_esalts_buf": bytes(131080) 
  }
  init(ctx)
  hashcat_passwords = 256
  passwords = []
  for line in sys.stdin:
    passwords.append(bytes(line.rstrip(), 'utf-8'))
    if(len(passwords) == hashcat_passwords):
      hashes = kernel_loop(ctx,passwords,0,False)
      passwords.clear()
  hashes = kernel_loop(ctx,passwords,0,False) ## remaining entries
  if(len(hashes)): print(hashes[-1])
  term(ctx)

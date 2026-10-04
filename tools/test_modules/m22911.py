#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

# RSA/DSA/EC/OpenSSH private key, PEM with DEK-Info AES-128 style header. cid 0 is 3DES (EDE3) CBC,
# key derived by the OpenSSL EVP_BytesToKey MD5 scheme, iv is the salt.

DATA_DEFAULT = (
  "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b7a2"
  "e4c254c8174219e60d9cce96737a906797b8edb86af8f055f60db7bd298b0d31d7ce97ebeae393d5"
  "0e6da5215b58dcd72f4d3cac9e79b6ccaed7da47d2bd04f6a767f5ab7dc0f58beb6298c1e2358ed6"
  "d3ef441f2326ac5db0027e08ae6c7724ff9a2a220a07e97319b6eff5cd653c7ab8b6ea9f9e89a40a"
  "b856f036acfd39b1e5926964a024de35052de6d3423fe763569f48869c834750b28f09cecdddb54a"
  "5526a2c5159d22d24606a2af6c6f47a5d9c04c454896192b8e7b82cf6f6934a23d3495059cb7e43b"
  "98a20bd5b5782e15d93c8b289838c0a1df82ee429f0708d97aa40d6e75ec57ff12a2714871f241a8"
  "6f6d8d3472b084aeb748da33e2d50203010001028201004afab8dadc1122e5fb7b225dbf4051005f"
  "4bdcf84620019589541ff633ea89b6dbf958fb62ae9226bfeac34c639b3e18077bd935792ba63d5e"
  "352ec2b5be93be57f37a21097f2f06857bceed601ff2041a417f2177b81afb246fd079040af96512"
  "34ca24a1456ac11641c7e319114cff23f59bcc1bfa769a0e9fcdeab98429973e10caf303f2bcb065"
  "f22c1cc259556de8377431237da7082cf03ce8da9530be398022f0171d468d92fcabbe776a5e9cf2"
  "045642868406fd03ab735a70bfec3a951bb3c7a1de0fb3ff63cef23897e4fc3f9c5edf62fd45d058"
  "fedc7d2fb22ec928984a061053a7138ce0417b5512579a92be0775104c0bc911f68a5e8ede298102"
  "818100e4e17e2c752dbf1ad1025a074dc5f9c3c5989d23c84594313373d3e4ed0c0ddd74429ab026"
  "535c5e77549d888835bc94f069ebc5e77fdbd2ddf4c8be6cf777799a6d8d18e2b8cecfc13ab26df8"
  "b71ca3d94c2193c294042fb1025fdab38ba7aaeafebd8dd1f9d78ee67100693e99255dad6b964ebf"
  "b7401a03b67d412fabb33502818100cd65067097e307643df1fc8214db1dd7d09342ef01417a2620"
  "adad87352a58b8fcf07521289da3851623d8d045935fab7ecccc52ba0b86adcb92da76255e00289b"
  "af9aacd936201861b0021249f4ab5e6020db823af7171aef0bbbd02dc94d2489fc0b68500bd1b7d2"
  "81ed69fe4a44384161fe906e49bc91e0362b446ec2c521028180497662d40c2c49b966ba758100a2"
  "799f2f8de369f7bef568b1560cfdde63cf13745c685fff7d2419a1fd83aeade1698cf87956d6a78e"
  "2f55482e683c4ea7432ec1b545e365e9e15f676ada98578b166334bcadce4a56cddd2cd85141d5fd"
  "0e2cdace36b30d613ea1bc2f2aed9cccf4e4536443d334cfb180680eabb73f80c1bd0281803f30fc"
  "b93951a4dd875d62e5968b0f746d7c51147d5b6abc3e4390e6cf4997005af993dfbec23923e1fae7"
  "62b47531f2ee510defc9c3700d1a5bb510b2506856160801db79fc78056850a16285145c80edac4e"
  "3c93ed9f532f067a2303633273b26c340a44ce4e1873107c3da6f9ac616e643ad0aecdcad14a9cff"
  "d4cf0ae76102818100b82528a3dfc595cf9c6a025998491e3b4849c71aa8d1222ddb14af7f82fbe5"
  "169ec3ba18ec28d5a9501e95bc9da72cea99e4cdfdf898f40bec6b28f838243d2f39d7226e0873ed"
  "ee752bcae07639a4bd0eb31be1718c456391630b83ad0e9bf3fa18a645007e64fe59af467ea021f9"
  "e9a0dd759b21cd0b93333a73116abcaa2a"
)

CID = 0
BS = 8


def module_constraints():
  return [[0, 128], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def generate_key(word, salt_bin):
  salt8 = salt_bin[:8]

  out = hashlib.md5(word + salt8).digest()
  out += hashlib.md5(out + word + salt8).digest()

  return out[:24]


def _ede3_cbc_encrypt(key, iv, data):
  e1 = DES.new(key[0:8], DES.MODE_ECB)
  d2 = DES.new(key[8:16], DES.MODE_ECB)
  e3 = DES.new(key[16:24], DES.MODE_ECB)

  out = b""
  prev = iv

  for i in range(0, len(data), BS):
    block = bytes(a ^ b for a, b in zip(data[i:i + BS], prev))
    enc = e3.encrypt(d2.decrypt(e1.encrypt(block)))
    out += enc
    prev = enc

  return out


def _ede3_cbc_decrypt(key, iv, data):
  d1 = DES.new(key[0:8], DES.MODE_ECB)
  e2 = DES.new(key[8:16], DES.MODE_ECB)
  d3 = DES.new(key[16:24], DES.MODE_ECB)

  out = b""
  prev = iv

  for i in range(0, len(data), BS):
    block = data[i:i + BS]
    dec = d1.decrypt(e2.encrypt(d3.decrypt(block)))
    out += bytes(a ^ b for a, b in zip(dec, prev))
    prev = block

  return out


def _std_unpad(buf):
  # Crypt::CBC 'standard' unpad removes last-byte-count bytes from the final block, no validation.
  pad_len = buf[-1]
  keep = BS - pad_len
  last = buf[-BS:]

  if keep >= 0:
    new_last = last[:keep]
  else:
    n = BS + keep
    new_last = last[:n] if n > 0 else b""

  return buf[:-BS] + new_last


def module_generate_hash(word, salt, cid=None, data=None):
  if cid is None:
    cid = CID

  salt_bin = bytes.fromhex(salt)
  key = generate_key(word, salt_bin)

  if data is not None:
    data_bin = bytes.fromhex(data)
    dec_bin = _std_unpad(_ede3_cbc_decrypt(key, salt_bin, data_bin))

    if len(dec_bin) < len(data_bin) and dec_bin[0:1] == b"\x30":
      data_bin = dec_bin
  else:
    data_bin = bytes.fromhex(DATA_DEFAULT)

  enc_bin = _ede3_cbc_encrypt(key, salt_bin, pad(data_bin, BS))

  return "$sshng$%d$%d$%s$%d$%s" % (cid, len(salt_bin), salt_bin.hex(), len(enc_bin), enc_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith("$sshng$"):
    return None

  fields = hash_in.split("$")

  if len(fields) < 7:
    return None

  signature, cid, salt, data = fields[1], fields[2], fields[4], fields[6]

  if signature != "sshng":
    return None

  try:
    cid = int(cid)
  except ValueError:
    return None

  if cid != CID:
    return None

  return (module_generate_hash(word, salt, cid, data), word)

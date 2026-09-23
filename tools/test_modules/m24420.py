#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad

from lib.test_helpers import random_bytes, random_number

# PKCS8 private key, PBKDF2-HMAC-SHA256 key derivation ($PEM$2). cid selects the CBC cipher and key
# length: 1 is 3DES-EDE (8 byte IV), 2/3/4 are AES-128/192/256 (16 byte IV), all with PKCS7
# padding. Since perl has no ASN.1 parser, a decrypt is accepted when the plaintext shrank (padding
# was stripped) and starts with 0x30, the DER SEQUENCE tag.

PKCS8_DATA = (
  "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100"
  "b7a2e4c254c8174219e60d9cce96737a906797b8edb86af8f055f60db7bd298b0d31d7ce97eb"
  "eae393d50e6da5215b58dcd72f4d3cac9e79b6ccaed7da47d2bd04f6a767f5ab7dc0f58beb62"
  "98c1e2358ed6d3ef441f2326ac5db0027e08ae6c7724ff9a2a220a07e97319b6eff5cd653c7a"
  "b8b6ea9f9e89a40ab856f036acfd39b1e5926964a024de35052de6d3423fe763569f48869c83"
  "4750b28f09cecdddb54a5526a2c5159d22d24606a2af6c6f47a5d9c04c454896192b8e7b82cf"
  "6f6934a23d3495059cb7e43b98a20bd5b5782e15d93c8b289838c0a1df82ee429f0708d97aa4"
  "0d6e75ec57ff12a2714871f241a86f6d8d3472b084aeb748da33e2d50203010001028201004a"
  "fab8dadc1122e5fb7b225dbf4051005f4bdcf84620019589541ff633ea89b6dbf958fb62ae92"
  "26bfeac34c639b3e18077bd935792ba63d5e352ec2b5be93be57f37a21097f2f06857bceed60"
  "1ff2041a417f2177b81afb246fd079040af9651234ca24a1456ac11641c7e319114cff23f59b"
  "cc1bfa769a0e9fcdeab98429973e10caf303f2bcb065f22c1cc259556de8377431237da7082c"
  "f03ce8da9530be398022f0171d468d92fcabbe776a5e9cf2045642868406fd03ab735a70bfec"
  "3a951bb3c7a1de0fb3ff63cef23897e4fc3f9c5edf62fd45d058fedc7d2fb22ec928984a0610"
  "53a7138ce0417b5512579a92be0775104c0bc911f68a5e8ede298102818100e4e17e2c752dbf"
  "1ad1025a074dc5f9c3c5989d23c84594313373d3e4ed0c0ddd74429ab026535c5e77549d8888"
  "35bc94f069ebc5e77fdbd2ddf4c8be6cf777799a6d8d18e2b8cecfc13ab26df8b71ca3d94c21"
  "93c294042fb1025fdab38ba7aaeafebd8dd1f9d78ee67100693e99255dad6b964ebfb7401a03"
  "b67d412fabb33502818100cd65067097e307643df1fc8214db1dd7d09342ef01417a2620adad"
  "87352a58b8fcf07521289da3851623d8d045935fab7ecccc52ba0b86adcb92da76255e00289b"
  "af9aacd936201861b0021249f4ab5e6020db823af7171aef0bbbd02dc94d2489fc0b68500bd1"
  "b7d281ed69fe4a44384161fe906e49bc91e0362b446ec2c521028180497662d40c2c49b966ba"
  "758100a2799f2f8de369f7bef568b1560cfdde63cf13745c685fff7d2419a1fd83aeade1698c"
  "f87956d6a78e2f55482e683c4ea7432ec1b545e365e9e15f676ada98578b166334bcadce4a56"
  "cddd2cd85141d5fd0e2cdace36b30d613ea1bc2f2aed9cccf4e4536443d334cfb180680eabb7"
  "3f80c1bd0281803f30fcb93951a4dd875d62e5968b0f746d7c51147d5b6abc3e4390e6cf4997"
  "005af993dfbec23923e1fae762b47531f2ee510defc9c3700d1a5bb510b2506856160801db79"
  "fc78056850a16285145c80edac4e3c93ed9f532f067a2303633273b26c340a44ce4e1873107c"
  "3da6f9ac616e643ad0aecdcad14a9cffd4cf0ae76102818100b82528a3dfc595cf9c6a025998"
  "491e3b4849c71aa8d1222ddb14af7f82fbe5169ec3ba18ec28d5a9501e95bc9da72cea99e4cd"
  "fdf898f40bec6b28f838243d2f39d7226e0873edee752bcae07639a4bd0eb31be1718c456391"
  "630b83ad0e9bf3fa18a645007e64fe59af467ea021f9e9a0dd759b21cd0b93333a73116abcaa"
  "2a"
)

HID       = "2"
KEY_LEN   = {1: 24, 2: 16, 3: 24, 4: 32}


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def _cipher(cid, key, iv):
  if cid == 1:
    return DES3.new(key, DES3.MODE_CBC, iv), 8

  return AES.new(key, AES.MODE_CBC, iv), 16


def _pbkdf2(word, salt_bin, iterations, key_len):
  return hashlib.pbkdf2_hmac("sha256", word, salt_bin, iterations, key_len)


def module_generate_hash(word, salt, cid=None, iterations=None, iv=None, data=None):
  cid = random_number(1, 4) if cid is None else int(cid)
  iterations = 2048 if iterations is None else int(iterations)

  key_len = KEY_LEN[cid]

  salt_bin = bytes.fromhex(salt)

  key = _pbkdf2(word, salt_bin, iterations, key_len)

  if data is not None:
    iv_bin   = bytes.fromhex(iv)
    data_bin = bytes.fromhex(data)

    block_size = 8 if cid == 1 else 16

    cipher, _ = _cipher(cid, key, iv_bin)

    try:
      dec_bin = unpad(cipher.decrypt(data_bin), block_size)
    except ValueError:
      dec_bin = None

    if dec_bin is not None and len(dec_bin) < len(data_bin) and dec_bin[:1] == b"\x30":
      data_bin = dec_bin
  else:
    iv_bin = random_bytes(8) if cid == 1 else random_bytes(16)

    data_bin = bytes.fromhex(PKCS8_DATA)

  block_size = 8 if cid == 1 else 16

  cipher, _ = _cipher(cid, key, iv_bin)

  enc_bin = cipher.encrypt(pad(data_bin, block_size))

  return "$PEM$%s$%d$%s$%d$%s$%d$%s" % (HID, cid, salt_bin.hex(), iterations, iv_bin.hex(),
                                        len(enc_bin), enc_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:6] != "$PEM$" + HID:
    return None

  fields = hash_in.split("$")

  if len(fields) != 9:
    return None

  signature, hid, cid, salt, iterations, iv, _, data = fields[1:]

  if signature != "PEM" or hid != HID:
    return None

  try:
    cid = int(cid)
  except ValueError:
    return None

  if cid not in KEY_LEN:
    return None

  return (module_generate_hash(word, salt, cid, iterations, iv, data), word)

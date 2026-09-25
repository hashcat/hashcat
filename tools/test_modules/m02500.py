#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac
import struct

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_bytes

# WPA-EAPOL-PBKDF2, HCCAPX output. The PMK is PBKDF2-HMAC-SHA1 (4096 iterations) of the passphrase
# salted by the ESSID, the PTK is a PRF over the MACs and nonces, and the MIC follows the key
# version (1/2/3 -> HMAC-MD5, HMAC-SHA1, AES-CMAC). The .pm leaves verify unimplemented because it
# predates a stable output format; every field is present in the HCCAPX record, so verify here
# parses it back and re-derives, which is what the python runner's round trip check needs.


def module_constraints():
  return [[8, 63], [0, 32], [-1, -1], [-1, -1], [-1, -1]]


def _gen_random_wpa_eapol(keyver, snonce):
  ret = b""

  ret += struct.pack("B", 1)  # version: 802.1X-2001
  ret += struct.pack("B", 3)  # type: key information

  length = 119 if keyver == 1 else 117
  ret += struct.pack(">H", length)

  descriptor_type = 254 if keyver == 1 else 1
  ret += struct.pack("B", descriptor_type)

  key_info = 0
  key_info |= 1 << 8  # key MIC
  key_info |= 1 << 3  # pairwise key

  if keyver == 1:
    key_info |= 1  # RC4 cipher, HMAC-MD5
  else:
    key_info |= 2  # AES cipher, HMAC-SHA1

  ret += struct.pack(">H", key_info)

  key_length = 32 if keyver == 1 else 0
  ret += struct.pack(">H", key_length)

  ret += struct.pack(">Q", 1)  # replay counter

  ret += snonce
  ret += b"\x00" * 16  # key IV
  ret += b"\x00" * 8   # key RSC
  ret += b"\x00" * 8   # key ID
  ret += b"\x00" * 16  # key MIC

  key_data_len = 24 if keyver == 1 else 22
  ret += struct.pack(">H", key_data_len)

  if keyver == 1:
    # WPA info, vendor specific tag
    key_data = b""
    key_data += struct.pack("B", 221)  # vendor specific tag
    key_data += struct.pack("B", 22)   # tag length
    key_data += bytes.fromhex("0050f2")  # microsoft OUI
    key_data += struct.pack("B", 1)    # WPA Information Element
    key_data += struct.pack("<H", 1)   # WPA version
    key_data += bytes.fromhex("0050f2")
    key_data += struct.pack("B", 2)    # multicast TKIP
    key_data += struct.pack("<H", 1)   # unicast count
    key_data += bytes.fromhex("0050f2")
    key_data += struct.pack("B", 2)    # unicast TKIP
    key_data += struct.pack("<H", 1)   # AKM count
    key_data += bytes.fromhex("0050f2")
    key_data += struct.pack("B", 2)    # AKM PSK
  else:
    # RSN info
    key_data = b""
    key_data += struct.pack("B", 48)   # RSN info tag
    key_data += struct.pack("B", 20)   # tag length
    key_data += struct.pack("<H", 1)   # RSN version
    key_data += bytes.fromhex("000fac")
    key_data += struct.pack("B", 4)    # group cipher AES (CCM)
    key_data += struct.pack("<H", 1)   # pairwise count
    key_data += bytes.fromhex("000fac")
    key_data += struct.pack("B", 4)    # pairwise AES (CCM)
    key_data += struct.pack("<H", 1)   # AKM count
    key_data += bytes.fromhex("000fac")
    key_data += struct.pack("B", 2)    # AKM PSK
    key_data += bytes.fromhex("0000")  # RSN capabilities

  ret += key_data

  return ret


def _wpa_prf_512(keyver, pmk, stmac, bssid, snonce, anonce):
  data = b"Pairwise key expansion"

  if keyver in (1, 2):
    data += b"\x00"

  # Min(AA, SPA) || Max(AA, SPA) over the 6 byte MACs
  if stmac < bssid:
    data += stmac + bssid
  else:
    data += bssid + stmac

  # Min(ANonce, SNonce) || Max(ANonce, SNonce) over the 32 byte nonces
  if snonce < anonce:
    data += snonce + anonce
  else:
    data += anonce + snonce

  if keyver in (1, 2):
    data += b"\x00"
    prf_buf = hmac.new(pmk, data, hashlib.sha1).digest()
  else:
    data3 = b"\x01\x00" + data + b"\x80\x01"
    prf_buf = hmac.new(pmk, data3, hashlib.sha256).digest()

  return prf_buf[:16]


def _mic(keyver, ptk, eapol):
  if keyver == 1:
    mic = hmac.new(ptk, eapol, hashlib.md5).digest()
  elif keyver == 2:
    mic = hmac.new(ptk, eapol, hashlib.sha1).digest()
  else:
    c = CMAC.new(ptk, ciphermod=AES)
    c.update(eapol)
    mic = c.digest()

  return mic[:16]


def module_generate_hash(word, salt, iterations=None, bssid=None, stmac=None,
                         snonce=None, anonce=None, keyver=None, eapol=None):
  essid = salt.encode("latin-1") if isinstance(salt, str) else salt

  if bssid is None:
    bssid  = random_bytes(6)
    stmac  = random_bytes(6)
    snonce = random_bytes(32)
    anonce = random_bytes(32)
    keyver = random_number(1, 3)
    eapol  = _gen_random_wpa_eapol(keyver, snonce)

  eapol_len = len(eapol)

  pmk = hashlib.pbkdf2_hmac("sha1", word, essid, 4096, 32)

  ptk = _wpa_prf_512(keyver, pmk, stmac, bssid, snonce, anonce)

  mic = _mic(keyver, ptk, eapol)

  hash_buf  = b"HCPX"
  hash_buf += struct.pack("<L", 4)  # HCCAPX version
  hash_buf += struct.pack("B", 0)   # authenticated

  essid_len = len(essid)
  hash_buf += struct.pack("B", essid_len)
  hash_buf += essid
  hash_buf += b"\x00" * (32 - essid_len)

  hash_buf += struct.pack("B", keyver)
  hash_buf += mic
  hash_buf += bssid   # access point MAC
  hash_buf += snonce  # access point nonce
  hash_buf += stmac   # client MAC
  hash_buf += anonce  # client nonce

  hash_buf += struct.pack("<H", eapol_len)
  hash_buf += eapol
  hash_buf += b"\x00" * (256 - eapol_len)

  return base64.b64encode(hash_buf).decode("ascii")


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx]
  word    = line[idx + 1:]

  try:
    buf = base64.b64decode(hash_in, validate=True)
  except Exception:
    return None

  if len(buf) != 393 or buf[0:4] != b"HCPX":
    return None

  essid_len = buf[9]

  if essid_len > 32:
    return None

  essid = buf[10:10 + essid_len]

  keyver = buf[42]
  bssid  = buf[59:65]
  snonce = buf[65:97]
  stmac  = buf[97:103]
  anonce = buf[103:135]

  eapol_len = struct.unpack("<H", buf[135:137])[0]

  if eapol_len > 256:
    return None

  eapol = buf[137:137 + eapol_len]

  new_hash = module_generate_hash(word, essid.decode("latin-1"), None,
                                  bssid, stmac, snonce, anonce, keyver, eapol)

  return (new_hash, word)

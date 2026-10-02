#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import struct

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_bytes

# WPA-PBKDF2-PMKID+EAPOL. The PMK is PBKDF2-HMAC-SHA1 (4096 iterations) of the
# passphrase salted by the ESSID. Two record kinds share the format: type 1 is a
# PMKID (HMAC-SHA1 over "PMK Name" || AP MAC || STA MAC), type 2 is an EAPOL MIC
# whose algorithm follows the key version (1/2/3 -> HMAC-MD5, HMAC-SHA1, AES-CMAC).


def module_constraints():
  return [[8, 63], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


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
    key_info |= 1
  elif keyver == 2:
    key_info |= 2
  elif keyver == 3:
    key_info |= 3

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


def _wpa_prf_512(keyver, pmk, macsta, macap, snonce, anonce):
  data = b"Pairwise key expansion"

  if keyver in (1, 2):
    data += b"\x00"

  # Min(AA, SPA) || Max(AA, SPA) over the 6 byte MACs
  if macsta < macap:
    data += macsta + macap
  else:
    data += macap + macsta

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


def _pmk(word, essid_bin):
  return hashlib.pbkdf2_hmac("sha1", word, essid_bin, 4096, 32)


def module_generate_hash(word, salt=None, type=None, macap=None, macsta=None,
                         essid=None, anonce=None, eapol=None, mp=None):
  if type is None:
    type = random_number(1, 2)
  else:
    type = int(type)

  if type == 1:
    if macap is None:
      macap = random_bytes(6).hex()
    if macsta is None:
      macsta = random_bytes(6).hex()
    if essid is None:
      essid = random_bytes(random_number(0, 32) & 0x1e).hex()

    essid_bin = bytes.fromhex(essid)

    pmk = _pmk(word, essid_bin)

    data = b"PMK Name" + bytes.fromhex(macap) + bytes.fromhex(macsta)

    pmkid = hmac.new(pmk, data, hashlib.sha1).hexdigest()

    return "WPA*%02x*%s*%s*%s*%s***" % (type, pmkid[:32], macap, macsta, essid)

  # type == 2
  if macap is None:
    macap = random_bytes(6)
  else:
    macap = bytes.fromhex(macap)

  if macsta is None:
    macsta = random_bytes(6)
  else:
    macsta = bytes.fromhex(macsta)

  if mp is None:
    mp = b"\x00"
  else:
    mp = bytes.fromhex(mp)

  if eapol is None:
    keyver = random_number(1, 3)
    snonce = random_bytes(32)
    eapol = _gen_random_wpa_eapol(keyver, snonce)
  else:
    eapol = bytes.fromhex(eapol)
    key_info = struct.unpack(">H", eapol[5:7])[0]
    keyver = key_info & 3
    snonce = eapol[17:49]

  if anonce is None:
    anonce = random_bytes(32)
  else:
    anonce = bytes.fromhex(anonce)

  if essid is None:
    essid = random_bytes(random_number(0, 32) & 0x1e).hex()

  essid_bin = bytes.fromhex(essid)

  pmk = _pmk(word, essid_bin)

  ptk = _wpa_prf_512(keyver, pmk, macsta, macap, snonce, anonce)

  if keyver == 1:
    mic = hmac.new(ptk, eapol, hashlib.md5).digest()
  elif keyver == 2:
    mic = hmac.new(ptk, eapol, hashlib.sha1).digest()
  elif keyver == 3:
    c = CMAC.new(ptk, ciphermod=AES)
    c.update(eapol)
    mic = c.digest()

  mic = mic[:16]

  return "WPA*%02x*%s*%s*%s*%s*%s*%s*%s" % (
    type, mic.hex(), macap.hex(), macsta.hex(), essid,
    anonce.hex(), eapol.hex(), mp.hex())


def module_verify_hash(line):
  idx1 = line.find(b":")

  if idx1 < 1:
    return None

  word = line[idx1 + 1:]
  hash_in = line[:idx1].decode(errors="replace")

  data = hash_in.split("*")

  if len(data) < 6:
    return None

  signature = data[0]
  type = data[1]
  macap = data[3]
  macsta = data[4]
  essid = data[5]
  anonce = data[6] if len(data) > 6 else None
  eapol = data[7] if len(data) > 7 else None
  mp = data[8] if len(data) > 8 else None

  if signature != "WPA":
    return None

  # type 1 records carry empty trailing fields, so treat those as absent
  anonce = anonce or None
  eapol = eapol or None
  mp = mp or None

  new_hash = module_generate_hash(word, None, type, macap, macsta, essid, anonce, eapol, mp)

  return (new_hash, word)

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
# passphrase salted by the ESSID. Four record kinds share the format: type 1 is a
# PMKID (HMAC-SHA1 over "PMK Name" || AP MAC || STA MAC, or HMAC-SHA256 on an AKM 6
# network), type 2 is an EAPOL MIC whose algorithm follows the key version
# (1/2/3 -> HMAC-MD5, HMAC-SHA1, AES-CMAC).
#
# Types 3 and 4 are the 802.11r Fast BSS Transition forms of the same two. They
# carry three more fields, the mobility domain and the two key holder IDs, and the
# PMK feeds the FT key hierarchy instead of the PTK directly. Type 3 holds a
# PMK-R1-Name and type 4 an EAPOL MIC taken over an AES-CMAC key from that
# hierarchy, so FT is defined for key version 3 only.


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


def _ft_kdf_block(key, counter, label, context, size):
  # KDF-Hash-Length from 802.11r: HMAC-SHA256 over the block counter, the label, the
  # context and the requested output size, the two numbers 16 bit little endian. The
  # label carries no terminator here, unlike the WPA PRF.
  data = struct.pack("<H", counter) + label + context + struct.pack("<H", size)

  return hmac.new(key, data, hashlib.sha256).digest()


def _gen_ft_eapol(snonce):
  body = b""

  body += struct.pack("B", 2)   # key descriptor: RSN

  key_info = 0
  key_info |= 3        # key version 3, AES-CMAC
  key_info |= 1 << 3   # pairwise key
  key_info |= 1 << 8   # key MIC present

  body += struct.pack(">H", key_info)
  body += struct.pack(">H", 0)  # key length
  body += struct.pack(">Q", 1)  # replay counter

  body += snonce
  body += b"\x00" * 16  # key IV
  body += b"\x00" * 8   # key RSC
  body += b"\x00" * 8   # key ID
  body += b"\x00" * 16  # key MIC, zeroed for the CMAC

  key_data = b""
  key_data += struct.pack("B", 48)     # RSN info tag
  key_data += struct.pack("B", 20)     # tag length
  key_data += struct.pack("<H", 1)     # RSN version
  key_data += bytes.fromhex("000fac")
  key_data += struct.pack("B", 4)      # group cipher AES (CCM)
  key_data += struct.pack("<H", 1)     # pairwise count
  key_data += bytes.fromhex("000fac")
  key_data += struct.pack("B", 4)      # pairwise AES (CCM)
  key_data += struct.pack("<H", 1)     # AKM count
  key_data += bytes.fromhex("000fac")
  key_data += struct.pack("B", 4)      # AKM FT/PSK
  key_data += bytes.fromhex("0000")    # RSN capabilities

  body += struct.pack(">H", len(key_data))
  body += key_data

  ret = b""

  ret += struct.pack("B", 1)  # version: 802.1X-2001
  ret += struct.pack("B", 3)  # type: key information
  ret += struct.pack(">H", len(body))
  ret += body

  return ret


def _ft_generate_hash(word, type, macap, macsta, essid, anonce, eapol, mp,
                      mdid, r0khid, r1khid):
  if macap is None:
    macap = random_bytes(6).hex()
  if macsta is None:
    macsta = random_bytes(6).hex()
  if essid is None:
    essid = random_bytes(random_number(0, 32) & 0x1e).hex()
  if mdid is None:
    mdid = random_bytes(2).hex()
  if r0khid is None:
    r0khid = random_bytes(random_number(0, 48)).hex()
  if r1khid is None:
    r1khid = random_bytes(6).hex()

  macap_bin  = bytes.fromhex(macap)
  macsta_bin = bytes.fromhex(macsta)
  essid_bin  = bytes.fromhex(essid)
  mdid_bin   = bytes.fromhex(mdid)
  r0khid_bin = bytes.fromhex(r0khid)
  r1khid_bin = bytes.fromhex(r1khid)

  pmk = _pmk(word, essid_bin)

  r0_ctx = (struct.pack("B", len(essid_bin)) + essid_bin + mdid_bin +
            struct.pack("B", len(r0khid_bin)) + r0khid_bin + macsta_bin)

  if type == 3:
    # The PMK-R0 KDF runs to 384 bits. Its second block holds the PMK-R0-Name salt,
    # so a PMKID needs that block and never the key itself.
    salt = _ft_kdf_block(pmk, 2, b"FT-R0", r0_ctx, 384)[:16]

    pmkr0_name = hashlib.sha256(b"FT-R0N" + salt).digest()[:16]

    pmkid = hashlib.sha256(b"FT-R1N" + pmkr0_name + r1khid_bin + macsta_bin).digest()[:16]

    if mp is None:
      mp = "00"

    return "WPA*%02x*%s*%s*%s*%s***%s*%s*%s*%s" % (
      type, pmkid.hex(), macap, macsta, essid, mp, mdid, r0khid, r1khid)

  # type == 4
  # Message pairs 3 and 4 store M3, whose frame carries the ANonce, and the nonce field then holds
  # the SNonce. hcxpcapngtool writes them with the AP-less bit set, as 13 and 14.
  if (mp is None) and (eapol is None):
    mp = "13" if random_number(0, 1) == 1 else "00"

  if mp is None:
    mp = "00"

  if eapol is None:
    frame_nonce = random_bytes(32)
    eapol       = _gen_ft_eapol(frame_nonce)
  else:
    eapol       = bytes.fromhex(eapol)
    frame_nonce = eapol[17:49]

  if anonce is None:
    field_nonce = random_bytes(32)
  else:
    field_nonce = bytes.fromhex(anonce)

  if (int(mp, 16) & 7) in (3, 4):
    snonce = field_nonce
    anonce = frame_nonce
  else:
    snonce = frame_nonce
    anonce = field_nonce

  pmkr0 = _ft_kdf_block(pmk, 1, b"FT-R0", r0_ctx, 384)
  pmkr1 = _ft_kdf_block(pmkr0, 1, b"FT-R1", r1khid_bin + macsta_bin, 256)

  ptk_ctx = snonce + anonce + macap_bin + macsta_bin

  ptk = _ft_kdf_block(pmkr1, 1, b"FT-PTK", ptk_ctx, 384)

  kck = ptk[:16]

  # the stored frame carries a zeroed MIC field, which is what the CMAC is taken over
  eapol = eapol[:81] + b"\x00" * 16 + eapol[97:]

  c = CMAC.new(kck, ciphermod=AES)
  c.update(eapol)

  mic = c.digest()[:16]

  return "WPA*%02x*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s" % (
    type, mic.hex(), macap, macsta, essid, field_nonce.hex(), eapol.hex(), mp,
    mdid, r0khid, r1khid)


def module_generate_hash(word, salt=None, type=None, macap=None, macsta=None,
                         essid=None, anonce=None, eapol=None, mp=None,
                         mdid=None, r0khid=None, r1khid=None):
  if type is None:
    type = random_number(1, 4)
  else:
    type = int(type)

  if type in (3, 4):
    return _ft_generate_hash(word, type, macap, macsta, essid, anonce, eapol, mp,
                             mdid, r0khid, r1khid)

  if type == 1:
    # Bit 1 of the message pair marks a PMKID from an AKM 6 (PSK-SHA256) network, which takes
    # HMAC-SHA256 rather than HMAC-SHA1. hcxpcapngtool writes it as 03. A fresh hash picks either.
    if (mp is None) and (macap is None):
      mp = "03" if random_number(0, 1) == 1 else ""

    if mp is None:
      mp = ""

    if macap is None:
      macap = random_bytes(6).hex()
    if macsta is None:
      macsta = random_bytes(6).hex()
    if essid is None:
      essid = random_bytes(random_number(0, 32) & 0x1e).hex()

    essid_bin = bytes.fromhex(essid)

    pmk = _pmk(word, essid_bin)

    data = b"PMK Name" + bytes.fromhex(macap) + bytes.fromhex(macsta)

    if (mp != "") and ((int(mp, 16) & 0x02) == 0x02):
      pmkid = hmac.new(pmk, data, hashlib.sha256).hexdigest()
    else:
      pmkid = hmac.new(pmk, data, hashlib.sha1).hexdigest()

    return "WPA*%02x*%s*%s*%s*%s***%s" % (type, pmkid[:32], macap, macsta, essid, mp)

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
  mdid = data[9] if len(data) > 9 else None
  r0khid = data[10] if len(data) > 10 else None
  r1khid = data[11] if len(data) > 11 else None

  if signature != "WPA":
    return None

  # a PMKID record carries empty trailing fields, so treat those as absent
  anonce = anonce or None
  eapol = eapol or None
  mp = mp or None

  # an FT key holder ID may legitimately be empty, so only an absent field is None
  if r0khid is None:
    r1khid = None

  new_hash = module_generate_hash(word, None, type, macap, macsta, essid, anonce,
                                 eapol, mp, mdid, r0khid, r1khid)

  return (new_hash, word)

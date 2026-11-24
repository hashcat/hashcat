#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

#
# Extracts the OSDP Secure Channel handshake from OSDPCAP captures, the JSON lines format written by
# libosdp-conformance and OSDP.Net, for hash-mode 47000, or with --mk for hash-mode 47001.
#
# The CP opens a session with osdp_CHLNG (SCB type 0x11, command 0x76) carrying RND.A. The PD
# answers with osdp_CCRYPT (SCB type 0x12, reply 0x76) carrying its cUID, RND.B and the client
# cryptogram.
#
# Hash format: $osdp$rnd_a*rnd_b*client_cryptogram
# With --mk:   $osdp-mk$cuid*rnd_a*rnd_b*client_cryptogram
#
# --mk leaves out a session that runs on SCBK-D, since that key does not come from a Master Key.
#
# Every hash goes to stdout. A hash whose cryptogram checks against SCBK-D, the published default
# key 0x30..0x3f, is also written to stderr, already paired with that key in hashcat's hash:plain
# form and marked as the default key, for example:
#
#   $osdp$9acc78e0e206fd87*d66d5a91e600806a*53fa00e5e6e152abd57a7e10000b4a5f:$HEX[303132333435363738393a3b3c3d3e3f] (SCBK-D, the default key)
#

import argparse
import json
import sys

from Crypto.Cipher import AES

SOM = 0x53

SCS_11 = 0x11
SCS_12 = 0x12

CMD_CHLNG    = 0x76
REPLY_CCRYPT = 0x76

SCBK_D = bytes(range(0x30, 0x40))


# True if the client cryptogram was made with this SCBK, computed as in test_modules/m47000.py.

def check_key(scbk, rnd_a, rnd_b, cryptogram):
  s_enc = AES.new(scbk, AES.MODE_ECB).encrypt(b"\x01\x82" + rnd_a[0:6] + b"\x00" * 8)

  return AES.new(s_enc, AES.MODE_ECB).encrypt(rnd_a + rnd_b) == cryptogram


def crc16(data):
  crc = 0x1d0f

  for b in data:
    crc ^= b << 8

    for _ in range(8):
      if crc & 0x8000:
        crc = ((crc << 1) ^ 0x1021) & 0xffff
      else:
        crc = (crc << 1) & 0xffff

  return crc


def checksum(data):
  return (-sum(data)) & 0xff


# Every valid frame in a record. A record can carry a leading mark byte or bytes that are not part
# of a frame, so each SOM is tried and kept only if its CRC or checksum matches.

def frames(data):
  pos = 0

  while True:
    pos = data.find(bytes([SOM]), pos)

    if pos < 0:
      return

    if len(data) - pos < 7:
      return

    length = data[pos + 2] | (data[pos + 3] << 8)

    frame = data[pos:pos + length]

    if (length >= 7) and (len(frame) == length):
      ctrl = frame[4]

      if ctrl & 0x04:
        valid = crc16(frame[:-2]) == (frame[-2] | (frame[-1] << 8))
      else:
        valid = checksum(frame[:-1]) == frame[-1]

      if valid:
        yield frame

        pos += length

        continue

    pos += 1


# (address, SQN, SCB type or None, command or reply code, data), or None if malformed.
# Only SCB types 0x11 and 0x12 are read, they carry neither MAC nor encryption.

def parse(frame):
  ctrl = frame[4]

  scb_type = None

  code_pos = 5

  if ctrl & 0x08:
    scb_len = frame[5]

    if scb_len < 2:
      return None

    scb_type = frame[6]

    code_pos = 5 + scb_len

  check_len = 2 if (ctrl & 0x04) else 1

  if code_pos >= len(frame) - check_len:
    return None

  return frame[1], ctrl & 0x03, scb_type, frame[code_pos], frame[code_pos + 1:len(frame) - check_len]


def extract(path, mk):
  try:
    f = open(path, "r", encoding="utf-8", errors="replace")
  except IOError as e:
    sys.stderr.write("%s: %s\n" % (path, e))
    return None

  sessions = []
  hashes   = []

  # (RND.A, SQN) of the osdp_CHLNG awaiting its osdp_CCRYPT, per PD address. Any other command to
  # or reply from that PD drops it, so a late reply cannot pair with a later challenge.

  challenges = {}

  with f:
    for line in f:
      line = line.strip()

      if len(line) == 0:
        continue

      try:
        record = json.loads(line)
      except ValueError:
        continue

      if not isinstance(record, dict):
        continue

      text = record.get("data", "")

      if not isinstance(text, str):
        continue

      hex_text = "".join(c for c in text if c in "0123456789abcdefABCDEF")

      if (len(hex_text) % 2) != 0:
        continue

      for frame in frames(bytes.fromhex(hex_text)):
        p = parse(frame)

        if p is None:
          continue

        addr, sqn, scb_type, code, data = p

        pd = addr & 0x7f

        if (addr & 0x80) == 0:
          if (scb_type == SCS_11) and (code == CMD_CHLNG) and (len(data) == 8):
            challenges[pd] = (data, sqn)
          else:
            challenges.pop(pd, None)

          continue

        if (scb_type != SCS_12) or (code != REPLY_CCRYPT) or (len(data) != 32):
          challenges.pop(pd, None)

          continue

        if pd not in challenges:
          continue

        rnd_a, chlng_sqn = challenges.pop(pd)

        # a reply carries the SQN of the command it answers

        if sqn != chlng_sqn:
          continue

        cuid       = data[ 0: 8]
        rnd_b      = data[ 8:16]
        cryptogram = data[16:32]

        h = "$osdp$%s*%s*%s" % (rnd_a.hex(), rnd_b.hex(), cryptogram.hex())

        if h in sessions:
          continue

        sessions.append(h)

        default_key = check_key(SCBK_D, rnd_a, rnd_b, cryptogram)

        # SCBK-D holds ':', so hashcat prints it as $HEX[]

        if default_key:
          sys.stderr.write("%s:$HEX[%s] (SCBK-D, the default key)\n" % (h, SCBK_D.hex()))

        if mk:
          if default_key:
            continue

          h = "$osdp-mk$%s*%s*%s*%s" % (cuid.hex(), rnd_a.hex(), rnd_b.hex(), cryptogram.hex())

        hashes.append(h)

  if len(sessions) == 0:
    sys.stderr.write("%s: no osdp_CHLNG and osdp_CCRYPT pair found\n" % path)
    return None

  if len(hashes) == 0:
    sys.stderr.write("%s: every session runs on SCBK-D, none on a key from a Master Key\n" % path)
    return None

  return hashes


def main():
  parser = argparse.ArgumentParser(description="Extract OSDP Secure Channel handshakes from OSDPCAP captures")

  parser.add_argument("--mk", action="store_true", help="write the lines of hash-mode 47001, for an SCBK derived from a Master Key")
  parser.add_argument("captures", nargs="+", metavar="capture.osdpcap")

  args = parser.parse_args()

  rc = 0

  for path in args.captures:
    hashes = extract(path, args.mk)

    if hashes is None:
      rc = 1
      continue

    for h in hashes:
      print(h)

  sys.exit(rc)


if __name__ == "__main__":
  main()

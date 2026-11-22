#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

#
# Extracts the OSDP Secure Channel handshake from OSDPCAP captures, the JSON lines format written by
# libosdp-conformance and OSDP.Net, for hash-mode 47000.
#
# The CP opens a session with osdp_CHLNG (SCB type 0x11, command 0x76) carrying RND.A. The PD
# answers with osdp_CCRYPT (SCB type 0x12, reply 0x76) carrying its cUID, RND.B and the client
# cryptogram.
#
# Hash format: $osdp$rnd_a*rnd_b*client_cryptogram
#

import json
import sys

SOM = 0x53

SCS_11 = 0x11
SCS_12 = 0x12

CMD_CHLNG    = 0x76
REPLY_CCRYPT = 0x76


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


# (address, SCB type, command or reply code, data), or None for a frame without a security block.
# Only SCB types 0x11 and 0x12 are read, they carry neither MAC nor encryption.

def parse(frame):
  ctrl = frame[4]

  if (ctrl & 0x08) == 0:
    return None

  scb_len = frame[5]

  if scb_len < 2:
    return None

  scb_type = frame[6]

  code_pos = 5 + scb_len

  check_len = 2 if (ctrl & 0x04) else 1

  if code_pos >= len(frame) - check_len:
    return None

  return frame[1], scb_type, frame[code_pos], frame[code_pos + 1:len(frame) - check_len]


def extract(path):
  try:
    f = open(path, "r", encoding="utf-8", errors="replace")
  except IOError as e:
    sys.stderr.write("%s: %s\n" % (path, e))
    return None

  hashes = []

  # RND.A of the last osdp_CHLNG sent to each PD address

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

        addr, scb_type, code, data = p

        pd = addr & 0x7f

        if (scb_type == SCS_11) and (code == CMD_CHLNG) and ((addr & 0x80) == 0) and (len(data) == 8):
          challenges[pd] = data

        elif (scb_type == SCS_12) and (code == REPLY_CCRYPT) and ((addr & 0x80) != 0) and (len(data) == 32):
          if pd not in challenges:
            continue

          rnd_a = challenges.pop(pd)

          rnd_b      = data[ 8:16]
          cryptogram = data[16:32]

          h = "$osdp$%s*%s*%s" % (rnd_a.hex(), rnd_b.hex(), cryptogram.hex())

          if h not in hashes:
            hashes.append(h)

  if len(hashes) == 0:
    sys.stderr.write("%s: no osdp_CHLNG and osdp_CCRYPT pair found\n" % path)
    return None

  return hashes


def main():
  if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s capture.osdpcap ...\n" % sys.argv[0])
    sys.exit(1)

  rc = 0

  for path in sys.argv[1:]:
    hashes = extract(path)

    if hashes is None:
      rc = 1
      continue

    for h in hashes:
      print(h)

  sys.exit(rc)


if __name__ == "__main__":
  main()

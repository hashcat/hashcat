#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Whirlpool (ISO/IEC 10118-3), for mode 6100. hashlib reaches it only where OpenSSL was built with
# the legacy provider, which is rare now, and pycryptodome dropped it, so this is a small self
# contained implementation. The 256 byte S box is the one the specification fixes; the eight round
# tables and the round constants are derived from it, so those large tables are not carried here.

SBOX = bytes.fromhex(
  "1823c6e887b8014f36a6d2f5796f9152"
  "60bc9b8ea30c7b351de0d7c22e4bfe57"
  "157737e59ff04ada58c9290ab1a06b85"
  "bd5d10f4cb3e0567e427418ba77d95d8"
  "fbee7c66dd17479eca2dbf07ad5a8333"
  "6302aa71c81949d9f2e35b889a2632b0"
  "e90fd580becd3448ff7a905f20681aae"
  "b454932264f173124008c3ecdba18d3d"
  "9700cf2b7682d61bb5af6a5045f330ef"
  "3f55a2ea65ba2fc0de1cfd4d9275068a"
  "b2e60e1f62d4a896f9c525598472394c"
  "5e78388cd1a5e261b3219c1e43c7fc04"
  "51996d0dfadf7e243babce118f4eb7eb"
  "3c8194f7b9132cd3e76ec40356447fa9"
  "2abbc153dc0b9d6c3174f646ac8914e1"
  "163a690970b6d0edcc4298a4285cf886"
)


def _mul(a, b):
  # multiply in GF(2^8) with the reducing polynomial 0x11d

  p = 0

  for _ in range(8):
    if b & 1:
      p ^= a

    hi = a & 0x80
    a = (a << 1) & 0xff

    if hi:
      a ^= 0x1d

    b >>= 1

  return p


# the eight circulant multiplication tables and ten round constants

_C = [[0] * 256 for _ in range(8)]

for x in range(256):
  s = SBOX[x]

  v = [_mul(s, c) for c in (1, 1, 4, 1, 8, 5, 2, 9)]

  for t in range(8):
    _C[t][x] = int.from_bytes(bytes(v[(i - t) % 8] for i in range(8)), "big")

_RC = []

for r in range(1, 11):
  _RC.append(int.from_bytes(bytes(SBOX[8 * (r - 1) + i] if i < 8 else 0 for i in range(8)), "big"))


def _w(x):
  return x & 0xffffffffffffffff


def _transform(state_block, key_block):
  # one Miyaguchi-Preneel step: block cipher W on the message block, keyed by the state, XOR the
  # state and the message back in

  k = [int.from_bytes(state_block[i * 8:i * 8 + 8], "big") for i in range(8)]
  b = [int.from_bytes(key_block[i * 8:i * 8 + 8], "big") ^ k[i] for i in range(8)]

  for r in range(10):
    k = [_w(_C[0][(k[i] >> 56) & 0xff] ^ _C[1][(k[(i - 1) % 8] >> 48) & 0xff] ^
            _C[2][(k[(i - 2) % 8] >> 40) & 0xff] ^ _C[3][(k[(i - 3) % 8] >> 32) & 0xff] ^
            _C[4][(k[(i - 4) % 8] >> 24) & 0xff] ^ _C[5][(k[(i - 5) % 8] >> 16) & 0xff] ^
            _C[6][(k[(i - 6) % 8] >> 8) & 0xff] ^ _C[7][k[(i - 7) % 8] & 0xff])
       for i in range(8)]

    k[0] ^= _RC[r]

    b = [_w(_C[0][(b[i] >> 56) & 0xff] ^ _C[1][(b[(i - 1) % 8] >> 48) & 0xff] ^
            _C[2][(b[(i - 2) % 8] >> 40) & 0xff] ^ _C[3][(b[(i - 3) % 8] >> 32) & 0xff] ^
            _C[4][(b[(i - 4) % 8] >> 24) & 0xff] ^ _C[5][(b[(i - 5) % 8] >> 16) & 0xff] ^
            _C[6][(b[(i - 6) % 8] >> 8) & 0xff] ^ _C[7][b[(i - 7) % 8] & 0xff] ^ k[i])
       for i in range(8)]

  return b"".join(
    (int.from_bytes(state_block[i * 8:i * 8 + 8], "big") ^ b[i] ^
     int.from_bytes(key_block[i * 8:i * 8 + 8], "big")).to_bytes(8, "big") for i in range(8))


def whirlpool(data):
  bit_len = (len(data) * 8).to_bytes(32, "big")

  msg = data + b"\x80" + b"\x00" * ((32 - (len(data) + 1) % 64) % 64) + bit_len

  state = b"\x00" * 64

  for i in range(0, len(msg), 64):
    state = _transform(state, msg[i:i + 64])

  return state


def whirlpool_hex(data):
  return whirlpool(data).hex()

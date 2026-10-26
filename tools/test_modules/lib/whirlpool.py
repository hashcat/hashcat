#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Whirlpool (ISO/IEC 10118-3), for mode 6100. hashlib reaches it only where OpenSSL was built with
# the legacy provider, which is rare now, and pycryptodome dropped it, so this is a small self
# contained implementation. The 256 byte S box is the one the specification fixes; the eight round
# tables and the round constants are derived from it, so those large tables are not carried here.
# wrl0 and wrl1 are the two earlier versions, Whirlpool-0 and Whirlpool-T.

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


# Whirlpool-0 used a random S box. Whirlpool-T took the final S box, and both used the circulant
# row (1, 1, 3, 1, 5, 8, 9, 5) that the final version replaced

SBOX0 = bytes.fromhex(
  "68d0eb2b489d6ae4e3a356817df1859e"
  "2c8e78ca17a961d55d0b8c3c77512242"
  "3f544180cc86b3182e570662f436d16b"
  "1b657510da4926f9cb66e7baae5052ab"
  "05f00d733b0420feddf5b45f0ab5c0a0"
  "71a52d607293390883215c87b1e000c3"
  "12918a021ce645c2c4fdbf44a14c33c5"
  "84237cb025153569ff944d70a2afcdd6"
  "6cb7f809f367a4eaecb6d4d2141ee124"
  "38c6db4b7a3ade5edf95fcaad7ce070f"
  "3d589a989cf2a7117e8b4303e2dce5b2"
  "4ec76de92740d837928f011d533e59c1"
  "4f3216fa74fb639f341a2a5a8dc9cff6"
  "9028889b310ebd4ae896a60cc879bcbe"
  "ef6e46975bed19d9ac99a829641fad55"
  "13bbf76fb9472feeb87b8930d37f7682"
)


def _tables(sbox, row):
  # the eight circulant multiplication tables and ten round constants

  c = [[0] * 256 for _ in range(8)]

  for x in range(256):
    s = sbox[x]

    v = [_mul(s, m) for m in row]

    for t in range(8):
      c[t][x] = int.from_bytes(bytes(v[(i - t) % 8] for i in range(8)), "big")

  rc = []

  for r in range(1, 11):
    rc.append(int.from_bytes(bytes(sbox[8 * (r - 1) + i] for i in range(8)), "big"))

  return c, rc


_C, _RC = _tables(SBOX, (1, 1, 4, 1, 8, 5, 2, 9))

_C0, _RC0 = _tables(SBOX0, (1, 1, 3, 1, 5, 8, 9, 5))
_C1, _RC1 = _tables(SBOX, (1, 1, 3, 1, 5, 8, 9, 5))


def _w(x):
  return x & 0xffffffffffffffff


def _transform(state_block, key_block, c=_C, rc=_RC):
  # one Miyaguchi-Preneel step: block cipher W on the message block, keyed by the state, XOR the
  # state and the message back in

  k = [int.from_bytes(state_block[i * 8:i * 8 + 8], "big") for i in range(8)]
  b = [int.from_bytes(key_block[i * 8:i * 8 + 8], "big") ^ k[i] for i in range(8)]

  for r in range(10):
    k = [_w(c[0][(k[i] >> 56) & 0xff] ^ c[1][(k[(i - 1) % 8] >> 48) & 0xff] ^
            c[2][(k[(i - 2) % 8] >> 40) & 0xff] ^ c[3][(k[(i - 3) % 8] >> 32) & 0xff] ^
            c[4][(k[(i - 4) % 8] >> 24) & 0xff] ^ c[5][(k[(i - 5) % 8] >> 16) & 0xff] ^
            c[6][(k[(i - 6) % 8] >> 8) & 0xff] ^ c[7][k[(i - 7) % 8] & 0xff])
       for i in range(8)]

    k[0] ^= rc[r]

    b = [_w(c[0][(b[i] >> 56) & 0xff] ^ c[1][(b[(i - 1) % 8] >> 48) & 0xff] ^
            c[2][(b[(i - 2) % 8] >> 40) & 0xff] ^ c[3][(b[(i - 3) % 8] >> 32) & 0xff] ^
            c[4][(b[(i - 4) % 8] >> 24) & 0xff] ^ c[5][(b[(i - 5) % 8] >> 16) & 0xff] ^
            c[6][(b[(i - 6) % 8] >> 8) & 0xff] ^ c[7][b[(i - 7) % 8] & 0xff] ^ k[i])
       for i in range(8)]

  return b"".join(
    (int.from_bytes(state_block[i * 8:i * 8 + 8], "big") ^ b[i] ^
     int.from_bytes(key_block[i * 8:i * 8 + 8], "big")).to_bytes(8, "big") for i in range(8))


def _hash(data, c, rc):
  bit_len = (len(data) * 8).to_bytes(32, "big")

  msg = data + b"\x80" + b"\x00" * ((32 - (len(data) + 1) % 64) % 64) + bit_len

  state = b"\x00" * 64

  for i in range(0, len(msg), 64):
    state = _transform(state, msg[i:i + 64], c, rc)

  return state


def whirlpool(data):
  return _hash(data, _C, _RC)


def whirlpool_hex(data):
  return whirlpool(data).hex()


def wrl0(data: bytes) -> bytes:
  digest = _hash(data, _C0, _RC0)

  return digest


def wrl1(data: bytes) -> bytes:
  digest = _hash(data, _C1, _RC1)

  return digest

#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# JH, the final round version, with 224, 256, 384 and 512 bit digests. Neither hashlib nor
# pycryptodome carries it. Each 128 bit state word holds the high and low 64 bit halves.

_M64  = 0xffffffffffffffff
_M128 = (1 << 128) - 1

# round constants of E8, one line per round: the even constant, then the odd one

_C = [
  0x72d5dea2df15f8677b84150ab7231557, 0x81abd6904d5a87f64e9f4fc5c3d12b40,
  0xea983ae05c45fa9c03c5d29966b2999a, 0x660296b4f2bb538ab556141a88dba231,
  0x03a35a5c9a190edb403fb20a87c14410, 0x1c051980849e951d6f33ebad5ee7cddc,
  0x10ba139202bf6b41dc786515f7bb27d0, 0x0a2c813937aa78503f1abfd2410091d3,
  0x422d5a0df6cc7e90dd629f9c92c097ce, 0x185ca70bc72b44acd1df65d663c6fc23,
  0x976e6c039ee0b81a2105457e446ceca8, 0xeef103bb5d8e61fafd9697b294838197,
  0x4a8e8537db03302f2a678d2dfb9f6a95, 0x8afe7381f8b8696c8ac77246c07f4214,
  0xc5f4158fbdc75ec475446fa78f11bb80, 0x52de75b7aee488bc82b8001e98a6a3f4,
  0x8ef48f33a9a36315aa5f5624d5b7f989, 0xb6f1ed207c5ae0fd36cae95a06422c36,
  0xce2935434efe983d533af974739a4ba7, 0xd0f51f596f4e81860e9dad81afd85a9f,
  0xa7050667ee34626a8b0b28be6eb91727, 0x47740726c680103fe0a07e6fc67e487b,
  0x0d550aa54af8a4c091e3e79f978ef19e, 0x8676728150608dd47e9e5a41f3e5b062,
  0xfc9f1fec4054207ae3e41a00cef4c984, 0x4fd794f59dfa95d8552e7e1124c354a5,
  0x5bdf7228bdfe6e2878f57fe20fa5c4b2, 0x05897cefee49d32e447e9385eb28597f,
  0x705f6937b324314a5e8628f11dd6e465, 0xc71b770451b920e774fe43e823d4878a,
  0x7d29e8a3927694f2ddcb7a099b30d9c1, 0x1d1b30fb5bdc1be0da24494ff29c82bf,
  0xa4e7ba31b470bfff0d324405def8bc48, 0x3baefc3253bbd339459fc3c1e0298ba0,
  0xe5c905fdf7ae090f947034124290f134, 0xa271b701e344ed95e93b8e364f2f984a,
  0x88401d63a06cf61547c1444b8752afff, 0x7ebb4af1e20ac6304670b6c5cc6e8ce6,
  0xa4d5a456bd4fca00da9d844bc83e18ae, 0x7357ce453064d1ade8a6ce68145c2567,
  0xa3da8cf2cb0ee11633e906589a94999a, 0x1f60b220c26f847bd1ceac7fa0d18518,
  0x32595ba18ddd19d3509a1cc0aaa5b446, 0x9f3d6367e4046bbaf6ca19ab0b56ee7e,
  0x1fb179eaa9282174e9bdf7353b3651ee, 0x1d57ac5a7550d3763a46c2fea37d7001,
  0xf735c1af98a4d84278edec209e6b6779, 0x41836315ea3adba8fac33b4d32832c83,
  0xa7403b1f1c2747f35940f034b72d769a, 0xe73e4e6cd2214ffdb8fd8d39dc5759ef,
  0x8d9b0c492b49ebda5ba2d74968f3700d, 0x7d3baed07a8d5584f5a5e9f0e4f88e65,
  0xa0b8a2f436103b530ca8079e753eec5a, 0x9168949256e8884f5bb05c55f8babc4c,
  0xe3bb3b99f387947b75daf4d6726b1c5d, 0x64aeac28dc34b36d6c34a550b828db71,
  0xf861e2f2108d512ae3db643359dd75fc, 0x1cacbcf143ce3fa267bbd13c02e843b0,
  0x330a5bca8829a1757f34194db416535c, 0x923b94c30e794d1e797475d7b6eeaf3f,
  0xeaa8d4f7be1a39215cf47e094c232751, 0x26a32453ba323cd244a3174a6da6d5ad,
  0xb51d3ea6aff2c90883593d98916b3c56, 0x4cf87ca17286604d46e23ecc086ec7f6,
  0x2f9833b3b1bc765e2bd666a5efc4e62a, 0x06f4b6e8bec1d43674ee8215bcef2163,
  0xfdc14e0df453c969a77d5ac406585826, 0x7ec1141606e0fa167e90af3d28639d3f,
  0xd2c9f2e3009bd20c5faace30b7d40c30, 0x742a5116f2e032980deb30d8e3cef89a,
  0x4bc59e7bb5f17992ff51e66e048668d3, 0x9b234d57e6966731cce6a6f3170a7505,
  0xb17681d913326cce3c175284f805a262, 0xf42bcbb378471547ff46548223936a48,
  0x38df58074e5e6565f2fc7c89fc86508e, 0x31702e44d00bca86f04009a23078474e,
  0x65a0ee39d1f73883f75ee937e42c3abd, 0x2197b2260113f86fa344edd1ef9fdee7,
  0x8ba0df15762592d93c85f7f612dc42be, 0xd8a7ec7cab27b07e538d7ddaaa3ea8de,
  0xaa25ce93bd0269d85af643fd1a7308f9, 0xc05fefda174a19a5974d66334cfd216a,
  0x35b49831db411570ea1e0fbbedcd549b, 0x9ad063a151974072f6759dbf91476fe2,
]


def _w(c64: int, n: int):
  c = (c64 << 64) | c64

  def f(x: int) -> int:
    t = (x & c) << n

    r = ((x >> n) & c) | t

    return r

  return f


def _w6(x: int) -> int:
  r = ((x & _M64) << 64) | (x >> 64)

  return r


_W = [
  _w(0x5555555555555555,  1),
  _w(0x3333333333333333,  2),
  _w(0x0f0f0f0f0f0f0f0f,  4),
  _w(0x00ff00ff00ff00ff,  8),
  _w(0x0000ffff0000ffff, 16),
  _w(0x00000000ffffffff, 32),
  _w6,
]


def _sb(x0: int, x1: int, x2: int, x3: int, c: int):
  x3 ^= _M128
  x0 ^= c & (x2 ^ _M128)

  t = c ^ (x0 & x1)

  x0 ^= x2 & x3
  x3 ^= (x1 ^ _M128) & x2
  x1 ^= x0 & x2
  x2 ^= x0 & (x3 ^ _M128)
  x0 ^= x1 | x3
  x3 ^= x1 & x2
  x1 ^= t & x0
  x2 ^= t

  return x0, x1, x2, x3


def _e8(h: list) -> list:
  h0, h1, h2, h3, h4, h5, h6, h7 = h

  for r in range(42):
    h0, h2, h4, h6 = _sb(h0, h2, h4, h6, _C[2 * r + 0])
    h1, h3, h5, h7 = _sb(h1, h3, h5, h7, _C[2 * r + 1])

    h1 ^= h2
    h3 ^= h4
    h5 ^= h6 ^ h0
    h7 ^= h0
    h0 ^= h3
    h2 ^= h5
    h4 ^= h7 ^ h1
    h6 ^= h1

    w = _W[r % 7]

    h1 = w(h1)
    h3 = w(h3)
    h5 = w(h5)
    h7 = w(h7)

  return [h0, h1, h2, h3, h4, h5, h6, h7]


def _f8(h: list, block: bytes) -> list:
  m = [int.from_bytes(block[i * 16:i * 16 + 16], "big") for i in range(4)]

  for i in range(4): h[i] ^= m[i]

  h = _e8(h)

  for i in range(4): h[i + 4] ^= m[i]

  return h


def _iv(bits: int) -> list:
  # the IV is F8 over a zero block, starting from the digest length in the first 2 bytes

  h = [0] * 8

  h[0] = bits << 112

  r = _f8(h, bytes(64))

  return r


_IV = {bits: _iv(bits) for bits in (224, 256, 384, 512)}


def _jh(data: bytes, bits: int) -> bytes:
  h = list(_IV[bits])

  rem = len(data) % 64

  if rem == 0:
    pad = 47
  else:
    pad = 111 - rem

  bitlen = (len(data) * 8) & _M128

  msg = data + b"\x80" + bytes(pad) + bitlen.to_bytes(16, "big")

  for off in range(0, len(msg), 64):
    h = _f8(h, msg[off:off + 64])

  out = b"".join(x.to_bytes(16, "big") for x in h[4:8])

  r = out[64 - (bits // 8):]

  return r


def jh224(data: bytes) -> bytes:
  return _jh(data, 224)


def jh256(data: bytes) -> bytes:
  return _jh(data, 256)


def jh384(data: bytes) -> bytes:
  return _jh(data, 384)


def jh512(data: bytes) -> bytes:
  return _jh(data, 512)

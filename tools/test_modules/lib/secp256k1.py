#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# secp256k1, only what an oracle needs from it: take a compressed point apart, multiply it by a
# scalar, put it back together.
#
# The curve is y^2 = x^3 + 7 over a prime field, so a compressed point is the sign of y and the x it
# belongs to, and recovering y is a square root. P is 3 mod 4, which makes that root one
# exponentiation rather than a search. Half the x values have no root, and a point that came out of
# random bytes is on the curve only that often, which is why decompress () can say no.

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

B = 7

POINT_LEN = 33


def decompress(data):
  if len(data) != POINT_LEN or data[0] not in (2, 3):
    return None

  x = int.from_bytes(data[1:], "big")

  if x >= P:
    return None

  y = pow((x * x * x + B) % P, (P + 1) // 4, P)

  if (y * y) % P != (x * x * x + B) % P:
    return None

  if (y & 1) != (data[0] & 1):
    y = P - y

  return (x, y)


def _double(p):
  if p is None:
    return None

  # a is zero on this curve, so the tangent is 3x^2 over 2y

  if p[1] == 0:
    return None

  s = (3 * p[0] * p[0]) * pow(2 * p[1], -1, P) % P

  x = (s * s - 2 * p[0]) % P

  return (x, (s * (p[0] - x) - p[1]) % P)


def _add(p, q):
  if p is None:
    return q

  if q is None:
    return p

  if p[0] == q[0]:
    return _double(p) if (p[1] == q[1]) else None

  s = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P

  x = (s * s - p[0] - q[0]) % P

  return (x, (s * (p[0] - x) - p[1]) % P)


def mul(k, point):
  r = None

  while k:
    if k & 1:
      r = _add(r, point)

    point = _double(point)

    k >>= 1

  return r


def compress(point):
  return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")

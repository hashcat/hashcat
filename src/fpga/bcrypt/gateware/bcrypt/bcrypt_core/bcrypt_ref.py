#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

M32 = 0xffffffff

P_INIT = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b,
]

def load_s(path):
  words = []
  for line in open(path):
    line = line.strip()
    if line == '' or line.startswith('//'):
      continue
    words.append(int(line, 16))
  assert len(words) == 1024, len(words)

  return [words[b*256:(b+1)*256] for b in range(4)]

def f(S, x):
  a = (x >> 24) & 0xff
  b = (x >> 16) & 0xff
  c = (x >>  8) & 0xff
  d = x & 0xff

  return ((((S[0][a] + S[1][b]) & M32) ^ S[2][c]) + S[3][d]) & M32

def enc(P, S, l, r):
  for i in range(16):
    l ^= P[i]
    r ^= f(S, l)
    l, r = r, l

  l, r = r, l

  r ^= P[16]
  l ^= P[17]

  return l & M32, r & M32

def expandkey(P, S, key, salt):
  for i in range(18):
    P[i] ^= key[i % len(key)]
    P[i] &= M32

  l = r = 0
  si = 0
  ns = len(salt)

  for i in range(0, 18, 2):
    if ns:
      l ^= salt[si % ns]
      r ^= salt[(si + 1) % ns]
      si = (si + 2) % ns
    l, r = enc(P, S, l, r)
    P[i], P[i+1] = l, r

  for bi in range(4):
    for j in range(0, 256, 2):
      if ns:
        l ^= salt[si % ns]
        r ^= salt[(si + 1) % ns]
        si = (si + 2) % ns
      l, r = enc(P, S, l, r)
      S[bi][j], S[bi][j+1] = l, r

def run(s_path, ek18, salt4, rounds):
  S = load_s(s_path)
  P = list(P_INIT)

  expandkey(P, S, ek18, salt4)

  for _ in range(rounds):
    expandkey(P, S, ek18, [])
    expandkey(P, S, salt4, [])

  mag = b"OrpheanBeholderScryDoubt"
  ct = [int.from_bytes(mag[4*k:4*k+4], 'big') for k in range(6)]

  for _ in range(64):
    for k in range(0, 6, 2):
      ct[k], ct[k+1] = enc(P, S, ct[k], ct[k+1])

  return P, S, ct

MAGIC_PN = [0x65616E42, 0x4F727068, 0x64657253, 0x65686F6C, 0x6F756274, 0x63727944]

def partial(s_path, ek18, salt4, rounds_done):
  S = load_s(s_path)
  P = list(P_INIT)
  expandkey(P, S, ek18, salt4)
  for _ in range(rounds_done):
    expandkey(P, S, ek18, [])
    expandkey(P, S, salt4, [])
  return P, S
def restore_image(P, S):
  img = list(P[:18]) + [0]*6 + list(MAGIC_PN)
  for b in range(4):
    img += S[b]

  assert len(img) == 1054, len(img)
  return img
if __name__ == '__main__':
  import sys

  ek18 = [
    0x70617373, 0x776f7264, 0x00706173, 0x73776f72,
    0x64007061, 0x7373776f, 0x72640070, 0x61737377,
    0x6f726400, 0x70617373, 0x776f7264, 0x00706173,
    0x73776f72, 0x64007061, 0x7373776f, 0x72640070,
    0x61737377, 0x6f726400,
  ]
  salt4 = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f]
  P, S, ct = run(sys.argv[1], ek18, salt4, 32)
  print("digest  :", " ".join("%08x" % c for c in ct))
  GOLD = "cff8a8ac 7bdadd00 1b00d26d f3c9e4ed 0c4983e3 981b1d0d"
  print("expect  :", GOLD)
  print("selfcheck:", "PASS" if ["%08x" % c for c in ct] == GOLD.split() else "FAIL")
  with open(sys.argv[2], 'w') as fh:
    for b in range(4):
      for j in range(256):
        fh.write("%08x\n" % S[b][j])

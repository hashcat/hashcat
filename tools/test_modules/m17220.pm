#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

# PKZIP traditional PKWARE / ZipCrypto (mode 17220). Self-contained oracle:
# the ZipCrypto key schedule is a byte-exact port of the kernel macros in
# OpenCL/m172*-pure.cl (init keys 0x12345678/0x23456789/0x34567890,
# update_key012 / update_key3, decrypt byte = ((key2 & 0xffff) | 3)).
#
# Each file is emitted as a "full data" (data_type_enum 2) block: a 12-byte
# encryption header (whose last byte is (crc >> 24) & 0xff, the value hashcat
# checks) followed by the ZipCrypto-encrypted file bytes -- stored for
# compression_type 0, raw DEFLATE for compression_type 8. Generating by
# *encrypting* the same way hashcat decrypts means a correct password
# reproduces every header check and CRC32 by construction.
#
# Per-mode container shape (count + per-file compression types) is selected by
# the mode number passed to the generator:
#   17210 = 1 stored           17200 = 1 deflate
#   17220 = N deflate          17225 = N mixed stored/deflate
#   17230 = >=3 deflate (checksum-only mode; full-data blocks still validate)

my $MODE = 17220;

my $PY = <<'PYCODE';
import sys, os, zlib, random

def make_tab():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if (c & 1) else 0)
        t.append(c & 0xffffffff)
    return t
TAB = make_tab()

def c32(x, c):
    return ((x >> 8) ^ TAB[(x ^ c) & 0xff]) & 0xffffffff

class ZC:
    def __init__(self, pw):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in pw:
            self.upd(b)
    def upd(self, c):
        self.k[0] = c32(self.k[0], c)
        self.k[1] = ((self.k[1] + (self.k[0] & 0xff)) * 0x08088405 + 1) & 0xffffffff
        self.k[2] = c32(self.k[2], (self.k[1] >> 24) & 0xff)
    def db(self):
        t = (self.k[2] & 0xffff) | 3
        return ((t * (t ^ 1)) >> 8) & 0xff
    def enc(self, d):
        o = bytearray()
        for p in d:
            o.append(p ^ self.db()); self.upd(p)
        return bytes(o)
    def dec(self, d):
        o = bytearray()
        for c in d:
            p = (c ^ self.db()) & 0xff; self.upd(p); o.append(p)
        return bytes(o)

def make_block(pw, ctype):
    content = os.urandom(random.randint(80, 320))
    crc = zlib.crc32(content) & 0xffffffff
    if ctype == 8:
        co = zlib.compressobj(6, zlib.DEFLATED, -15)   # raw deflate
        stream = co.compress(content) + co.flush()
    else:
        stream = content
    hdr = bytearray(os.urandom(12))
    hdr[10] = (crc >> 16) & 0xff
    hdr[11] = (crc >> 24) & 0xff
    enc = ZC(pw).enc(bytes(hdr) + stream)
    dlen = len(enc)
    csum = (crc >> 16) & 0xffff
    # data_type_enum 2 block: 2*magic*clen*ulen*crc*off*aoff*ctype*dlen*csum_crc*csum_ts*data
    # NOTE: hashcat's encoder prints crc/clen/ulen/off/aoff with %x (no zero pad),
    # so match that exactly or the re-encoded hash won't round-trip (test.sh "not matched").
    return "2*0*%x*%x*%x*0*%x*%d*%x*%04x*%04x*%s" % (
        dlen, len(content), crc, dlen, ctype, dlen, csum, csum, enc.hex())

def container(mode):
    if mode == 17210:
        return [0]
    if mode == 17200:
        return [8]
    if mode == 17220:
        return [8] * random.randint(2, 8)
    if mode == 17225:
        n = random.randint(3, 8)
        cts = [random.choice([0, 8]) for _ in range(n)]
        cts[0] = 0; cts[1] = 8          # guarantee a genuine mix
        return cts
    if mode == 17230:
        return [8] * random.randint(3, 8)
    return [8]

def build(pw, mode):
    cts = container(mode)
    blocks = "*".join(make_block(pw, ct) for ct in cts)
    return "$pkzip2$%d*1*%s*$/pkzip2$" % (len(cts), blocks)

def parse(line):
    core = line
    if not core.startswith("$pkzip2$"):
        raise ValueError("sig")
    core = core[len("$pkzip2$"):]
    if core.endswith("*$/pkzip2$"):
        core = core[:-len("*$/pkzip2$")]
    t = core.split("*")
    n = int(t[0]); i = 2                 # skip count, checksum_size
    files = []
    for _ in range(n):
        dtype = int(t[i]); i += 2        # dtype, magic
        crc = 0
        if dtype > 1:
            crc = int(t[i + 2], 16); i += 5   # clen, ulen, crc, off, aoff
        ctype = int(t[i]); i += 2        # ctype, dlen
        i += 2                           # csum_crc, csum_ts (v2)
        data = bytes.fromhex(t[i]); i += 1
        files.append((ctype, crc, data))
    return files

def verify(pw, line):
    try:
        files = parse(line)
    except Exception:
        return False
    for ctype, crc, enc in files:
        dec = ZC(pw).dec(enc)
        if dec[11] != ((crc >> 24) & 0xff):
            return False
        body = dec[12:]
        if ctype == 8:
            try:
                body = zlib.decompressobj(-15).decompress(body)
            except Exception:
                return False
        if (zlib.crc32(body) & 0xffffffff) != crc:
            return False
    return True

action = sys.argv[1]
pw     = bytes.fromhex(sys.argv[2])
if action == "gen":
    sys.stdout.write(build(pw, int(sys.argv[3])))
else:
    sys.stdout.write("1" if verify(pw, sys.argv[3]) else "0")
PYCODE

sub _run
{
  my @args = @_;
  my $out = do
  {
    local $ENV{PYTHONUTF8} = 1;
    open (my $fh, "-|", "python3", "-c", $PY, @args) or return undef;
    local $/; my $r = <$fh>; close ($fh); $r;
  };
  return $out;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $word_hex = unpack ("H*", $word);

  my $hash = _run ("gen", $word_hex, $MODE);

  return unless defined $hash;

  $hash =~ s/[\r\n]//g;

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = rindex ($line, ':');
  return if $idx < 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);
  my $word_hex    = unpack ("H*", $word_packed);

  my $ok = _run ("verify", $word_hex, $hash);

  return unless defined $ok;

  $ok =~ s/[\r\n]//g;

  return unless $ok eq "1";

  return ($hash, $word);
}

1;

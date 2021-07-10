#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA;
use Crypt::CBC;
use Encode;

sub module_constraints { [[0, 128], [8, 8], [0, 20], [8, 8], [-1, -1]] }

my $ITERATIONS = 0x40000;

my $FIXED_RAW_STRING = pack ("H*", "c43d7b00400700000000000000000000");

my $SHA1C00 = 0x5a827999;
my $SHA1C01 = 0x6ed9eba1;
my $SHA1C02 = 0x8f1bbcdc;
my $SHA1C03 = 0xca62c1d6;

my $SHA1M_A = 0x67452301;
my $SHA1M_B = 0xefcdab89;
my $SHA1M_C = 0x98badcfe;
my $SHA1M_D = 0x10325476;
my $SHA1M_E = 0xc3d2e1f0;

sub rotl32
{
  my $x = shift;
  my $n = shift;

  return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff;
}

sub blk
{
  my $b = shift;
  my $i = shift;

  $$b[$i & 15] = rotl32 ($$b[($i + 13) & 15] ^
                         $$b[($i +  8) & 15] ^
                         $$b[($i +  2) & 15] ^
                         $$b[($i +  0) & 15], 1);

  return $$b[$i & 15];
}

sub R0
{
  my ($b, $v, $w, $x, $y, $z, $i) = @_;

  $$b[$i] = unpack ("L<", pack ("L>", $$b[$i])); # blk0 or just swap_byte32 ()

  $z += (($w & ($x ^ $y)) ^ $y) + $$b[$i] + $SHA1C00 + rotl32 ($v, 5);

  $z &= 0xffffffff;

  $w = rotl32 ($w, 30);

  return ($z, $w);
}

sub R1
{
  my ($b, $v, $w, $x, $y, $z, $i) = @_;

  $z += (($w & ($x ^ $y)) ^ $y) + blk ($b, $i) + $SHA1C00 + rotl32 ($v, 5);

  $z &= 0xffffffff;

  $w = rotl32 ($w, 30);

  return ($z, $w);
}

sub R2
{
  my ($b, $v, $w, $x, $y, $z, $i) = @_;

  $z += ($w ^ $x ^ $y) + blk ($b, $i) + $SHA1C01 + rotl32 ($v, 5);

  $z &= 0xffffffff;

  $w = rotl32 ($w, 30);

  return ($z, $w);
}

sub R3
{
  my ($b, $v, $w, $x, $y, $z, $i) = @_;

  $z += ((($w | $x) & $y) | ($w & $x)) + blk ($b, $i) + $SHA1C02 + rotl32 ($v, 5);

  $z &= 0xffffffff;

  $w = rotl32 ($w, 30);

  return ($z, $w);
}

sub R4
{
  my ($b, $v, $w, $x, $y, $z, $i) = @_;

  $z += ($w ^ $x ^ $y) + blk ($b, $i) + $SHA1C03 + rotl32 ($v, 5);

  $z &= 0xffffffff;

  $w = rotl32 ($w, 30);

  return ($z, $w);
}

sub sha1_transform
{
  my ($state, $buffer) = @_;

  my @block = unpack ("L<*", $$buffer);

  my $a = $$state[0];
  my $b = $$state[1];
  my $c = $$state[2];
  my $d = $$state[3];
  my $e = $$state[4];

  ($e, $b) = R0 (\@block, $a, $b, $c, $d, $e,  0);
  ($d, $a) = R0 (\@block, $e, $a, $b, $c, $d,  1);
  ($c, $e) = R0 (\@block, $d, $e, $a, $b, $c,  2);
  ($b, $d) = R0 (\@block, $c, $d, $e, $a, $b,  3);

  ($a, $c) = R0 (\@block, $b, $c, $d, $e, $a,  4);
  ($e, $b) = R0 (\@block, $a, $b, $c, $d, $e,  5);
  ($d, $a) = R0 (\@block, $e, $a, $b, $c, $d,  6);
  ($c, $e) = R0 (\@block, $d, $e, $a, $b, $c,  7);

  ($b, $d) = R0 (\@block, $c, $d, $e, $a, $b,  8);
  ($a, $c) = R0 (\@block, $b, $c, $d, $e, $a,  9);
  ($e, $b) = R0 (\@block, $a, $b, $c, $d, $e, 10);
  ($d, $a) = R0 (\@block, $e, $a, $b, $c, $d, 11);

  ($c, $e) = R0 (\@block, $d, $e, $a, $b, $c, 12);
  ($b, $d) = R0 (\@block, $c, $d, $e, $a, $b, 13);
  ($a, $c) = R0 (\@block, $b, $c, $d, $e, $a, 14);
  ($e, $b) = R0 (\@block, $a, $b, $c, $d, $e, 15);

  ($d, $a) = R1 (\@block, $e, $a, $b, $c, $d, 16);
  ($c, $e) = R1 (\@block, $d, $e, $a, $b, $c, 17);
  ($b, $d) = R1 (\@block, $c, $d, $e, $a, $b, 18);
  ($a, $c) = R1 (\@block, $b, $c, $d, $e, $a, 19);

  ($e, $b) = R2 (\@block, $a, $b, $c, $d, $e, 20);
  ($d, $a) = R2 (\@block, $e, $a, $b, $c, $d, 21);
  ($c, $e) = R2 (\@block, $d, $e, $a, $b, $c, 22);
  ($b, $d) = R2 (\@block, $c, $d, $e, $a, $b, 23);

  ($a, $c) = R2 (\@block, $b, $c, $d, $e, $a, 24);
  ($e, $b) = R2 (\@block, $a, $b, $c, $d, $e, 25);
  ($d, $a) = R2 (\@block, $e, $a, $b, $c, $d, 26);
  ($c, $e) = R2 (\@block, $d, $e, $a, $b, $c, 27);

  ($b, $d) = R2 (\@block, $c, $d, $e, $a, $b, 28);
  ($a, $c) = R2 (\@block, $b, $c, $d, $e, $a, 29);
  ($e, $b) = R2 (\@block, $a, $b, $c, $d, $e, 30);
  ($d, $a) = R2 (\@block, $e, $a, $b, $c, $d, 31);

  ($c, $e) = R2 (\@block, $d, $e, $a, $b, $c, 32);
  ($b, $d) = R2 (\@block, $c, $d, $e, $a, $b, 33);
  ($a, $c) = R2 (\@block, $b, $c, $d, $e, $a, 34);
  ($e, $b) = R2 (\@block, $a, $b, $c, $d, $e, 35);

  ($d, $a) = R2 (\@block, $e, $a, $b, $c, $d, 36);
  ($c, $e) = R2 (\@block, $d, $e, $a, $b, $c, 37);
  ($b, $d) = R2 (\@block, $c, $d, $e, $a, $b, 38);
  ($a, $c) = R2 (\@block, $b, $c, $d, $e, $a, 39);

  ($e, $b) = R3 (\@block, $a, $b, $c, $d, $e, 40);
  ($d, $a) = R3 (\@block, $e, $a, $b, $c, $d, 41);
  ($c, $e) = R3 (\@block, $d, $e, $a, $b, $c, 42);
  ($b, $d) = R3 (\@block, $c, $d, $e, $a, $b, 43);

  ($a, $c) = R3 (\@block, $b, $c, $d, $e, $a, 44);
  ($e, $b) = R3 (\@block, $a, $b, $c, $d, $e, 45);
  ($d, $a) = R3 (\@block, $e, $a, $b, $c, $d, 46);
  ($c, $e) = R3 (\@block, $d, $e, $a, $b, $c, 47);

  ($b, $d) = R3 (\@block, $c, $d, $e, $a, $b, 48);
  ($a, $c) = R3 (\@block, $b, $c, $d, $e, $a, 49);
  ($e, $b) = R3 (\@block, $a, $b, $c, $d, $e, 50);
  ($d, $a) = R3 (\@block, $e, $a, $b, $c, $d, 51);

  ($c, $e) = R3 (\@block, $d, $e, $a, $b, $c, 52);
  ($b, $d) = R3 (\@block, $c, $d, $e, $a, $b, 53);
  ($a, $c) = R3 (\@block, $b, $c, $d, $e, $a, 54);
  ($e, $b) = R3 (\@block, $a, $b, $c, $d, $e, 55);

  ($d, $a) = R3 (\@block, $e, $a, $b, $c, $d, 56);
  ($c, $e) = R3 (\@block, $d, $e, $a, $b, $c, 57);
  ($b, $d) = R3 (\@block, $c, $d, $e, $a, $b, 58);
  ($a, $c) = R3 (\@block, $b, $c, $d, $e, $a, 59);

  ($e, $b) = R4 (\@block, $a, $b, $c, $d, $e, 60);
  ($d, $a) = R4 (\@block, $e, $a, $b, $c, $d, 61);
  ($c, $e) = R4 (\@block, $d, $e, $a, $b, $c, 62);
  ($b, $d) = R4 (\@block, $c, $d, $e, $a, $b, 63);

  ($a, $c) = R4 (\@block, $b, $c, $d, $e, $a, 64);
  ($e, $b) = R4 (\@block, $a, $b, $c, $d, $e, 65);
  ($d, $a) = R4 (\@block, $e, $a, $b, $c, $d, 66);
  ($c, $e) = R4 (\@block, $d, $e, $a, $b, $c, 67);

  ($b, $d) = R4 (\@block, $c, $d, $e, $a, $b, 68);
  ($a, $c) = R4 (\@block, $b, $c, $d, $e, $a, 69);
  ($e, $b) = R4 (\@block, $a, $b, $c, $d, $e, 70);
  ($d, $a) = R4 (\@block, $e, $a, $b, $c, $d, 71);

  ($c, $e) = R4 (\@block, $d, $e, $a, $b, $c, 72);
  ($b, $d) = R4 (\@block, $c, $d, $e, $a, $b, 73);
  ($a, $c) = R4 (\@block, $b, $c, $d, $e, $a, 74);
  ($e, $b) = R4 (\@block, $a, $b, $c, $d, $e, 75);

  ($d, $a) = R4 (\@block, $e, $a, $b, $c, $d, 76);
  ($c, $e) = R4 (\@block, $d, $e, $a, $b, $c, 77);
  ($b, $d) = R4 (\@block, $c, $d, $e, $a, $b, 78);
  ($a, $c) = R4 (\@block, $b, $c, $d, $e, $a, 79);

  $$state[0] = ($$state[0] + $a) & 0xffffffff;
  $$state[1] = ($$state[1] + $b) & 0xffffffff;
  $$state[2] = ($$state[2] + $c) & 0xffffffff;
  $$state[3] = ($$state[3] + $d) & 0xffffffff;
  $$state[4] = ($$state[4] + $e) & 0xffffffff;

  $$buffer = pack ("L<*", @block);
}

sub sha1_getstate
{
  my $ctx = shift;

  my $info = $ctx->getstate;

  # state:

  my $idx = index ($info, "H:");

  my $state = substr ($info, $idx + 2, 44);

  $state =~ s/://g;

  my @state_arr = unpack ("L>*", pack ("H*", $state));

  # block:

  $idx = index ($info, "block:");

  my $block = substr ($info, $idx + 6, 191);

  $block =~ s/://g;

  $block = pack ("H*", $block);


  return (\@state_arr, $block);
}

sub sha1_update_rar29
{
  my $ctx   = shift;
  my $data  = shift;
  my $len   = shift;
  my $count = shift;

  my $ctx_orig = $ctx->clone;

  $ctx->add ($$data);


  # two early exits from this function, if (strange data) manipulation is not needed:

  my $j = $count & 63;

  return if (($j + $len) <= 63);


  my $i = 64 - $j;

  return if (($i + 63) >= $len);


  # proceed with updating $data:

  my ($state, $block) = sha1_getstate ($ctx_orig);


  substr ($block, $j, $i) = substr ($$data, 0, $i);

  sha1_transform ($state, \$block);


  while (($i + 63) < $len)
  {
    my $workspace = substr ($$data, $i, 64);

    sha1_transform ($state, \$workspace);

    substr ($$data, $i, 64) = $workspace;

    $i += 64;
  }
}

sub module_generate_hash
{
  my $pass = shift;
  my $salt = shift;

  # convert to utf16le:

  my $buf = encode ("UTF-16LE", $pass);

  # add the salt to the password buffer:

  $buf .= $salt;

  my $len = length ($buf);

  my $count = 0;

  my $ctx = Digest::SHA->new ('SHA1');

  my $iv = "";

  # main loop:

  for (my $i = 0; $i < $ITERATIONS; $i++)
  {
    sha1_update_rar29 ($ctx, \$buf, $len, $count);

    $count += $len;

    my $pos = substr (pack ("L<", $i), 0, 3);

    $ctx->add ($pos);

    $count += 3;

    if (($i & 0x3fff) == 0)
    {
      my $dgst = $ctx->clone->digest;

      $iv .= substr ($dgst, 19, 1);
    }
  }

  my $k = $ctx->digest;

  $k = pack ("L<*", unpack ("L>4", $k)); # byte swap the first 4 * 4 = 16 bytes

  my $aes = Crypt::CBC->new (
    -cipher      => "Crypt::Rijndael",
    -key         => $k,
    -iv          => $iv,
    -keysize     => 16,
    -literal_key => 1,
    -header      => 'none');

  my $hash = $aes->encrypt ($FIXED_RAW_STRING);

  return sprintf ("\$RAR3\$*0*%s*%s", unpack ("H*", $salt), unpack ("H*", substr ($hash, 0, 16)));
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return if ($idx < 1);

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return if (substr ($hash, 0, 9) ne "\$RAR3\$*0*");

  $idx = index ($hash, '*', 9);

  return if ($idx < 1);

  my $salt = substr ($hash, 9, $idx - 9);

  $salt = pack ("H*", $salt);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;

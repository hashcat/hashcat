#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

my $LOTUS_MAGIC_TABLE =
[
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c,
  0x1b, 0x33, 0xfd, 0xd0, 0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a, 0x41, 0x9f, 0xe1, 0xd9,
  0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0,
  0xa6, 0x3f, 0xd8, 0x0c, 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60, 0x48, 0xe6, 0x1e, 0x53,
  0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12,
  0xba, 0x3c, 0x06, 0x4e, 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf, 0x3a, 0xde, 0x96, 0x0e,
  0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02,
  0x75, 0xd5, 0x61, 0xe3, 0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c, 0xb4, 0xc5, 0xcc, 0x70,
  0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b,
  0x82, 0xf9, 0x40, 0xb5, 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5, 0x64, 0x6d, 0x7a, 0xd4,
  0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9,
  0x4c, 0xff, 0x43, 0xab
];

sub pad16
{
  my $block_ref = shift;

  my $offset = shift;

  my $value = 16 - $offset;

  for (my $i = $offset; $i < 16; $i++)
  {
    push @{$block_ref}, $value;
  }
}

sub lotus_mix
{
  my $in_ref = shift;

  my $p = 0;

  for (my $i = 0; $i < 18; $i++)
  {
    for (my $j = 0; $j < 48; $j++)
    {
      $p = ($p + 48 - $j) & 0xff;

      my $c = $LOTUS_MAGIC_TABLE->[$p];

      $p = $in_ref->[$j] ^ $c;

      $in_ref->[$j] = $p;
    }
  }
}

sub lotus_transform_password
{
  my $in_ref  = shift;
  my $out_ref = shift;

  my $t = $out_ref->[15];

  for (my $i = 0; $i < 16; $i++)
  {
    $t ^= $in_ref->[$i];

    my $c = $LOTUS_MAGIC_TABLE->[$t];

    $out_ref->[$i] ^= $c;

    $t = $out_ref->[$i];
  }
}

sub mdtransform_norecalc
{
  my $state_ref = shift;
  my $block_ref = shift;

  my @x;

  push (@x, @{$state_ref});
  push (@x, @{$block_ref});

  for (my $i = 0; $i < 16; $i++)
  {
    push (@x, $x[0 + $i] ^ $x[16 + $i]);
  }

  lotus_mix (\@x);

  for (my $i = 0; $i < 16; $i++)
  {
    $state_ref->[$i] = $x[$i];
  }
}

sub mdtransform
{
  my $state_ref    = shift;
  my $checksum_ref = shift;
  my $block_ref    = shift;

  mdtransform_norecalc ($state_ref, $block_ref);

  lotus_transform_password ($block_ref, $checksum_ref);
}

sub domino_big_md
{
  my $saved_key_ref = shift;

  my $size = shift;

  @{$saved_key_ref} = splice (@{$saved_key_ref}, 0, $size);

  my @state = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  my @checksum;

  my $curpos;

  for ($curpos = 0; $curpos + 16 < $size; $curpos += 16)
  {
    my @block = splice (@{$saved_key_ref}, 0, 16);

    mdtransform (\@state, \@checksum, \@block);
  }

  my $left = $size - $curpos;

  my @block = splice (@{$saved_key_ref}, 0, 16);

  pad16 (\@block, $left);

  mdtransform (\@state, \@checksum, \@block);

  mdtransform_norecalc (\@state, \@checksum);

  return @state;
}

sub domino_85x_encode
{
  my $final = shift;
  my $char  = shift;

  my $byte10 = (ord (substr ($final, 3, 1)) + 4);

  if ($byte10 > 255)
  {
    $byte10 = $byte10 - 256;
  }

  substr ($final, 3, 1) = chr ($byte10);

  my $passwd = "";

  $passwd .= domino_base64_encode ((int (ord (substr ($final,  0, 1))) << 16) | (int (ord (substr ($final,  1, 1))) << 8) | (int (ord (substr ($final,  2, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  3, 1))) << 16) | (int (ord (substr ($final,  4, 1))) << 8) | (int (ord (substr ($final,  5, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  6, 1))) << 16) | (int (ord (substr ($final,  7, 1))) << 8) | (int (ord (substr ($final,  8, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  9, 1))) << 16) | (int (ord (substr ($final, 10, 1))) << 8) | (int (ord (substr ($final, 11, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 12, 1))) << 16) | (int (ord (substr ($final, 13, 1))) << 8) | (int (ord (substr ($final, 14, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 15, 1))) << 16) | (int (ord (substr ($final, 16, 1))) << 8) | (int (ord (substr ($final, 17, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 18, 1))) << 16) | (int (ord (substr ($final, 19, 1))) << 8) | (int (ord (substr ($final, 20, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 21, 1))) << 16) | (int (ord (substr ($final, 22, 1))) << 8) | (int (ord (substr ($final, 23, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 24, 1))) << 16) | (int (ord (substr ($final, 25, 1))) << 8) | (int (ord (substr ($final, 26, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 27, 1))) << 16) | (int (ord (substr ($final, 28, 1))) << 8) | (int (ord (substr ($final, 29, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 30, 1))) << 16) | (int (ord (substr ($final, 31, 1))) << 8) | (int (ord (substr ($final, 32, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 33, 1))) << 16) | (int (ord (substr ($final, 34, 1))) << 8) | (int (ord (substr ($final, 35, 1)))), 4);

  if (defined ($char))
  {
    substr ($passwd, 18, 1) = $char;
  }

  return $passwd;
}

sub domino_85x_decode
{
  my $str = shift;

  my $decoded  = "";

  for (my $i = 0; $i < length ($str); $i += 4)
  {
    my $num = domino_base64_decode (substr ($str, $i, 4), 4);

    $decoded .= chr (($num >> 16) & 0xff) . chr (($num >> 8) & 0xff) . chr ($num & 0xff);
  }

  my $digest;
  my $salt;
  my $iterations = -1;
  my $chars;

  $salt   = substr ($decoded,  0, 16);  # longer than -m 8700 (5 vs 16 <- new)

  my $byte10 = (ord (substr ($salt, 3, 1)) - 4);

  if ($byte10 < 0)
  {
    $byte10 = 256 + $byte10;
  }

  substr ($salt, 3, 1) = chr ($byte10);

  $iterations = substr ($decoded,  16, 10);

  if ($iterations =~ /^?d*$/)
  {
    # continue

    $iterations = $iterations + 0;            # hack: make sure it is an int now (atoi ())
    $chars = substr ($decoded, 26, 2);        # in my example it is "02"
    $digest = substr ($decoded, 28, 8);       # only of length of 8 vs 20 SHA1 bytes
  }

  return ($digest, $salt, $iterations, $chars);
}

sub domino_base64_decode
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

  my $ret = 0;

  my $i = 1;

  while ($i <= $n)
  {
    my $idx = (index ($itoa64, substr ($v, $n - $i, 1))) & 0x3f;

    $ret += ($idx << (6 * ($i - 1)));

    $i = $i + 1;
  }

  return $ret
}

sub domino_base64_encode
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

  my $ret = "";

  while (($n - 1) >= 0)
  {
    $n = $n - 1;

    $ret = substr ($itoa64, $v & 0x3f, 1) . $ret;

    $v = $v >> 6;
  }

  return $ret
}

sub domino_encode
{
  my $final = shift;
  my $char  = shift;

  my $byte10 = (ord (substr ($final, 3, 1)) + 4);

  if ($byte10 > 255)
  {
    $byte10 = $byte10 - 256;
  }

  substr ($final, 3, 1) = chr ($byte10);

  my $passwd = "";

  $passwd .= domino_base64_encode ((int (ord (substr ($final,  0, 1))) << 16) | (int (ord (substr ($final,  1, 1))) << 8) | (int (ord (substr ($final,  2, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  3, 1))) << 16) | (int (ord (substr ($final,  4, 1))) << 8) | (int (ord (substr ($final,  5, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  6, 1))) << 16) | (int (ord (substr ($final,  7, 1))) << 8) | (int (ord (substr ($final,  8, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  9, 1))) << 16) | (int (ord (substr ($final, 10, 1))) << 8) | (int (ord (substr ($final, 11, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 12, 1))) << 16) | (int (ord (substr ($final, 13, 1))) << 8) | (int (ord (substr ($final, 14, 1)))), 4);

  if (defined ($char))
  {
    substr ($passwd, 18, 1) = $char;
  }
  substr ($passwd, 19, 1) = "";

  return $passwd;
}

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 5000;
  my $param = shift;

  my $domino_char = undef;

  # domino 5 hash - SEC_pwddigest_V1 - -m 8600

  my @saved_key = map { ord $_; } split "", $word;

  my $len = scalar @saved_key;

  my @state = domino_big_md (\@saved_key, $len);

  # domino 6 hash - SEC_pwddigest_V2 - -m 8700

  my $salt_part = substr ($salt, 0, 5);

  my $str = "(" . unpack ("H*", join ("", (map { chr $_; } @state))) . ")";

  @saved_key = map { ord $_; } split "", $salt_part . uc $str;

  @state = domino_big_md (\@saved_key, 34);

  my $hash_buf = join ("", (map { chr $_; } @state));

  my $tmp_hash = sprintf ('(G%s)', domino_encode ($salt_part . $hash_buf, $domino_char));

  # domino 8(.5.x) hash - SEC_pwddigest_V3 - -m 9100

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len =>  8,
    salt_len   => 16,
  );

  my $chars = "02";

  if (defined ($param))
  {
    $chars = $param;
  }

  my $digest_new = $pbkdf2->PBKDF2 ($salt, $tmp_hash);

  for (my $i = length ($iter); $i < 10; $i++)
  {
    $iter = "0" . $iter;
  }

  my $hash = sprintf ('(H%s)', domino_85x_encode ($salt . $iter . $chars . $digest_new, $domino_char));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # LOTUS 8
  # split hash and plain
  my $index = index ($line, ":");

  return if $index < 1;

  my $hash_in = substr ($line, 0, $index);

  my $word = substr ($line, $index + 1);

  my $base64_part = substr ($hash_in, 2, -1);

  my (undef, $salt, $iter, $param) = domino_85x_decode ($base64_part);

  return if ($iter < 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter, $param);

  return ($new_hash, $word);
}

1;

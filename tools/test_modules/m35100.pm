#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);

# There is no pure kernel: OpenCL/ carries only m35100-optimized.cl, so hashcat
# falls back to it even under -P and module_pw_max() then caps the password at 15.
# Declaring a pure range here made test.pl generate up to 256 bytes against a
# kernel that cannot take them, and every long candidate was skipped as too long.

sub module_constraints { [[-1, -1], [-1, -1], [0, 15], [0, 20], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $hash_buf;

  if (defined $iter)
  {
    $hash_buf = sm3crypt ($word, $salt, $iter, 1);
  }
  else
  {
    $hash_buf = sm3crypt ($word, $salt, 5000, 0);
  }

  my $hash = sprintf ("%s", $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":", 30);

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  $index1 = index ($hash_in,  ",", 1);

  my $index2 = index ($hash_in, "\$", 1);

  if ($index1 != -1)
  {
    if ($index1 < $index2)
    {
      $index2 = $index1;
    }
  }

  #$param = substr ($hash_in, $index2, 1);

  $index2++;

  # rounds= if available
  my $iter;

  if (substr ($hash_in, $index2, 7) eq "rounds=")
  {
    my $old_index = $index2;

    $index2 = index ($hash_in, "\$", $index2 + 1);

    return if $index2 < 1;

    $iter = substr ($hash_in, $old_index + 7, $index2 - $old_index - 7);

    $index2++;
  }

  # get salt
  my $index3 = rindex ($hash_in, "\$");

  return if $index3 < 1;

  my $salt = substr ($hash_in, $index2, $index3 - $index2);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

# This is a modified sha_crypts () function of pass_gen.pl from
# https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/pass_gen.pl

# Copyright: https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/doc/pass_gen.Manifest
# public domain
# written by Jim Fougeron

# updated for new MySQL hashes by philsmd
# modified date: February 2020
# license: public domain

my @i64 = ('.', '/', '0'..'9', 'A'..'Z', 'a'..'z');

sub to64
{
  my $v = shift;
  my $n = shift;

  my $str;

  while (--$n >= 0)
  {
    $str .= $i64[$v & 0x3F];

    $v >>= 6;
  }

  return $str;
}

sub sm3crypts
{
  my ($bits, $key, $salt, $loops) = @_;

  my $bytes = $bits / 8;

  my $data_base64 = encode_base64 ($key . $salt . $key, "");

  my $python_code = <<'END_CODE';

import hashlib
import base64

data_raw = base64.b64decode (sm3_data)

m = hashlib.new ("sm3")
m.update (data_raw)
r = m.hexdigest ()

print (r)

END_CODE

  # replace code with these values

  $python_code =~ s/sm3_data/"$data_base64"/;

  my $b = `python3 -c '$python_code'`;

  $b =~ s/[\r\n]//g;
  $b = pack ("H*", $b);

  # Add for any character in the key one byte of the alternate sum.

  my $tmp = $key . $salt;

  for (my $i = length ($key); $i > 0; $i -= $bytes)
  {
    if ($i > $bytes)
    {
      $tmp .= $b;
    }
    else
    {
      $tmp .= substr ($b, 0, $i);
    }
  }

  # Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.

  for (my $i = length ($key); $i > 0; $i >>= 1)
  {
    if (($i & 1) != 0)
    {
      $tmp .= $b;
    }
    else
    {
      $tmp .= $key;
    }
  }

  $data_base64 = encode_base64 ($tmp, "");

  $python_code = <<'END_CODE';

import hashlib
import base64

data_raw = base64.b64decode (sm3_data)

m = hashlib.new ("sm3")
m.update (data_raw)
r = m.hexdigest ()

print (r)

END_CODE

  # replace code with these values

  $python_code =~ s/sm3_data/"$data_base64"/;

  my $a = `python3 -c '$python_code'`;

  $a =~ s/[\r\n]//g;
  $a = pack ("H*", $a);

  # NOTE, this will be the 'initial' $c value in the inner loop.

  # For every character in the password add the entire password.  produces DP

  $tmp = "";

  for (my $i = 0; $i < length ($key); $i++)
  {
    $tmp .= $key;
  }

  $data_base64 = encode_base64 ($tmp, "");

  $python_code = <<'END_CODE';

import hashlib
import base64

data_raw = base64.b64decode (sm3_data)

m = hashlib.new ("sm3")
m.update (data_raw)
r = m.hexdigest ()

print (r)

END_CODE

  # replace code with these values

  $python_code =~ s/sm3_data/"$data_base64"/;

  my $dp = `python3 -c '$python_code'`;

  $dp =~ s/[\r\n]//g;
  $dp = pack ("H*", $dp);

  # Create byte sequence P

  my $p = "";

  for (my $i = length ($key); $i > 0; $i -= $bytes)
  {
    if ($i > $bytes)
    {
      $p .= $dp;
    }
    else
    {
      $p .= substr ($dp, 0, $i);
    }
  }

  # produce ds

  $tmp = "";

  my $til = 16 + ord (substr ($a, 0, 1));

  for (my $i = 0; $i < $til; $i++)
  {
    $tmp .= $salt;
  }

  $data_base64 = encode_base64 ($tmp, "");

  $python_code = <<'END_CODE';

import hashlib
import base64

data_raw = base64.b64decode (sm3_data)

m = hashlib.new ("sm3")
m.update (data_raw)
r = m.hexdigest ()

print (r)

END_CODE

  # replace code with these values

  $python_code =~ s/sm3_data/"$data_base64"/;

  my $ds = `python3 -c '$python_code'`;

  $ds =~ s/[\r\n]//g;
  $ds = pack ("H*", $ds);

  # Create byte sequence S

  my $s = "";

  for (my $i = length ($salt); $i > 0; $i -= $bytes)
  {
    if ($i > $bytes)
    {
      $s .= $ds;
    }
    else
    {
      $s .= substr ($ds, 0, $i);
    }
  }

  my $c = $a; # Ok, we saved this, which will 'seed' our crypt value here in the loop.

  # now we do 5000 iterations of SHA2 (256 or 512)

  my $tmp_base64 = encode_base64 ($tmp, "");

  my $p_base64 = encode_base64 ($p, "");
  my $c_base64 = encode_base64 ($c, "");
  my $s_base64 = encode_base64 ($s, "");

  $python_code = <<'END_CODE';
import hashlib
import base64

tmp = base64.b64decode (tmp_data)
p   = base64.b64decode (p_data)
c   = base64.b64decode (c_data)
s   = base64.b64decode (s_data)

loops = loops_data

i = 0

while i < loops:
  if (i & 1):
    tmp = p
  else:
    tmp = c

  if (i % 3):
    tmp += s
  if (i % 7):
    tmp += p

  if (i & 1):
    tmp += c
  else:
    tmp += p

  m = hashlib.new ("sm3")
  m.update (tmp)
  c = m.digest ()

  i += 1

print (base64.b64encode (c))

END_CODE

  # replace code with these values

  $python_code =~ s/tmp_data/"$tmp_base64"/;
  $python_code =~ s/p_data/"$p_base64"/;
  $python_code =~ s/c_data/"$c_base64"/;
  $python_code =~ s/s_data/"$s_base64"/;
  $python_code =~ s/loops_data/$loops/;

  $c = `python3 -c '$python_code'`;

  $c =~ s/^b'//g;
  $c =~ s/'//g;
  $c =~ s/[\r\n]//g;

  $c = decode_base64 ($c);

  my $inc1; my $inc2; my $mod; my $end;

  if ($bits == 256) { $inc1 = 10; $inc2 = 21; $mod = 30; $end =  0; }
  else              { $inc1 = 21; $inc2 = 22; $mod = 63; $end = 21; }

  my $i = 0;
  $tmp = "";

  do
  {
    $tmp .= to64 ((ord (substr ($c, $i, 1)) << 16) | (ord (substr ($c, ($i + $inc1) % $mod, 1)) << 8) | ord (substr ($c, ($i + $inc1 * 2) % $mod, 1)), 4);
    $i = ($i + $inc2) % $mod;
  } while ($i != $end);

  if ($bits == 256) { $tmp .= to64 ((ord (substr ($c, 31, 1)) << 8) | ord (substr ($c, 30, 1)), 3); }
  else              { $tmp .= to64  (ord (substr ($c, 63, 1)), 2); }

  return $tmp;
}

sub sm3crypt
{
  my $pass   = shift;
  my $salt   = shift;
  my $iter   = shift;
  my $rounds = shift;

  my $bin = sm3crypts (256, $pass, $salt, $iter);

  if ($rounds == 1)
  {
    return "\$sm3\$rounds=$iter\$" . $salt . "\$$bin";
  }
  else
  {
    return "\$sm3\$" . $salt . "\$$bin";
  }
}

1;

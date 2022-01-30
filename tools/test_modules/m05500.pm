#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Authen::Passphrase::NTHash;
use Digest::MD5 qw (md5);
use Crypt::ECB;

sub setup_des_key
{
  my @key_56 = split (//, shift);

  my $key = "";

  $key = $key_56[0];

  $key .= chr (((ord ($key_56[0]) << 7) | (ord ($key_56[1]) >> 1)) & 255);
  $key .= chr (((ord ($key_56[1]) << 6) | (ord ($key_56[2]) >> 2)) & 255);
  $key .= chr (((ord ($key_56[2]) << 5) | (ord ($key_56[3]) >> 3)) & 255);
  $key .= chr (((ord ($key_56[3]) << 4) | (ord ($key_56[4]) >> 4)) & 255);
  $key .= chr (((ord ($key_56[4]) << 3) | (ord ($key_56[5]) >> 5)) & 255);
  $key .= chr (((ord ($key_56[5]) << 2) | (ord ($key_56[6]) >> 6)) & 255);
  $key .= chr (( ord ($key_56[6]) << 1) & 255);

  return $key;
}

sub get_random_netntlmv1_salt
{
  my $len_user   = shift;
  my $len_domain = shift;

  my $char;
  my $type;
  my $user = "";

  for (my $i = 0; $i < $len_user; $i++)
  {
    $type = random_number (1, 3);

    if ($type == 1)
    {
      $char = random_numeric_string (1);
    }
    elsif ($type == 2)
    {
      $char = random_uppercase_string (1);
    }
    else
    {
      $char = random_lowercase_string (1);
    }

    $user .= $char;
  }

  my $domain = "";

  for (my $i = 0; $i < $len_domain; $i++)
  {
    $type = random_number (1, 3);

    if ($type == 1)
    {
      $char = random_numeric_string (1);
    }
    elsif ($type == 2)
    {
      $char = random_uppercase_string (1);
    }
    else
    {
      $char = random_lowercase_string (1);
    }

    $domain .= $char;
  }

  my $c_challenge = random_bytes (8);
  my $s_challenge = random_bytes (8);

  my $salt_buf = $user . "::" . $domain . ":" . unpack ("H*", $c_challenge) . unpack ("H*", $s_challenge);

  return $salt_buf;
}

sub module_constraints { [[0, 127], [-1, -1], [0, 27], [-1, -1], [-1, -1]] } # room for improvement in pure kernel mode

sub module_generate_hash
{
  my $word   = shift;
  my $unused = shift;
  my $salt   = shift // get_random_netntlmv1_salt (random_number (0, 15), random_number (0, 15));

  my $index1 = index  ($salt, "::");
  my $user   = substr ($salt, 0, $index1);

  my $index2 = index  ($salt, ":", $index1 + 2);
  my $domain = substr ($salt, $index1 + 2, $index2 - $index1 - 2);

  my $len = length (substr ($salt, $index2 + 1));

  my $c_challenge_hex;

  if ($len > 32)
  {
    $c_challenge_hex = substr ($salt, $index2 +  1, 48);
    $index2 += 32;
  }
  else
  {
    $c_challenge_hex  = substr ($salt, $index2 +  1, 16);
    $c_challenge_hex .= 00 x 32;
  }

  my $c_challenge     = pack   ("H*", substr ($c_challenge_hex, 0, 16));
  my $s_challenge_hex = substr ($salt, $index2 + 17, 16);
  my $s_challenge     = pack   ("H*", $s_challenge_hex);

  my $challenge = substr (md5 ($s_challenge . $c_challenge), 0, 8);

  my $ntresp;

  my $nthash = Authen::Passphrase::NTHash->new (passphrase => $word)->hash . "\x00" x 5;

  $ntresp .= Crypt::ECB::encrypt (setup_des_key (substr ($nthash,  0, 7)), "DES", $challenge, "none");
  $ntresp .= Crypt::ECB::encrypt (setup_des_key (substr ($nthash,  7, 7)), "DES", $challenge, "none");
  $ntresp .= Crypt::ECB::encrypt (setup_des_key (substr ($nthash, 14, 7)), "DES", $challenge, "none");

  my $tmp_hash = sprintf ("%s::%s:%s:%s:%s", $user, $domain, $c_challenge_hex, unpack ("H*", $ntresp), $s_challenge_hex);

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, "::");

  return if $index1 < 1;

  my $index2 = index ($line, ":", $index1 + 2);

  return if $index2 < 1;

  $index2 = index ($line, ":", $index2 + 1);

  return if $index2 < 1;

  my $salt = substr ($line, 0, $index2 - 32);

  $index2 = index ($line, ":", $index2 + 1);

  return if $index2 < 1;

  $salt .= substr ($line, $index2 + 1, 16);

  my $word = substr ($line, $index2 + 1 + 16 + 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $salt);

  return ($new_hash, $word);
}

1;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha512);
use Crypt::CBC;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $ckey       = shift // random_hex_string (96);
  my $public_key = shift // random_hex_string (66);
  my $salt_iter  = shift // random_number (150000, 250000);
  my $cry_master = shift;

  my $digest = sha512 ($word . pack ("H*", $salt));

  for (my $i = 1; $i < $salt_iter; $i++)
  {
    $digest = sha512 ($digest);
  }

  my $data = "";

  if (! defined ($cry_master))
  {
    $data = random_hex_string (32);
  }
  else
  {
    my $aes = Crypt::CBC->new ({
      key         => substr ($digest,  0, 32),
      cipher      => "Crypt::Rijndael",
      iv          => substr ($digest, 32, 16),
      literal_key => 1,
      header      => "none",
      keysize     => 32,
      padding     => "none",
    });

    $data = $aes->decrypt (pack ("H*", $cry_master));

    if ($data =~ m/\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10$/)
    {
      # remove padding:

      $data = substr ($data, 0, -16);
    }
    elsif ($data =~ m/\x08\x08\x08\x08\x08\x08\x08\x08$/)
    {
      # remove padding:

      $data = substr ($data, 0, -8);
    }
    else
    {
      $data = "WRONG"; # fake
    }
  }

  my $aes = Crypt::CBC->new ({
    key         => substr ($digest,  0, 32),
    cipher      => "Crypt::Rijndael",
    iv          => substr ($digest, 32, 16),
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "standard",
  });

  $cry_master = unpack ("H*", $aes->encrypt ($data));

  my $hash = sprintf ('$bitcoin$%d$%s$%d$%s$%d$%d$%s$%d$%s',
    length ($cry_master),
    $cry_master,
    length ($salt),
    $salt,
    $salt_iter,
    length ($ckey),
    $ckey,
    length ($public_key),
    $public_key);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 9) eq "\$bitcoin\$");

  my $split_idx = index ($line, ":");

  return if ($split_idx < 1);

  my $hash = substr ($line, 0, $split_idx);
  my $word = substr ($line, $split_idx + 1);

  # cry_master length

  my $idx1 = index ($hash, "\$", 9);

  return if ($idx1 < 1);

  my $cry_master_len = substr ($hash, 9, $idx1 - 9);

  # cry_master

  my $idx2 = index ($hash, "\$", $idx1 + 1);

  return if ($idx2 < 1);

  my $cry_master = substr ($hash, $idx1 + 1,  $idx2 - $idx1 - 1);

  return unless ($cry_master =~ m/^[0-9a-fA-F]+$/);

  # salt length

  $idx1 = index ($hash, "\$", $idx2 + 1);

  return if ($idx1 < 1);

  my $salt_len = substr ($hash, $idx2 + 1,  $idx1 - $idx2 - 1);

  # salt

  $idx2 = index ($hash, "\$", $idx1 + 1);

  return if ($idx2 < 1);

  my $salt = substr ($hash, $idx1 + 1,  $idx2 - $idx1 - 1);

  return unless ($salt =~ m/^[0-9a-fA-F]+$/);

  # salt iter

  $idx1 = index ($hash, "\$", $idx2 + 1);

  return if ($idx1 < 1);

  my $salt_iter = substr ($hash, $idx2 + 1,  $idx1 - $idx2 - 1);

  # ckey length

  $idx2 = index ($hash, "\$", $idx1 + 1);

  return if ($idx2 < 1);

  my $ckey_len = substr ($hash, $idx1 + 1,  $idx2 - $idx1 - 1);

  # ckey

  $idx1 = index ($hash, "\$", $idx2 + 1);

  return if ($idx1 < 1);

  my $ckey = substr ($hash, $idx2 + 1,  $idx1 - $idx2 - 1);

  return unless ($ckey =~ m/^[0-9a-fA-F]+$/);

  # public key length

  $idx2 = index ($hash, "\$", $idx1 + 1);

  return if ($idx2 < 1);

  my $public_key_len = substr ($hash, $idx1 + 1,  $idx2 - $idx1 - 1);

  # public key

  my $public_key = substr ($hash, $idx2 + 1);

  return unless ($public_key =~ m/^[0-9a-fA-F]+$/);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $ckey, $public_key, $salt_iter, $cry_master);

  return ($new_hash, $word);
}

1;

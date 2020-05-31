#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1);
use Crypt::CBC;

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word    = shift;
  my $salt    = shift; # unused since unsalted algo
  my $iv      = shift;
  my $data    = shift;
  my $file    = shift;

  my $bit_len = 256;
  my $key_len = $bit_len / 8;

  my $is_decrypt = defined ($data);

  my $padding = "none"; # for decryption we need this to "keep" the padding bytes

  if ($is_decrypt == 0)
  {
    $padding = "standard";

    # generate some additional random hash data:

    my $iv_len = random_number (1, 16);

    $iv = random_bytes ($iv_len);

    $data = random_bytes (128);

    $file = random_lowercase_string (random_number (1, 16));

    $file .= ".txt";
  }

  my $iv_mod = $iv;

  $iv_mod .= "\x00" x (16 - length ($iv_mod));


  # start of main algo:

  my $digest = sha1 ($word);

  my $buf = "";

  for (my $i = 0; $i < 20; $i++)
  {
    $buf .= chr (ord (substr ($digest, $i, 1)) ^ ord ("\x36")); # or  just ^ 0x36
  }

  $buf .= "\x36" x 44;

  my $key = sha1 ($buf);


  $buf = "";

  for (my $i = 0; $i < 20; $i++)
  {
    $buf .= chr (ord (substr ($digest, $i, 1)) ^ ord ("\x5c")); # or  just ^ 0x36
  }

  $buf .= "\x5c" x 44;

  # final key:

  $key = $key . sha1 ($buf);

  $key = substr ($key, 0, $key_len);

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    iv          => $iv_mod,
    keysize     => $key_len,
    literal_key => 1,
    header      => "none",
    padding     => $padding,
  });

  if ($is_decrypt == 0)
  {
    $data = $aes->encrypt ($data);
  }
  else
  {
    my $data_decrypted = $aes->decrypt ($data);

    # the password is wrong if the decrypted data does not have the expected padding bytes:

    if (substr ($data_decrypted, -16) ne "\x10" x 16)
    {
      $data = "fake"; # fake data
    }
  }

  my $iv_padded = $iv;

  if (length ($iv_padded) < 12)
  {
    $iv_padded .= "\x00" x (12 - length ($iv_padded));
  }

  my $hash = sprintf ("\$zip3\$*0*1*%i*0*%s*%s*0*0*0*%s", $bit_len, unpack ("H*", $iv_padded), unpack ("H*", $data), $file);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 11) eq "\$zip3\$*0*1*");

  my $idx1 = index ($line, ":");

  return unless ($idx1 >= 11);

  my $hash = substr ($line, 0, $idx1);
  my $word = substr ($line, $idx1 + 1);

  # bit_len:

  $idx1 = index ($hash, "*", 11);

  return unless ($idx1 > 0);

  my $bit_len = substr ($hash, 11, $idx1 - 11);

  $bit_len = int ($bit_len);

  return unless ($bit_len == 256);

  # unused:

  return unless (substr ($hash, $idx1 + 1, 2) eq "0*");

  # iv:

  my $idx2 = index ($hash, "*", $idx1 + 3);

  return unless ($idx2 > 0);

  my $iv = substr ($hash, $idx1 + 3, $idx2 - $idx1 - 3);

  return unless ($iv =~ m/^[0-9a-fA-F]+$/);
  return unless ((length ($iv) % 2) == 0);

  # data:

  $idx1 = index ($hash, "*", $idx2 + 1);

  return unless ($idx1 > 0);

  my $data = substr ($hash, $idx2 + 1, $idx1 - $idx2 - 1);

  return unless ($data =~ m/^[0-9a-fA-F]+$/);
  return unless ((length ($data) % 2) == 0);

  # unused:

  return unless (substr ($hash, $idx1 + 1, 6) eq "0*0*0*");

  # file:

  my $file = substr ($hash, $idx1 + 7);

  # convert to hex:

  $iv   = pack ("H*", $iv);
  $data = pack ("H*", $data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, "", $iv, $data, $file);

  return ($new_hash, $word);
}

1;

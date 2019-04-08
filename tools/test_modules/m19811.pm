#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);
use Encode;

sub module_constraints { [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift // "";

  my $iter = 1000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter
  );

  my $word_utf16le = encode ("UTF-16LE", $word);

  my $salt_bin = pack ("H*", $salt);

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word_utf16le);

  my $key_main  = encode_base64 (substr ($key,  0, 32), "");
  my $key_tweak = encode_base64 (substr ($key, 32, 32), "");

  my $diskcryptor_data = "";

  $diskcryptor_data .= $salt_bin;

  if (length ($data) == 0) # normal case
  {
    $diskcryptor_data .= "DCRP";

    $diskcryptor_data .= random_bytes (4);

    $diskcryptor_data .= (int (rand (2)) == 1) ? pack ("H*", "02000400") : pack ("H*", "02000500");

    $diskcryptor_data .= "\x00" x (2048 - length ($diskcryptor_data)); # fill it up to 2048 bytes
  }
  else # verify
  {
    # extract the data from the function parameter

    my $data_base64 = encode_base64 (pack ("H*", $data), "");

    # attention: this is the decryption (further down we have the reverse: encryption)

    my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import AES
import base64

aes_key1 = base64.b64decode (key_main)
aes_key2 = base64.b64decode (key_tweak)

xts_key = (aes_key1, aes_key2)

cipher = AES.new (xts_key, AES.MODE_XTS)

sequence = "01".decode ("hex")

data_decrypted = cipher.decrypt (base64.b64decode (diskcryptor_data), sequence)

print data_decrypted.encode ("hex")

END_CODE

    # replace code with these values

    $python_code =~ s/key_main/"$key_main"/;
    $python_code =~ s/key_tweak/"$key_tweak"/;
    $python_code =~ s/diskcryptor_data/"$data_base64"/;

    my $output_buf = `python2 -c '$python_code'`;

    $output_buf =~ s/[\r\n]//g;

    $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

    $output_buf = pack ("H*", $output_buf);

    $diskcryptor_data .= $output_buf;
  }

  $diskcryptor_data = encode_base64 ($diskcryptor_data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import AES
import base64

aes_key1 = base64.b64decode (key_main)
aes_key2 = base64.b64decode (key_tweak)

xts_key = (aes_key1, aes_key2)

cipher = AES.new (xts_key, AES.MODE_XTS)

sequence = "01".decode ("hex")

data_encrypted = cipher.encrypt (base64.b64decode (diskcryptor_data), sequence)

print data_encrypted.encode ("hex")

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/diskcryptor_data/"$diskcryptor_data"/;

  my $hash_buf = `python2 -c '$python_code'`;

  $hash_buf =~ s/[\r\n]//g;

  $hash_buf = substr ($hash_buf, 128); # remove the "garbage" from the start (encrypted salt)

  my $hash = sprintf ("\$diskcryptor\$0*%s%s", $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  return unless (substr ($hash_in, 0, 13) eq "\$diskcryptor\$");

  my $word = substr ($line, $index1 + 1);

  my $index2 = index ($hash_in, "\*", 13);

  return if $index2 < 1;

  my $version = substr ($hash_in, 13, $index2 - 13);

  return unless ($version eq "0");

  my $data = substr ($hash_in, $index2 + 1);

  return unless (length ($data) == 4096);

  my $salt = substr ($data, 0, 128);

  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $data);

  return ($new_hash, $word);
}

1;

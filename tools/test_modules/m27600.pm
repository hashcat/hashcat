#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64);

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub aes_decrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $python_code = <<'END_CODE';

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

key = base64.b64decode (key_main)
tweak = base64.b64decode (key_tweak)

cipher = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=default_backend())
decryptor = cipher.decryptor()

decrypted = decryptor.update(base64.b64decode (data)[0:64])
print (decrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = pack ("H*", $output_buf);

  return $output_buf;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt1 = shift;
  my $iter1 = shift // 160000;
  my $enc_pass = shift // random_hex_string (128);
  my $salt2 = shift // random_hex_string (64);
  my $iter2 = shift // 20000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter1,
    output_len => 64
  );

  my $salt1_bin = pack ("H*", $salt1);

  my $key = $pbkdf2->PBKDF2 ($salt1_bin, $word);

  my $tweak = "\x00" x 16;

  my $key_b64 = encode_base64 ($key, "");
  my $tweak_b64 = encode_base64 ($tweak, "");
  my $enc_pass_b64 = encode_base64 (pack ("H*", $enc_pass), "");

  my $dec_pass = aes_decrypt ($key_b64, $tweak_b64, $enc_pass_b64);

  $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter2,
    output_len => 32
  );

  my $salt2_bin = pack ("H*", $salt2);

  my $hash_buf = $pbkdf2->PBKDF2 ($salt2_bin, $dec_pass);

  my $hash = sprintf ("\$vbox\$0\$%s\$%s\$16\$%s\$%s\$%s\$%s", $iter1, $salt1, $enc_pass, $iter2, $salt2, unpack ("H*", $hash_buf));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 6) eq '$vbox$';

  my (undef, $signature, $version, $iter1, $salt1, $klen, $enc_pass, $iter2, $salt2) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $iter1;
  return unless defined $salt1;
  return unless defined $klen;
  return unless defined $enc_pass;
  return unless defined $iter2;
  return unless defined $salt2;

  return unless ($version eq "0");
  return unless (length $salt1 eq 64);
  return unless ($klen eq "16");
  return unless (length $enc_pass eq 128);
  return unless (length $salt2 eq 64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt1, $iter1, $enc_pass, $salt2, $iter2);

  return ($new_hash, $word);
}

1;

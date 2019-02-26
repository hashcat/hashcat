#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::HMAC qw (hmac_hex);
use Digest::SHA qw (sha256);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word           = shift;
  my $salt_hex       = shift;
  my $ciphertext_hex = shift // random_hex_string (64);

  if (length $salt_hex == 0)
  {
    $salt_hex = random_hex_string (64);
  }

  my $salt_bin       = pack ("H*", $salt_hex);
  my $ciphertext_bin = pack ("H*", $ciphertext_hex);

  # actually 80 but the last 16 bytes are the IV which we don't need
  my $out_len = 64;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => 10000,
    output_len => $out_len
  );

  my $derived_key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $hash_buf = hmac_hex ($ciphertext_bin, substr ($derived_key, 32, 32), \&sha256);

  my $hash = sprintf ('$ansible$0*0*%s*%s*%s', unpack ("H*", $salt_bin), unpack ("H*", $ciphertext_bin), $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split ('\*', $digest);

  return unless scalar @data == 5;

  my ($signature_tmp, $cipher, $salt, $ciphertext, $hmac) = @data;

  my (undef, $signature, undef) = split ('\$', $signature_tmp);

  return unless ($signature eq "ansible");

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $ciphertext);

  return ($new_hash, $word);
}

1;


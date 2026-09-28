#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use Crypt::PBKDF2;
use Encode;

# The optimized kernels widen each byte instead of decoding the UTF-8, and
# module_01000.c:58 documents that as deliberate rather than as a bug, so the two
# kernel families really do disagree on a multi byte password. The oracle follows
# whichever one test.sh is about to run: decoding as latin1 reproduces the
# widening byte for byte, decoding as utf-8 is the conversion the pure kernels do.
# test.sh exports IS_OPTIMIZED from the same value it uses to decide on -O.

my $PW_CHARSET = "latin1";

if (exists $ENV{"IS_OPTIMIZED"} && defined $ENV{"IS_OPTIMIZED"} && $ENV{"IS_OPTIMIZED"} == 0)
{
  $PW_CHARSET = "utf-8";
}

sub module_constraints { [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iterations,
    output_len => 64
  );

  my $digest = encode_base64 ($pbkdf2->PBKDF2 ($salt, encode ("UTF-16LE", decode ($PW_CHARSET, $word))), "");

  my $base64_salt = encode_base64 ($salt, "");

  my $hash = sprintf ("sha512utf16le:%i:%s:%s", $iterations, $base64_salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my ($signature, $iterations, $salt_encoded, $hash_encoded) = split (':', $digest);

  return unless ($signature eq 'sha512utf16le');
  return unless defined $iterations;
  return unless defined $salt_encoded;
  return unless defined $hash_encoded;

  my $salt = decode_base64 ($salt_encoded);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations);

  return ($new_hash, $word);
}

1;

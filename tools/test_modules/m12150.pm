#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha512);

sub module_constraints {
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]];
}

sub module_generate_hash {
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1024;

  if (length $salt == 0) {
    $salt = random_bytes(16);
  }

  # Initialize the hash with the salt and password
  my $ctx = Digest::SHA->new(512);
  $ctx->add($salt);
  $ctx->add($word);

  my $digest = $ctx->digest;

  # Perform the iterations
  for (my $i = 1; $i < $iterations; $i++) {
      $ctx = Digest::SHA->new(512);
      $ctx->add($digest);
      $digest = $ctx->digest;        
  }

  # Encode the final hash and salt
  my $hash_encoded = encode_base64($digest, "");
  my $salt_encoded = encode_base64($salt, "");

  # Format the final hash
  my $hash = sprintf('$shiro1$SHA-512$%i$%s$%s', $iterations, $salt_encoded, $hash_encoded);

  return $hash;
}

sub module_verify_hash {
  my $line = shift;

  # Split the input line into components
  my ($digest, $word) = split(/:/, $line, 2);

  return unless defined $digest;
  return unless defined $word;

  # Match and capture the hash format components
  if ($digest =~ /^\$shiro1\$SHA-512\$(\d+)\$([A-Za-z0-9+\/=]+)\$([A-Za-z0-9+\/=]+)$/) {
    my ($iterations, $salt_encoded, $hash_encoded) = ($1, $2, $3);

    # Decode base64 encoded salt
    my $salt = decode_base64($salt_encoded);

    # Verify the hash
    my $word_packed = pack_if_HEX_notation($word);
    my $new_hash = module_generate_hash($word_packed, $salt, $iterations);

    return ($new_hash, $word);
  }

  return; # Return undefined if the digest doesn't match the expected format
}

1;

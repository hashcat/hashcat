#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (hmac_sha256_hex);

sub module_constraints { [[0, 256], [0, 256], [0, 31], [0, 51], [0, 82]] }

# Python Werkzeug legacy password hash, method "sha256":
#   werkzeug.security.generate_password_hash(pw, method="sha256", salt_length=N)
# produces  sha256$<salt>$<digest>  where digest = HMAC-SHA256(key=salt, msg=password).
# (Werkzeug uses the salt as the HMAC key; removed from werkzeug >= 2.3.)

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = hmac_sha256_hex ($word, $salt);   # (data, key) -> HMAC-SHA256(key = salt)

  return sprintf ("sha256\$%s\$%s", $salt, $digest);
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line, 2);

  return unless defined $hash;
  return unless defined $word;

  my @parts = split (/\$/, $hash);

  return unless scalar @parts == 3;
  return unless $parts[0] eq "sha256";

  my $salt = $parts[1];

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;

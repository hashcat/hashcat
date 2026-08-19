#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::HMAC_MD5 qw (hmac_md5_hex);

sub module_constraints { [[0, 256], [0, 256], [0, 31], [0, 51], [0, 82]] }

# Python Werkzeug legacy password hash, method "md5":
#   werkzeug.security.generate_password_hash(pw, method="md5", salt_length=N)
# produces  md5$<salt>$<digest>  where digest = HMAC-MD5(key=salt, msg=password).
# (Werkzeug uses the salt as the HMAC key; removed from werkzeug >= 2.3.)

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = hmac_md5_hex ($word, $salt);   # (data, key) -> HMAC-MD5(key = salt)

  return sprintf ("md5\$%s\$%s", $salt, $digest);
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line, 2);

  return unless defined $hash;
  return unless defined $word;

  my @parts = split (/\$/, $hash);

  return unless scalar @parts == 3;
  return unless $parts[0] eq "md5";

  my $salt = $parts[1];

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;

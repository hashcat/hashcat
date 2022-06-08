#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1 qw (sha1 sha1_hex);
use Encode;

sub module_constraints { [[0, 256], [0, 128], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $user = shift // random_mixedcase_string (random_number (0, 256 / 2));

  my $word_utf16le = encode ("UTF-16LE", $word);
  my $user_utf16le = encode ("UTF-16LE", $user);

  my $digest = sha1_hex ($salt . sha1 ($user_utf16le . ':' . $word_utf16le));

  my $hash = sprintf ("%s:%s:%s", $digest, unpack ("H*", $salt), unpack ("H*", $user));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $user, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $user;
  return unless defined $word;

  return unless ($hash =~ m/^[0-9a-fA-F]{40}$/);
  return unless ($salt =~ m/^[0-9a-fA-F]{0,256}$/);
  return unless ($user =~ m/^[0-9a-fA-F]{0,256}$/);

  $salt = pack ("H*", $salt);
  $user = pack ("H*", $user);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $user);

  return ($new_hash, $word);
}

1;

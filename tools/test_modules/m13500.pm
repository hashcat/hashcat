#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);
use Encode;

sub module_constraints { [[0, 256], [-1, -1], [0, 16], [-1, -1], [-1, -1]] }

sub get_pstoken_salt
{
  my $pstoken_length = random_number (16, 255);

  ## not a valid pstoken but a better test
  ## because of random length

  my $pstoken_const = random_bytes ($pstoken_length);

  return unpack ("H*", $pstoken_const);
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  if (length $salt == 0)
  {
    $salt = get_pstoken_salt ();
  }

  my $hash_buf = sha1_hex (pack ("H*", $salt) . encode ("UTF-16LE", $word));

  my $hash = sprintf ("%s:%s", $hash_buf, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;

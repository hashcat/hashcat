#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Text::Iconv;
use Encode;

sub module_constraints { [[32, 32], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_get_random_password
{
  my $word = shift;

  my $converter = Text::Iconv->new('utf8', 'UTF-16LE');

  $word = md4_hex ($converter->convert ($word));

  return $word;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $word_bin = pack ("H*", $word);

  my $salt_bin = encode ("UTF-16LE", lc ($salt));

  my $digest = md4_hex ($word_bin . $salt_bin);

  my $hash = sprintf ("%s:%s", $digest, $salt);

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

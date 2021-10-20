#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Text::Iconv;

sub module_constraints { [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $converter = Text::Iconv->new('utf8', 'UTF-16LE');

  my $digest = md4_hex ($converter->convert ($word));

  return $digest;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;

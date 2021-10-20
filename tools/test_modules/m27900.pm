#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::CRC;

sub module_constraints { [[-1, -1], [-1, -1], [0, 31], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $iv = hex ($salt);

  my $ctx = Digest::CRC->new
  (
    width   => 32,
    init    => $iv,
    xorout  => 0xffffffff,
    refout  => 1,
    poly    => 0x1edc6f41,
    refin   => 1,
    cont    => 1
  );

  $ctx->add ($word);

  my $hash = sprintf ("%s:%s", $ctx->hexdigest (), $salt);

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

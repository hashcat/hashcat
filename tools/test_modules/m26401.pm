#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;

sub module_constraints { [[0, 16], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $cipher = Crypt::Mode::ECB->new ('AES', 0);

  my $key_bin = $word;
  my $pt_bin  = pack ("H*", $salt);

  $key_bin .= "\x00" x 16;

  $key_bin = substr ($key_bin, 0, 16);

  my $ct_bin = $cipher->encrypt ($pt_bin, $key_bin);

  my $hash = sprintf ("%s:%s", unpack ("H*", $ct_bin), $salt);

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

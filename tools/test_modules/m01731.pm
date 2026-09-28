#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha512_hex);
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

sub module_constraints { [[0, 256], [8, 8], [0, 27], [8, 8], [8, 27]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_bin = pack ("H*", $salt);

  my $digest = sha512_hex (encode ("UTF-16LE", decode ($PW_CHARSET, $word)) . $salt_bin);

  my $hash = sprintf ("0x0200%s%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  my $salt = substr ($digest, 6, 8);

  my $hash = substr ($digest, 14);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;

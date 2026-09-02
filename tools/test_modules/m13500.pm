#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);
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

  my $hash_buf = sha1_hex (pack ("H*", $salt) . encode ("UTF-16LE", decode ($PW_CHARSET, $word)));

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

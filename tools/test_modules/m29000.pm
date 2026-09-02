#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1 qw (sha1 sha1_hex);
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

sub module_constraints { [[0, 256], [0, 128], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $user = shift // random_mixedcase_string (random_number (0, 256 / 2));

  my $word_utf16le = encode ("UTF-16LE", decode ($PW_CHARSET, $word));
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

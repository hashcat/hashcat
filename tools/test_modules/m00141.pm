#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1 qw (sha1);
use MIME::Base64 qw (encode_base64 decode_base64);
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

sub module_constraints { [[0, 256], [0, 256], [0, 27], [0, 27], [0, 27]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = sha1 ($salt . encode ("UTF-16LE", decode ($PW_CHARSET, $word)));

  my $base64_salt_buf = encode_base64 ($salt, "");
  my $base64_hash_buf = encode_base64 ($digest, "");

  $base64_hash_buf = substr ($base64_hash_buf, 0, 27);

  my $hash = sprintf ("\$episerver\$*0*%s*%s", $base64_salt_buf, $base64_hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  $digest = substr ($digest, 14);

  my ($base64_salt, $base64_hash) = split ('\*', $digest);

  my $hash = decode_base64 ($base64_hash);
  my $salt = decode_base64 ($base64_salt);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;

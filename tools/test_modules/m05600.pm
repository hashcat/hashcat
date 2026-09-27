#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4  qw (md4);
use Digest::HMAC qw (hmac hmac_hex);
use Digest::MD5  qw (md5);
use Encode       qw (encode decode);

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

sub module_constraints { [[0, 127], [0, 55], [0, 27], [0, 27], [-1, -1]] } # room for improvement in pure kernel mode

sub module_generate_hash
{
  my $word = shift;
  my $user = shift;

  my $user_len   = length $user;
  my $domain_len = 27 - $user_len;

  my $domain = shift // random_string ($domain_len);
  my $srv_ch = shift // random_hex_string (2 * 8);
  my $cli_ch = shift // random_client_challenge ();

  my $b_srv_ch = pack ('H*', $srv_ch);
  my $b_cli_ch = pack ('H*', $cli_ch);

  # md4 of the UTF-16LE password, which is what the NT hash is. Authen::Passphrase::NTHash
  # cannot be used here: it gets the encoding wrong for a character outside the BMP, an
  # emoji for instance, and the kernel does not.
  my $nthash   = md4 (encode ("UTF-16LE", decode ($PW_CHARSET, $word)));
  my $identity = encode ('UTF-16LE', uc ($user) . $domain);
  my $digest   = hmac_hex ($b_srv_ch . $b_cli_ch, hmac ($identity, $nthash, \&md5, 64), \&md5, 64);

  my $hash = sprintf ("%s::%s:%s:%s:%s", $user, $domain, $srv_ch, $digest, $cli_ch);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $user;
  my $domain;
  my $srv_ch;
  my $cli_ch;
  my $word;

  my $hash;

  my $index1 = index ($line, '::');
  my $index2 = index ($line, ':', $index1 + 2);
  my $index3 = index ($line, ':', $index2 + 3 + 16 + 32);

  return if $index1 eq -1;
  return if $index2 eq -1;
  return if $index3 eq -1;

  $hash = substr ($line, 0, $index3);

  $user   = substr ($line, 0, $index1);
  $domain = substr ($line, $index1 + 2, $index2 - $index1 - 2);
  $srv_ch = substr ($line, $index2 + 1, 16);
  $cli_ch = substr ($line, $index2 + 3 + 16 + 32, $index3 - $index2 - 3 - 16 - 32);
  $word   = substr ($line, $index3 + 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $user, $domain, $srv_ch, $cli_ch);

  return ($new_hash, $word);
}

sub random_client_challenge
{
  my $ch;

  $ch .= '0101000000000000';
  $ch .= random_hex_string (2 * 16);
  $ch .= '00000000';
  $ch .= random_hex_string (2 * random_count (20));
  $ch .= '00';

  return $ch;
}

1;

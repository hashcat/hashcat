#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::HMAC qw (hmac hmac_hex);
use Digest::MD5  qw (md5);
use Encode       qw (encode);

sub module_constraints { [[32, 32], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

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

  my $nthash = pack ("H*", $word);
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

  my $word_packed = pack ("H*", $word);

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

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5 md5_hex);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $realm = shift;
  my $nonce = shift;
  my $cnonce = shift;
  my $nc = shift;
  my $qop = shift;
  my $uri = shift;
  my $username = shift;

  if (! defined $realm)
  {
    $realm    = "REALM-" . random_hex_string (6);
    $nonce    = random_hex_string (28);
    $cnonce   = random_hex_string (32);
    $nc       = "00000001";
    $qop      = "auth";
    $uri      = "ldap/" . lc (random_hex_string (8)) . ".local";
    $username = "user" . int (rand (9999));
  }

  my $ha2 = md5_hex ("AUTHENTICATE:" . $uri);

  my $h_raw = md5 ($username . ":" . $realm . ":" . $word);

  my $ha1 = md5_hex ($h_raw . ":" . $nonce . ":" . $cnonce);

  my $response = md5_hex ($ha1 . ":" . $nonce . ":" . $nc . ":" . $cnonce . ":" . $qop . ":" . $ha2);

  my $hash = sprintf ("\$sasl\$DIGEST-MD5\$%s\$%s\$%s\$%s\$%s\$%s\$%s\$%s",
    $realm, $username, $nonce, $cnonce, $nc, $qop, $uri, $response);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless length ($word) gt 0;
  return unless substr ($hash, 0, 6) eq '$sasl$';

  my (undef, $sig, $subsig, $realm, $username, $nonce, $cnonce, $nc, $qop, $uri, $response) = split '\$', $hash;

  return unless defined $sig;
  return unless defined $subsig;
  return unless defined $realm;
  return unless defined $username;
  return unless defined $nonce;
  return unless defined $cnonce;
  return unless defined $nc;
  return unless defined $qop;
  return unless defined $uri;
  return unless defined $response;
  return unless $subsig eq "DIGEST-MD5";

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $realm, $nonce, $cnonce, $nc, $qop, $uri, $username);

  return ($new_hash, $word);
}

1;

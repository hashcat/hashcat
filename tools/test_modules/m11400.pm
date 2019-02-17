#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 24], [1, 15], [0, 24], [1, 15], [-1, -1]] }

sub module_generate_hash
{
  my $word         = shift;
  my $nonce        = shift;
  my $user         = shift // random_string (random_number (1, 12 + 1));
  my $realm        = shift;
  my $nonce_count  = shift;
  my $nonce_client = shift;
  my $qop          = shift;
  my $method       = shift // random_string (random_number (1, 24 + 1));
  my $URI_prefix   = shift // random_string (random_number (1, 10 + 1));
  my $URI_resource = shift // random_string (random_number (1, 32 + 1));
  my $URI_suffix   = shift // random_string (random_number (1, 32 + 1));
  my $directive    = shift // "MD5";

  # not needed information
  my $URI_server = shift // random_string (random_number (1, 32 + 1));
  my $URI_client = $URI_resource;

  return unless ($directive eq "MD5"); # only MD5 directive currently supported

  unless (defined $realm)
  {
    # special limit: (user_len + 1 + realm_len + 1 + word_len) < 56
    my $realm_max_len = 55 - length ($user) - 1 - length ($word) - 1;

    if ($realm_max_len < 1) # should never happen
    {
      $realm_max_len = 1;
    }

    $realm_max_len = min (20, $realm_max_len);

    $realm = random_string (random_number (1, $realm_max_len + 1));
  }

  unless ((defined $nonce_count) && (defined $nonce_client) && (defined $qop))
  {
    if (random_number (0, 1 + 1) == 1)
    {
      $qop = "auth";

      $nonce_count  = random_string (random_number (1, 10 + 1));
      $nonce_client = random_string (random_number (1, 12 + 1));
    }
    else
    {
      $qop = "";

      $nonce_count  = "";
      $nonce_client = "";
    }
  }

  # start

  my $URI = "";

  if (length ($URI_prefix) > 0)
  {
    $URI = $URI_prefix . ":";
  }

  $URI .= $URI_resource;

  if (length ($URI_suffix) > 0)
  {
    $URI .= ":" . $URI_suffix;
  }

  my $HA2 = md5_hex ($method . ":" . $URI);

  my $HA1 = md5_hex ($user . ":" . $realm . ":" . $word);

  my $tmp;

  if (($qop eq "auth") || ($qop eq "auth-int"))
  {
    $tmp = $nonce . ":" . $nonce_count . ":" . $nonce_client . ":" . $qop;
  }
  else
  {
    $tmp = $nonce;
  }

  my $digest = md5_hex ($HA1 . ":" . $tmp . ":" . $HA2);

  my $hash = sprintf ("\$sip\$*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s", $URI_server, $URI_resource, $user, $realm, $method, $URI_prefix, $URI_resource, $URI_suffix, $nonce, $nonce_client, $nonce_count, $qop, $directive, $digest);

  return $hash;
}

sub module_verify_hash
{

  my $line = shift;

  my ($digest, $word) = split (/:/, $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split ('\*', $digest);

  return unless scalar @data == 15;

  my $signature    = shift @data;
  my $URI_server   = shift @data;
  my $URI_client   = shift @data;
  my $user         = shift @data;
  my $realm        = shift @data;
  my $method       = shift @data;
  my $URI_prefix   = shift @data;
  my $URI_resource = shift @data;
  my $URI_suffix   = shift @data;
  my $nonce        = shift @data;
  my $nonce_client = shift @data;
  my $nonce_count  = shift @data;
  my $qop          = shift @data;
  my $directive    = shift @data;
  my $hash         = shift @data;

  return unless ($signature eq '$sip$');

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash (
    $word_packed,
    $nonce,
    $user,
    $realm,
    $nonce_count,
    $nonce_client,
    $qop,
    $method,
    $URI_prefix,
    $URI_resource,
    $URI_suffix,
    $directive,
    $URI_server);

  return ($new_hash, $word);
}

sub min
{
  $_[$_[0] > $_[1]];
}

1;

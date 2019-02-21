#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[0, 243], [-1, -1], [0, 43], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word           = shift;
  my $session_id     = shift || random_bytes (8);
  my $encrypted_data = shift;
  my $sequence       = shift || "c006";

  $session_id = pack ("H*", $session_id);

  if (defined $encrypted_data)
  {
    $encrypted_data = pack ("H*", $encrypted_data);
  }

  $sequence = pack ("H*", $sequence);

  my $key = md5 ($session_id . $word . $sequence);

  if (defined $encrypted_data)
  {
    ## verify case

    my $encrypted_data_len = length $encrypted_data;

    my $plain_data = substr ($encrypted_data, 0, 6) ^ substr ($key, 0, 6);

    my ($status, $flags, $server_msg_len, $data_len) = unpack ("CCnn", $plain_data);

    if ((($status >= 0x01 && $status <= 0x07) || $status == 0x21)
     &&  ($flags  == 0x01 || $flags  == 0x00)
     &&  (6 + $server_msg_len + $data_len == $encrypted_data_len))
    {
      ## ok
    }
    else
    {
      $encrypted_data = ""; # some invalid data
    }
  }
  else
  {
    my $plain_data = "\x01\x00\x00\x00\x00\x00";

    my $plain_data_len = length $plain_data;

    my $shortest = ($plain_data_len > 16) ? 16 : $plain_data_len;

    $encrypted_data = substr ($plain_data, 0, $shortest) ^ substr ($key, 0, $shortest);
  }

  my $hash = sprintf ('$tacacs-plus$0$%s$%s$%s', unpack ("H*", $session_id), unpack ("H*", $encrypted_data), unpack ("H*", $sequence));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 6;

  shift @data;

  my $signature = shift @data;

  return unless ($signature eq "tacacs-plus");

  my $auth_version = shift @data;

  return unless ($auth_version eq "0");

  my $session_id      = shift @data;
  my $encrypted_data  = shift @data;
  my $sequence        = shift @data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $session_id, $encrypted_data, $sequence);

  return ($new_hash, $word);
}

1;

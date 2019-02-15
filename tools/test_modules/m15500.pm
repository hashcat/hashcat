#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1);
use Encode;

sub module_constraints { [[0, 16], [-1, -1], [0, 16], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word    = shift;
  my $iv      = shift || random_hex_string (40);
  my $enc_key = shift || random_hex_string (random_number (1, 1500));
  my $alias   = shift || "test";

  if (length $iv)
  {
    $iv = pack ("H*", $iv);
  }

  if (length $enc_key)
  {
    $enc_key = pack ("H*", $enc_key);
  }

  my $word_utf16be = encode ("UTF-16BE", $word);

  my $digest = sha1 ($word_utf16be . $iv);

  my $DER1 = substr ($digest, 0, 1);
  my $DER2 = substr ($digest, 6, 14);

  my @enc_key_data = split "", $enc_key;

  my $enc_key_data_length = scalar @enc_key_data;

  my @key_data = ();

  for (my $i = 0; $i < scalar $enc_key_data_length; $i += 20)
  {
    my @digest_data = split "", $digest;

    for (my $j = 0; $j < 20; $j++)
    {
      last if (($i + $j) >= $enc_key_data_length);

      $key_data[$i + $j] = $enc_key_data[$i + $j] ^ $digest_data[$j];
    }

    $digest = sha1 ($word_utf16be . $digest);
  }

  my $key = join "", @key_data;

  $digest = sha1 ($word_utf16be . $key);

  my $hash = sprintf ("\$jksprivk\$*%s*%s*%s*%s*%s*%s", uc unpack ("H*", $digest), uc unpack ("H*", $iv), uc unpack ("H*", $enc_key), uc unpack ("H*", $DER1), uc unpack ("H*", $DER2), $alias);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\*', $hash);

  return unless scalar @data == 7;

  my $signature = shift @data;

  return unless ($signature eq '$jksprivk$');

  my $checksum  = shift @data;
  my $iv        = shift @data;
  my $enc_key   = shift @data;
  my $DER1      = shift @data;
  my $DER2      = shift @data;
  my $alias     = shift @data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $iv, $enc_key, $alias);

  return ($new_hash, $word);
}

1;

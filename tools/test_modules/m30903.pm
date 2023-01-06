#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Bitcoin::Crypto         qw (btc_prv btc_extprv);
use Bitcoin::Crypto::Base58 qw (decode_base58check);

sub module_constraints { [[64, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

# Note:
# We have introduced the function: module_get_random_password ()
# that will help to generate random valid passwords from a given seed.

sub module_generate_hash
{
  my $word = shift; # expecting valid raw private key

  return unless ($word =~ m/^[0-9a-fA-F]{64}$/);

  my $priv = "";

  my @is_valid_hex = eval
  {
    $priv = btc_prv->from_hex ($word);
  };

  return if (! @is_valid_hex);

  my $IS_COMPRESSED = 1;

  $priv->set_compressed ($IS_COMPRESSED);

  my $pub  = $priv->get_public_key    ();
  my $hash = $pub->get_segwit_address ();

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = rindex ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless (defined ($hash));
  return unless (defined ($word));

  return unless ($word =~ m/^[0-9a-fA-F]{64}$/);

  return unless ($hash =~ m/^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]*$/); # bech32/base32 encoding

  my $new_hash = module_generate_hash ($word);

  return ($new_hash, $word);
}

sub module_get_random_password
{
  my $seed = shift;

  my $master_key  = btc_extprv->from_seed ($seed); # expecting random seed from test.pl
  my $derived_key = $master_key->derive_key ("m/0'");

  my $priv = $derived_key->get_basic_key ();

  return $priv->to_hex (); # the result is padded (32 raw bytes)
}

1;

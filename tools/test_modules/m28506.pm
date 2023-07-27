#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Bitcoin::Crypto         qw (btc_prv btc_extprv);
use Bitcoin::Crypto::Base58 qw (decode_base58check);

sub module_constraints { [[51, 51], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

# Note:
# We expect valid WIF format which for BTC private address is 51/52 base58 characters long.
# For uncompressed P2SH(P2WPKH) the length of the WIF is always 51.
# Standard test.pl is generating random passwords consisting only from digits.
# That does not work for this mode.
# So we have introduced new function: module_get_random_password ()
# that will help to generate random valid password for the module from a given seed.
#
# It will be called from test.pl if it exists in the module, otherwise everything
# will work as in legacy code. Search test.pl for module_get_random_password ()

sub module_generate_hash
{
  my $word = shift; # expecting valid WIF formatted private key

  my @is_valid_base58 = eval
  {
    decode_base58check ($word); # or we could use validate_wif ()
  };

  return if (! @is_valid_base58);

  # validate WIF (check password, "verify")

  my $priv = "";

  my @is_valid_wif = eval
  {
    $priv = btc_prv->from_wif ($word);
  };

  return if (! @is_valid_wif);

  return if ($priv->compressed != 0);

  my $pub  = $priv->get_public_key    ();
  my $hash = $pub->get_compat_address ();

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

  my @is_valid_base58 = eval
  {
    decode_base58check ($hash);
    decode_base58check ($word);
  };

  return unless (@is_valid_base58);

  return unless (length ($word) == 51);

  return unless (substr ($word, 0, 1) eq "5");

  my $new_hash = module_generate_hash ($word);

  return ($new_hash, $word);
}

sub module_get_random_password
{
  # new function added to generate valid password for an algorithm
  # from a given seed as a parameter

  my $seed = shift;

  my $master_key  = btc_extprv->from_seed ($seed); # expecting random seed from test.pl
  my $derived_key = $master_key->derive_key ("m/0'");

  my $priv = $derived_key->get_basic_key ();

  my $IS_COMPRESSED = 0;

  $priv->set_compressed ($IS_COMPRESSED);

  # return WIF format

  return $priv->to_wif ();
}

1;

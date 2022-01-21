#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Bitcoin::Crypto         qw (btc_prv btc_extprv);
use Bitcoin::Crypto::Base58 qw (decode_base58check);

sub module_constraints { [[51, 52], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

# Note: the 51/52 password limit above is just used here to emphasize that we actually
# would expect a valid WIF (in base58check format) as a password candidate,
# but the unit test interface does not give us this type of data
# ($word is just a 51-52 digit long number)

sub module_generate_hash
{
  my $word    = shift;
  my $address = shift // "";

  my $priv = undef;

  my @is_valid_base58 = eval
  {
    decode_base58check ($word); # or we could use from_wif () or validate_wif ()
  };

  if (! @is_valid_base58) # generate new random key
  {
    # is calling the function from_bytes () not secure/valid enough (not "valid" entropy) ?
    # $priv = btc_prv->from_bytes (substr ($word, 0, 32)); # from_bytes () allows only 32 bytes

    # this is safer (and probably more valid and secure):
    # but note that also $word itself is not random enough (it's just a 51-52 digit long number)
    # we could actually hash $word before using it as a seed (this is already done with a hmac ()
    # within the from_seed () implementation), but this doesn't change much here since the
    # original/source entropy ($word) is insecure

    my $master_key  = btc_extprv->from_seed ($word); # here $word should actually be >= 64 bytes
    my $derived_key = $master_key->derive_key ("m/0'");

    $priv = $derived_key->get_basic_key ();

    # randomly try either compressed or uncompressed keys

    my $is_compressed = 0;

    if (int (rand (2)) == 0)
    {
      $is_compressed = 1;
    }

    $priv->set_compressed ($is_compressed);
  }
  else # validate WIF (check password, "verify")
  {
    $priv = btc_prv->from_wif ($word);

    # the compression detection is already done automatically by from_wif ():
    #
    # my $is_compressed = 0;
    #
    # if (length ($word) == 52)
    # {
    #   $is_compressed = 1;
    # }
    #
    # $priv->set_compressed ($is_compressed);
  }

  my $pub  = $priv->get_public_key    ();
  my $hash = $pub->get_legacy_address ();

  # or:
  # my $pub_sha256    = sha256    ($pub->to_bytes ());
  # my $pub_ripemd160 = ripemd160 ($pub_sha256);
  #
  # my $hash = encode_base58check ("\x00" . $pub_ripemd160);

  if (length ($address) > 0) # special case: alternatives for "verify"
  {
    if ($hash ne $address)
    {
      # there is actually NO reason to try the wrong/alternative type (compressed or uncompressed)
      # Why should we do this if we have the correct info from the WIF (extra 0x01 byte) ?
      #
      # my $is_compressed_wrong = 1;
      #
      # if (length ($word) == 52)
      # {
      #   $is_compressed_wrong = 0; # WRONG
      # }
      #
      # $priv->set_compressed ($is_compressed_wrong);
      #
      # my $pub_wrong = $priv->get_public_key ();
      #
      # $hash = $pub_wrong->get_legacy_address ();
    }
  }
  # print(">>\t".$hash);

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

  next unless (@is_valid_base58);

  return unless ((length ($word) == 51) ||
                 (length ($word) == 52));

  # my $word_packed = pack_if_HEX_notation ($word); # not applicable here ($HEX[] of base58)

  my $new_hash = module_generate_hash ($word, $hash);

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

  my $is_compressed = 0;

  # randomize compression 
  if (int (rand (2)) == 0) 
  {
    $is_compressed = 1;
  }

  $priv->set_compressed ($is_compressed);
  # return WIF format
  return $priv->to_wif();
}
1;
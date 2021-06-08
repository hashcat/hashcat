#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256);
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $FORTIGATE_SIGNATURE = "SH2";
  my $FORTIGATE_MAGIC     = pack ("H*", "a388ba2e424cb04a537930c13107cc3fa1329029a9815b70");

  my $salt_bin = pack ("H*", $salt);

  my $hash_buf = sha256 ($salt_bin . $word . $FORTIGATE_MAGIC);

  $hash_buf = encode_base64 ($salt_bin . $hash_buf, "");

  my $hash = sprintf ("%s%s", $FORTIGATE_SIGNATURE, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 != 63;

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  my $decoded = decode_base64 (substr ($hash_in, 3));

  my $salt = substr ($decoded, 0, 12);

  $salt = unpack ("H*", $salt);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;

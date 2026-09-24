#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw(hmac_sha512);

my $MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
my $PATH     = "m/49'/0'/0'/0/0";

BEGIN
{
  unless (defined &pack_if_HEX_notation)
  {
    *pack_if_HEX_notation = sub { return shift };
  }
}

sub module_constraints { [[0, 256], [-1, -1], [0, 256], [-1, -1], [-1, -1]] }

sub pbkdf2_hmac_sha512
{
  my ($password, $salt, $iterations, $dk_len) = @_;

  my $block_count = int (($dk_len + 63) / 64);
  my $derived     = "";

  for my $block (1 .. $block_count)
  {
    my $u = hmac_sha512 ($salt . pack ("N", $block), $password);
    my $t = $u;

    for (my $i = 1; $i < $iterations; $i++)
    {
      $u = hmac_sha512 ($u, $password);
      $t ^= $u;
    }

    $derived .= $t;
  }

  return substr ($derived, 0, $dk_len);
}

sub derive_il_prefix_hex
{
  my ($mnemonic, $passphrase) = @_;

  my $salt   = "mnemonic" . $passphrase;
  my $seed   = pbkdf2_hmac_sha512 ($mnemonic, $salt, 2048, 64);
  my $master = hmac_sha512 ($seed, "Bitcoin seed");

  return unpack ("H*", substr ($master, 0, 16));
}

sub module_generate_hash
{
  my $word = shift;

  my $passphrase = pack_if_HEX_notation ($word);

  my $il_hex = derive_il_prefix_hex ($MNEMONIC, $passphrase);

  return sprintf ("%s:%s:%s", $MNEMONIC, $il_hex, $PATH);
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = rindex ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  my @parts = split (':', $hash, 3);

  return unless scalar @parts == 3;

  my ($mnemonic, $target_hex, $path) = @parts;

  return unless $target_hex =~ /\A[0-9a-fA-F]{32}\z/;

  my $word_packed = pack_if_HEX_notation ($word);

  my $computed_hex = derive_il_prefix_hex ($mnemonic, $word_packed);

  my $new_hash = sprintf ("%s:%s:%s", $mnemonic, $computed_hex, $path);

  return unless lc $new_hash eq lc $hash;

  return ($new_hash, $word);
}

1;

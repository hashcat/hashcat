#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256_hex);
use Crypt::CBC;

sub module_constraints { [[0, 55], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub calculate_padding
{
  my $length = shift;
  my $blocksize = shift // 32;
  my $minpadding = shift // 16;

  my $padded_len = $length+$minpadding;
  my $finalpadded = (($padded_len - 1) | ($blocksize - 1)) + 1;

  return $finalpadded - $length;
}

sub module_generate_hash
{
  my $word = shift;
  my $total_len = (length ($word) * 2) + 8 + 64;
  my $padding = shift // random_hex_string (calculate_padding ($total_len));

  if (length $padding == 0) {
    $padding = random_hex_string (calculate_padding ($total_len));
  }

  my $digest = sha256_hex ($word);
  my $len = sprintf ("%02d", length ($word));
  my $paddedlen = sprintf ("%02x000000", $len);
  my $hexofword = unpack "H*", $word;
  my $plaintext = $paddedlen . $hexofword . $digest . $padding;

  my $aes = Crypt::CBC->new ({
    key         => pack ("H*", $digest),
    cipher      => "Crypt::Rijndael",
    iv          => => "\x00" x 16,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "none",
  });

  my $ciphertext = $aes->encrypt (pack ("H*", $plaintext));
  my $hash = sprintf ("S:\"Config Passphrase\"=02:%s", unpack ("H*", $ciphertext));

  return $hash
}

sub get_aes
{
  my $word_packed = shift;
  my $key = sha256_hex ($word_packed);

  my $aes = Crypt::CBC->new ({
    key         => pack ("H*", $key),
    cipher      => "Crypt::Rijndael",
    iv          => => "\x00" x 16,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "none",
  });

  return $aes
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = $line=~ /S:.Config.Passphrase.=02:(.*):(.*)/;

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);
  my $decrypted = get_aes ($word_packed)->decrypt (pack"H*", $hash);
  my $plaintext_hex = unpack "H*", $decrypted;
  my $passlen = hex (substr ($plaintext_hex, 0, 2));
  my $padding = substr ($plaintext_hex, 8 + 2 * $passlen + 64);

  my $new_hash = module_generate_hash ($word_packed,$padding);

  return ($new_hash, $word);
}

1;

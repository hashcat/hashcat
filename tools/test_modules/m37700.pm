#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::AuthEnc::ChaCha20Poly1305 qw (chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $nonce      = shift // random_hex_string (24);
  my $ciphertext = shift;
  my $tag        = shift;

  return unless defined $word;
  return unless defined $salt && $salt =~ /\A[0-9a-fA-F]{64}\z/;
  return unless defined $nonce && $nonce =~ /\A[0-9a-fA-F]{24}\z/;
  return unless defined $ciphertext == defined $tag;

  if (defined $ciphertext)
  {
    return unless $ciphertext =~ /\A[0-9a-fA-F]{330}\z/;
    return unless $tag =~ /\A[0-9a-fA-F]{32}\z/;
  }

  my $salt_bin  = pack ('H*', $salt);
  my $nonce_bin = pack ('H*', $nonce);

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => 210012,
    output_len => 32
  );

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $plaintext;

  if (defined $ciphertext)
  {
    $plaintext = chacha20poly1305_decrypt_verify ($key, $nonce_bin, '', pack ('H*', $ciphertext), pack ('H*', $tag));

    return unless defined $plaintext;
  }
  else
  {
    $plaintext = random_bytes (165);
  }

  my ($ciphertext_bin, $tag_bin) = chacha20poly1305_encrypt_authenticate ($key, $nonce_bin, '', $plaintext);

  return sprintf ('ETERNL:%s%s%s%s',
    unpack ('H*', $salt_bin),
    unpack ('H*', $nonce_bin),
    unpack ('H*', $tag_bin),
    unpack ('H*', $ciphertext_bin)
  );
}

sub module_verify_hash
{
  my $line = shift;

  return unless defined $line;

  my $idx = index ($line, ':', 7);

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless $hash =~ /\AETERNL:([0-9a-fA-F]{64})([0-9a-fA-F]{24})([0-9a-fA-F]{32})([0-9a-fA-F]{330})\z/;

  my ($salt, $nonce, $tag, $ciphertext) = ($1, $2, $3, $4);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $nonce, $ciphertext, $tag);

  return unless defined $new_hash;

  return ($new_hash, $word);
}

1;

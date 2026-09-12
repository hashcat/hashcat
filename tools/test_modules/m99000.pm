#!/usr/bin/env perl

##
## Author......: Datarecovery.com
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::Mode::CBC;

sub module_constraints { [[8, 30], [6, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 5000;
  my $iv   = shift;
  my $ct   = shift;

  # Derive 32-byte key via PBKDF2-HMAC-SHA256
  my $pbkdf2 = Crypt::PBKDF2->new (
    hash_class => 'HMACSHA2',
    hash_args  => { sha_size => 256 },
    iterations => $iter,
    output_len => 32,
  );

  my $key = $pbkdf2->PBKDF2 ($salt, $word);

  # If no IV/CT provided, generate them by encrypting a known test plaintext
  if (! defined $iv || ! defined $ct)
  {
    $iv = pack ('H*', '0102030405060708090a0b0c0d0e0f10');

    my $pt = "TESTVECTOR______TESTPAD!" . (chr (8) x 8);

    my $cbc = Crypt::Mode::CBC->new ('AES', 0);

    $ct = $cbc->encrypt ($pt, $key, $iv);
  }

  my $iv_hex = unpack ('H*', $iv);
  my $ct_hex = unpack ('H*', substr ($ct, 0, 32));

  my $hash = sprintf ('$lpvault$0$%u$%s$%s$%s', $iter, $salt, $iv_hex, $ct_hex);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @parts = split (/\$/, $hash);

  return unless scalar @parts == 7;
  return unless $parts[1] eq 'lpvault';
  return unless $parts[2] eq '0';

  my $iter = $parts[3];
  my $salt = $parts[4];
  my $iv   = pack ('H*', $parts[5]);
  my $ct   = pack ('H*', $parts[6]);

  my $word_packed = pack ('a*', $word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $iv, $ct);

  return ($new_hash, $word);
}

1;

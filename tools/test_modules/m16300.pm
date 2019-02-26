#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::PBKDF2;
use Digest::Keccak qw (keccak_256_hex);

sub module_constraints { [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word    = shift;
  my $ethaddr = shift;
  my $encseed = shift;

  my $iv   = "";
  my $seed = "";

  # setup pbkdf2 params:

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => 2000,
    output_len => 16
  );

  my $key = $pbkdf2->PBKDF2 ($word, $word);

  if (defined $encseed)
  {
    $iv      = substr ($encseed, 0, 16);
    $encseed = substr ($encseed, 16);

    # AES-128-CBC decrypt:

    my $aes_cbc = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $iv,
      literal_key => 1,
      header      => "none",
      keysize     => 16
    });

    $seed = $aes_cbc->decrypt ($encseed);
  }
  else
  {
    $iv   = random_bytes (16);
    $seed = random_bytes (592);

    # AES-128-CBC encrypt:

    my $aes_cbc = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $iv,
      literal_key => 1,
      header      => "none",
      keysize     => 16
    });

    $encseed = $aes_cbc->encrypt ($seed);
  }

  my $digest = keccak_256_hex ($seed . "\x02");

  my $hash = sprintf ("\$ethereum\$w*%s*%s*%s", unpack ("H*", $iv . $encseed), $ethaddr, substr ($digest, 0, 32));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 12);

  return unless ($signature eq "\$ethereum\$w\*");

  my @data = split ('\*', $hash);

  return unless scalar (@data) == 4;

  shift @data;

  my $encseed = pack ("H*", shift @data);
  my $ethaddr = shift @data;
  my $bpk     = pack ("H*", shift @data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $ethaddr, $encseed, $bpk);

  return ($new_hash, $word);
}

1;

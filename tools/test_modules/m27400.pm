#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt_str = shift;
  my $ct_str = shift;

  my $iv_str = "";

  if (defined $ct_str)
  {
    $iv_str = substr($ct_str, 0, 32);
  }
  else
  {
    $iv_str = random_hex_string (32);
  }

  my $salt = pack ("H*", $salt_str);

  my $iv = pack ("H*", $iv_str);

  my $iterations = 10000;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
    output_len   => 32
  );

  my $key = $pbkdf2->PBKDF2 ($salt, $word);

  my $cipher = Crypt::CBC->new ({
    key         => $key,
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    literal_key => 1,
    header      => "none",
    keysize     => 32
  });

  my $hash = "";

  my $data = 'type=key:cipher=';

  my $encrypted = unpack ("H*", $cipher->encrypt ($data));

  if (defined $ct_str)
  {
    my $ct_bin = pack ("H*", $ct_str);
    my $iv_bin = substr ($ct_bin, 0, 16);

    $hash = sprintf ("\$vmx\$0\$%s\$%s\$%s%s", $iterations, unpack ("H*", $salt), unpack ("H*", $iv_bin), substr ($encrypted, 0, 32));
  }
  else
  {
    $hash = sprintf ("\$vmx\$0\$%s\$%s\$%s%s", $iterations, unpack ("H*", $salt), unpack ("H*", $iv), substr ($encrypted, 0, 32));
  }

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my (undef, $signature, $version, $rounds, $salt, $ct) = split '\$', $hash;

  return unless ($signature eq "vmx");
  return unless ($version eq 0);
  return unless ($rounds eq 10000);
  return unless (length $ct eq 64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $ct);

  return ($new_hash, $word);
}

1;

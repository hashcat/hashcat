#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::PBKDF2;

# we need to make sure the salts are unique, otherwise this module will fail
sub module_constraints { [[0, 256], [10, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 100100;
  my $iv   = shift // random_bytes (16);

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256);

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iter,
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

  my $encrypt = $cipher->encrypt (substr ($salt, 0, 16));

  my $hash_buf = substr (unpack ("H*", $encrypt), 0, 32);

  my $iv_buf = unpack("H*", $iv);

  my $hash = sprintf ("%s:%i:%s:%s", $hash_buf, $iter, $salt, $iv_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $iter, $salt, $iv, $word) = split ":", $line;

  return unless defined $hash;
  return unless defined $iter;
  return unless defined $salt;
  return unless defined $word;
  return unless defined $iv;

  return unless ($iv =~ m/^[0-9a-fA-F]{32}$/);

  $iv = pack ("H*", $iv);

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter, $iv);

  return ($new_hash, $word);
}

1;

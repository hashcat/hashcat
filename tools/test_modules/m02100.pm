#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4 md4_hex);
use Crypt::PBKDF2;
use Encode;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 10240;

  my $salt_bin = encode ("UTF-16LE", lc ($salt));

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iterations,
    output_len => 16,
    salt_len   => length ($salt_bin),
  );

  my $digest = unpack ("H*", $pbkdf2->PBKDF2 ($salt_bin, md4 (md4 (encode ("UTF-16LE", $word)) . $salt_bin)));

  my $hash = sprintf ("\$DCC2\$%i#%s#%s", $iterations, $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 6);

  return unless ($signature eq '$DCC2$');

  $hash = substr ($hash, 6);

  my @data = split ('#', $hash);

  return unless scalar @data == 3;

  my $iterations = shift @data;
  my $salt       = shift @data;
  my $digest     = shift @data;

  return unless defined $iterations;
  return unless defined $salt;
  return unless defined $digest;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations);

  return ($new_hash, $word);
}

1;

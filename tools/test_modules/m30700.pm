#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA;

sub salt_to_state
{
  my $salt = shift;

  my @tmp = unpack("(A8)*", $salt);

  my $state = sprintf 'alg:256
H:%s
block:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
blockcnt:0
lenhh:0
lenhl:0
lenlh:0
lenll:0', join(":", @tmp);

  return $state
}

sub module_constraints { [[0, 256], [64, 64], [0, 55], [64, 64], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $sha256_ctx = Digest::SHA->new (256);

  $sha256_ctx->putstate (salt_to_state ($salt));

  $sha256_ctx->add ($word);

  my $digest = $sha256_ctx->hexdigest();

  my $hash = sprintf ("sha256:%s:%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($signature, $digest, $salt, $word) = split (':', $line);

  return unless defined $signature;
  return unless defined $digest;
  return unless defined $salt;
  return unless defined $word;

  return unless ($signature eq "sha256");

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;

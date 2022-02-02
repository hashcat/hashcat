#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64);
use Digest::SHA  qw (sha512);
use Encode;

sub module_constraints { [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 100000;

  my $tmp = sha512 ($salt . encode ("UTF-16LE", $word));

  for (my $i = 0; $i < $iter; $i++)
  {
    my $num32 = pack ("L", $i);

    $tmp = sha512 ($tmp . $num32);
  }

  my $salt_b64 = encode_base64 ($salt, "");
  my $digest_b64 = encode_base64 ($tmp, "");

  my $hash = sprintf ("\$office\$%d\$0\$%d\$%s\$%s", 2016, $iter, $salt_b64, $digest_b64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split ":", $line;

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 7;
  return unless (shift @data eq 'office');
  return unless (shift @data eq '2016');
  return unless (shift @data eq '0');

  my $iter   = shift @data;
  my $salt   = shift @data;
  my $digest = shift @data;

  return unless defined $iter;
  return unless defined $salt;
  return unless defined $digest;

  return unless length ($salt) == 24;
  return unless length ($digest) == 88;

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;

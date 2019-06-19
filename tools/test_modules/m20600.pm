#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use MIME::Base64;

sub module_constraints { [[0, 256], [0, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my ($word, $salt, $iter) = @_;

  return unless defined $word;
  return unless defined $salt;

  $iter //= 1000;

  my $digest = sha256($salt.$word);

  for (my $i = 1; $i < $iter; $i++) {
    $digest = sha256($digest);
  }

  chomp($digest = encode_base64($digest));

  my $hash = sprintf ("otm_sha256:%d:%s:%s", $iter, $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($sig, $iter, $salt, $hash, $word) = split (':', $line);

  return unless defined $iter;
  return unless defined $salt;
  return unless defined $word;
 
  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;

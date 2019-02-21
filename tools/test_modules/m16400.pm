#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::Perl::MD5;

sub module_constraints { [[0, 64], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word    = shift;

  my $md5 = Digest::Perl::MD5->new;
  my $length = length ($word);

  $md5->{_data} = $word ^ ("\x5c" x $length);
  $md5->{_data} .= "\x5c" x (64 - $length);
  $md5->add();

  my $digest = unpack ("H*", pack ('V4', @{$md5->{_state}}));
 
  my $hash = sprintf ("{CRAM-MD5}%s00000000000000000000000000000000", $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  return unless defined $digest;
  return unless defined $word;

  my $signature = substr ($digest, 0, 10);

  return unless ($signature eq "{CRAM-MD5}");

  my $hash = substr ($digest, 10);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;

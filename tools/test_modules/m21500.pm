#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use Crypt::PBKDF2;
use Digest::SHA qw (sha512);
use Encode;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => 1000,
    output_len => 1024
  );

  my $custom_salt = substr ($salt, 0, 8);

  if (length $custom_salt < 8)
  {
    $custom_salt = substr ($custom_salt . "1244352345234", 0, 8);
  }

  my $key = $kdf->PBKDF2 ($custom_salt, $word);

  my $key_b64 = encode_base64 (sha512 ($key), "");

  my $hash = sprintf ("\$solarwinds\$0\$%s\$%s", $salt, $key_b64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 5;

  shift @data;

  my $signature = shift @data;
  my $sig_dec   = shift @data;
  my $salt      = shift @data;
  my $digest    = shift @data;

  return unless ($signature eq "solarwinds");
  return unless ($sig_dec eq "0");

  return if length ($salt) > 256;
  return unless length ($digest) == 88;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;

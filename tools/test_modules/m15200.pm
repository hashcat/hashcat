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
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 5000;
  my $encrypted  = shift;

  my $salt_bin = pack ("H*", $salt);

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
    output_len   => 32
  );

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $cipher = Crypt::CBC->new ({
    key         => $key,
    cipher      => "Crypt::Rijndael",
    iv          => $salt_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 32
  });

  my $data = qq|{
"guid" : "00000000-0000-0000-0000-000000000000",
"sharedKey" : "00000000-0000-0000-0000-000000000000",
"options" : {"pbkdf2_iterations":$iterations,"fee_policy":0,"html5_notifications":false,"logout_time":600000,"tx_display":0,"always_keep_local_backup":false}|;
  
  unless (defined $encrypted)
  {
    $encrypted = unpack ("H*", $cipher->encrypt ($data));
  }

  my $hash = sprintf ("\$blockchain\$v2\$%d\$%s\$%s", $iterations, length ($salt . $encrypted) / 2, $salt . $encrypted);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my (undef, $signature, $version, $iterations, $data_len, $data) = split '\$', $hash;

  return unless ($signature eq "blockchain");
  return unless ($version eq "v2");
  return unless (($data_len * 2) == length $data);

  my $salt      = substr ($data, 0, 32);
  my $encrypted = substr ($data, 32);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $encrypted);

  return ($new_hash, $word);
}

1;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha512);
use Crypt::CBC;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $ckey       = shift // random_hex_string (96);
  my $public_key = shift // random_hex_string (66);
  my $salt_iter  = shift // random_number (150000, 250000);

  my $digest = sha512 ($word . pack ("H*", $salt));

  for (my $i = 1; $i < $salt_iter; $i++)
  {
    $digest = sha512 ($digest);
  }

  my $data = random_hex_string (32);

  my $aes = Crypt::CBC->new ({
    key         => substr ($digest,  0, 32),
    cipher      => "Crypt::Rijndael",
    iv          => substr ($digest, 32, 16),
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "standard",
  });

  my $cry_master = (unpack ("H*", $aes->encrypt ($data)));

  my $hash = sprintf ('$bitcoin$%d$%s$%d$%s$%d$%d$%s$%d$%s',
    length ($cry_master),
    $cry_master,
    length ($salt),
    $salt,
    $salt_iter,
    length ($ckey),
    $ckey,
    length ($public_key),
    $public_key);

  return $hash;
}

sub module_verify_hash
{
  print "ERROR: verify currently not supported for Bitcoin/Litecoin wallet.dat because of unknown crypt data\n";

  exit (1);
}

1;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 8192; ## https://pagure.io/389-ds-base/blob/master/f/ldap/servers/plugins/pwdstorage/pbkdf2_pwd.c

  if (length $salt == 0)
  {
    $salt = random_bytes (16);
  }

  my $pbkdf2 = Crypt::PBKDF2->new (
    hash_class => 'HMACSHA2',
    iterations => $iter,
    output_len => 256,
    salt_len => 64,
  );

  my $p = $pbkdf2->generate ($word, $salt);

  my $decoded_hash = $pbkdf2->decode_string ($p);

  my $diter = $decoded_hash->{"iterations"};

  my $iterbytes = pack ('I', unpack ('N*', pack ('L*', $diter)));

  my $dsalt = $decoded_hash->{"salt"};

  my $dhash = $decoded_hash->{"hash"};

  my $tmp = $iterbytes . $dsalt . $dhash;

  my $hash = "{PBKDF2_SHA256}" . encode_base64 ($tmp, '');

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless (substr ($hash, 0, 15) eq '{PBKDF2_SHA256}');

  my $hashbytes = decode_base64 (substr ($hash, 15, length $hash));

  my $iterbytes = substr $hashbytes, 0, 4;

  my $iter = unpack ('N*', pack ('L*', unpack ('I', $iterbytes)));

  my $salt = substr $hashbytes, 4, 64;

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;

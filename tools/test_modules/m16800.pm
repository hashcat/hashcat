#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::SHA  qw (sha1);
use Digest::HMAC qw (hmac_hex);

sub module_constraints { [[8, 63], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $macap  = shift;
  my $macsta = shift;
  my $essid  = shift;

  if (!defined ($macap))
  {
    $macap = unpack ("H*", random_bytes (6));
  }

  if (!defined ($macsta))
  {
    $macsta = unpack ("H*", random_bytes (6));
  }

  if (!defined ($essid))
  {
    $essid = unpack ("H*", random_bytes (random_number (0, 32) & 0x1e));
  }

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => 4096,
    output_len => 32,
  );

  my $essid_bin = pack ("H*", $essid);

  my $pmk = $pbkdf2->PBKDF2 ($essid_bin, $word);

  my $macap_bin  = pack ("H*", $macap);
  my $macsta_bin = pack ("H*", $macsta);

  my $data = "PMK Name" . $macap_bin . $macsta_bin;

  my $pmkid = hmac_hex ($data, $pmk, \&sha1);

  my $hash = sprintf ("%s:%s:%s:%s", substr ($pmkid, 0, 32), $macap, $macsta, $essid);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split (/\:/, $hash);

  return unless scalar @data == 4;

  my (undef, $macap, $macsta, $essid) = @data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $macap, $macsta, $essid);

  return ($new_hash, $word);
}

1;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (hmac_sha1);
use Crypt::Mode::CBC;
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word      = shift;
  my $salt      = shift;
  my $user      = shift // "user";
  my $realm     = shift // "realm";

  my $mysalt = uc $realm;
  $mysalt = $mysalt . $user;

  # first we generate the 'seed'
  my $iter = 4096;
  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 32
  );

  my $b_seed = $pbkdf2->PBKDF2 ($mysalt, $word);

  # we can precompute this
  my $b_kerberos_nfolded = pack ("H*", '6b65726265726f737b9b5b2b93132b93');

  my $b_iv = pack ("H*", '0' x 32);

  # 'key_bytes' will be the AES key used to generate 'ki' (for final hmac-sha1)
  # and 'ke' (AES key to decrypt/encrypt the ticket)
  my $cbc         = Crypt::Mode::CBC->new ('AES', 0);
  my $b_key_bytes = $cbc->encrypt ($b_kerberos_nfolded, $b_seed, $b_iv);

  $b_key_bytes = $b_key_bytes . $cbc->encrypt ($b_key_bytes, $b_seed, $b_iv);

  my $tmp_hash = sprintf ('$krb5db$18$%s$%s$%s', $user, $realm, unpack ("H*", $b_key_bytes));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 6;

  shift @data;

  my $signature = shift @data;
  my $algorithm = shift @data;
  my $user      = shift @data;
  my $realm     = shift @data;

  return unless ($signature eq "krb5db");
  return unless ($algorithm eq "18");

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $user, $realm);

  return ($new_hash, $word);
}

1;

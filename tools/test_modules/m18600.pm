#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::GCrypt;
use Crypt::PBKDF2;
use Digest::SHA qw (sha1 sha1_hex);

sub module_constraints { [[0, 51], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 100000;
  my $iv    = shift // random_hex_string (2 * 8);
  my $plain = shift // random_hex_string (2 * 1024);

  my $b_iv    = pack ('H*', $iv);
  my $b_salt  = pack ('H*', $salt);
  my $b_plain = pack ('H*', $plain);

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 16
  );

  my $pass_hash = sha1 ($word);
  my $key       = $kdf->PBKDF2 ($b_salt, $pass_hash);

  my $cfb = Crypt::GCrypt->new
  (
    type      => 'cipher',
    algorithm => 'blowfish',
    mode      => 'cfb'
  );

  $cfb->start  ('encrypting');
  $cfb->setkey ($key);
  $cfb->setiv  ($b_iv);

  my $b_cipher = $cfb->encrypt ($b_plain);

  $cfb->finish ();

  my $cipher   = unpack ('H*', $b_cipher);
  my $checksum = sha1_hex ($b_plain);

  my $hash = '$odf$'."*0*0*$iter*16*$checksum*8*$iv*16*$salt*0*$cipher";

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  # tokenize
  my @data = split ('\*', $hash);

  return unless scalar @data == 12;

  my $signature   = shift @data;
  my $cipher_type = shift @data;
  my $cs_type     = shift @data;
  my $iter        = shift @data;
  my $cs_len      = shift @data;
  my $cs          = shift @data;
  my $iv_len      = shift @data;
  my $iv          = shift @data;
  my $salt_len    = shift @data;
  my $salt        = shift @data;
  my $unused      = shift @data;
  my $cipher      = shift @data;

  # validate
  return unless $signature   eq '$odf$';
  return unless $cipher_type eq '0';
  return unless $cs_type     eq '0';
  return unless $cs_len      eq '16';
  return unless $iv_len      eq '8';
  return unless $salt_len    eq '16';
  return unless $unused      eq '0';
  return unless defined $cipher;

  # decrypt
  my $b_iv     = pack ('H*', $iv);
  my $b_salt   = pack ('H*', $salt);
  my $b_cipher = pack ('H*', $cipher);

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 16
  );

  my $pass_hash = sha1 ($word);
  my $key       = $kdf->PBKDF2 ($b_salt, $pass_hash);

  my $cfb = Crypt::GCrypt->new(
    type      => 'cipher',
    algorithm => 'blowfish',
    mode      => 'cfb'
  );

  $cfb->start  ('decrypting');
  $cfb->setkey ($key);
  $cfb->setiv  ($b_iv);

  my $b_plain = $cfb->decrypt ($b_cipher);

  $cfb->finish ();

  my $plain = unpack ('H*', $b_plain);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $iv, $plain);

  return ($new_hash, $word);
}

1;

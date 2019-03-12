#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word           = shift;
  my $salt           = shift; # unused
  my $version        = shift // 5;
  my $iter           = shift // 10000;
  my $user_salt      = shift // random_hex_string (128);
  my $ck_salt        = shift // random_hex_string (128);
  my $user_iv        = shift // random_hex_string (32);
  my $masterkey_blob = shift; # use this as hint regular or verify call

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 32
  );

  my $user_salt_bin = pack ("H*", $user_salt);

  my $key_bin = $kdf->PBKDF2 ($user_salt_bin, $word);

  my $iv_bin = pack ("H*", $user_iv);

  my $cipher = Crypt::CBC->new ({
    key         => $key_bin,
    cipher      => "Crypt::Rijndael",
    iv          => $iv_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "standard",
  });

  my $decrypted_bin = random_bytes (83);

  if (defined $masterkey_blob)
  {
    my $encrypted_bin = pack ("H*", $masterkey_blob);

    my $test_bin = $cipher->decrypt ($encrypted_bin);

    if (length ($test_bin) == 83)
    {
      $decrypted_bin = $test_bin;
    }
  }

  my $encrypted_bin = $cipher->encrypt ($decrypted_bin);

  my $hash = sprintf ("\$ab\$%u*0*%u*%s*%s*%s*%s", $version, $iter, $user_salt, $ck_salt, $user_iv, unpack ("H*", $encrypted_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my ($tag, $cipher, $iter, $user_salt, $ck_salt, $user_iv, $masterkey_blob) = split (/\*/, $hash);

  my (undef, $signature, $version) = split (/\$/, $tag);

  return unless $signature eq "ab";
  return unless $cipher    eq "0";

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $version, $iter, $user_salt, $ck_salt, $user_iv, $masterkey_blob);

  return ($new_hash, $word);
}

1;

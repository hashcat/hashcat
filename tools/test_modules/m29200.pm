#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##
## Further credits:
## The password-storage algorithm used by Radmin 3 was analyzed and made public
## by synacktiv:
## https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html
##

use strict;
use warnings;

use Digest::SHA qw (sha1 sha1_hex);
use Crypt::OpenSSL::Bignum::CTX;
use Encode;

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

my $GENERATOR = "05";
my $MODULUS   = "9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96db70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a79021c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb0fdbaf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d6091acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f1930ebc4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f";

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $user = shift;

  if (! defined ($user))
  {
    $user = random_mixedcase_string (int (rand (128)));

    $user = encode ('UTF16-LE', $user);
  }

  my $word_utf16 = encode ("UTF-16LE", $word);

  my $exponent = sha1_hex ($salt . sha1 ($user . ":" . $word_utf16));

  my $g = Crypt::OpenSSL::Bignum->new_from_hex ($GENERATOR);
  my $m = Crypt::OpenSSL::Bignum->new_from_hex ($MODULUS);
  my $e = Crypt::OpenSSL::Bignum->new_from_hex ($exponent);

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new ();

  my $pow = $g->mod_exp ($e, $m, $ctx);

  my $res = $pow->to_bin ();

  # IMPORTANT step:

  $res = "\x00" x (256 - length ($res)) . $res; # pad it to exactly 256 bytes


  my $hash = sprintf ("\$radmin3\$%s*%s*%s", unpack ("H*", $user), unpack ("H*", $salt), unpack ("H*", $res));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 9) eq '$radmin3$';

  my ($user, $salt, $verifier) = split ('\*', substr ($hash, 9));

  return unless defined $user;
  return unless defined $salt;
  return unless defined $verifier;

  return unless length ($salt) == 64;

  return unless $user     =~ m/^[0-9a-fA-F]*$/;
  return unless $salt     =~ m/^[0-9a-fA-F]*$/;
  return unless $verifier =~ m/^[0-9a-fA-F]*$/;

  $salt = pack ("H*", $salt);
  $user = pack ("H*", $user);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $user);

  return ($new_hash, $word);
}

1;

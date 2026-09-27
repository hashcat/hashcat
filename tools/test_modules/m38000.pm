#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::Bignum::CTX;

use Digest::SHA qw (sha256);

sub module_constraints { [[0, 256], [32, 32], [0, 256], [32, 32], [-1, -1]] }

my $CONV_TO_M_HEX = "555555555555555555555555555555555555555555555555555555555552db9c";

sub setup_curve25519_weierstrass
{
  my $ctx = Crypt::OpenSSL::Bignum::CTX->new ();

  my $prime = Crypt::OpenSSL::Bignum->new_from_hex ("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
  my $a_w   = Crypt::OpenSSL::Bignum->new_from_hex ("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144");
  my $b_w   = Crypt::OpenSSL::Bignum->new_from_hex ("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864");

  my $method = Crypt::OpenSSL::EC::EC_GFp_simple_method ();
  my $group  = Crypt::OpenSSL::EC::EC_GROUP::new ($method);

  Crypt::OpenSSL::EC::EC_GROUP::set_curve_GFp ($group, $prime, $a_w, $b_w, $ctx);

  my $Gx = Crypt::OpenSSL::Bignum->new_from_hex ("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a");
  my $Gy = Crypt::OpenSSL::Bignum->new_from_hex ("5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14");

  my $G = Crypt::OpenSSL::EC::EC_POINT::new ($group);

  Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp ($group, $G, $Gx, $Gy, $ctx);

  my $order    = Crypt::OpenSSL::Bignum->new_from_hex ("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
  my $cofactor = Crypt::OpenSSL::Bignum->new_from_hex ("08");

  Crypt::OpenSSL::EC::EC_GROUP::set_generator ($group, $G, $order, $cofactor);

  return ($group, $G, $prime, $ctx);
}

sub compute_verifier
{
  my $word     = shift;
  my $username = shift;
  my $salt_hex = shift;

  my ($group, $G, $prime, $ctx) = setup_curve25519_weierstrass ();

  # step 1: inner = SHA256(username + ":" + password)

  my $inner = sha256 ($username . ":" . $word);

  # step 2: scalar = SHA256(salt + inner)

  my $salt = pack ("H*", $salt_hex);

  my $scalar_bytes = sha256 ($salt . $inner);

  my $scalar = Crypt::OpenSSL::Bignum->new_from_hex (unpack ("H*", $scalar_bytes));

  # step 3: point = scalar * G

  my $result = Crypt::OpenSSL::EC::EC_POINT::new ($group);

  my $zero = Crypt::OpenSSL::Bignum->zero ();

  Crypt::OpenSSL::EC::EC_POINT::mul ($group, $result, $zero, $G, $scalar, $ctx);

  my $rx = Crypt::OpenSSL::Bignum->new ();
  my $ry = Crypt::OpenSSL::Bignum->new ();

  Crypt::OpenSSL::EC::EC_POINT::get_affine_coordinates_GFp ($group, $result, $rx, $ry, $ctx);

  # step 4: x_mont = (x_weierstrass + conversion_to_m) mod p

  my $conv_to_m = Crypt::OpenSSL::Bignum->new_from_hex ($CONV_TO_M_HEX);

  my $x_sum = $rx->add ($conv_to_m);

  my ($div, $x_mont) = $x_sum->div ($prime, $ctx);

  my $x_hex = lc ($x_mont->to_hex ());

  $x_hex = ("0" x (64 - length ($x_hex))) . $x_hex;

  # step 5: verifier = first 28 bytes (56 hex chars)

  return substr ($x_hex, 0, 56);
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $username = "hashcat";

  if (defined ($salt))
  {
    # salt is passed as hex string (32 chars)
  }
  else
  {
    $salt = random_hex_string (32);
  }

  my $verifier = compute_verifier ($word, $username, $salt);

  my $hash = sprintf ("\$mikrotik\$%s\$%s\$%s", $username, $salt, $verifier);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = rindex ($line, ":");

  return if ($idx < 1);

  my $hash_in = substr ($line, 0, $idx);
  my $word    = substr ($line, $idx + 1);

  return unless (substr ($hash_in, 0, 10) eq "\$mikrotik\$");

  my $rest = substr ($hash_in, 10);

  # parse: username$salt_hex$verifier_hex

  my @parts = split ('\$', $rest);

  return if (scalar @parts != 3);

  my $username     = $parts[0];
  my $salt_hex     = $parts[1];
  my $verifier_hex = $parts[2];

  return if (length ($salt_hex) != 32);
  return if (length ($verifier_hex) != 56);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_verifier = compute_verifier ($word_packed, $username, $salt_hex);

  return unless ($new_verifier eq $verifier_hex);

  my $new_hash = sprintf ("\$mikrotik\$%s\$%s\$%s", $username, $salt_hex, $new_verifier);

  return ($new_hash, $word);
}

1;

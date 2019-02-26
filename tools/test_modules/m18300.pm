#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 20000;
  my $Z_PK = shift // 2;
  my $blob = shift;

  if (length $salt == 0)
  {
    $salt = random_hex_string (32);
  }

  my $salt_bin = pack ("H*", $salt);

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32,
  );

  my $KEK = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $blob_bin;

  my $A;
  my $B;
  my $P1;
  my $P2;
  my $P3;
  my $P4;

  if (defined $blob)
  {
    $blob_bin = pack ("H*", $blob);

    $A  = substr ($blob_bin,  0, 8);
    $P1 = substr ($blob_bin,  8, 8);
    $P2 = substr ($blob_bin, 16, 8);
    $P3 = substr ($blob_bin, 24, 8);
    $P4 = substr ($blob_bin, 32, 8);

    for (my $j = 5; $j >= 0; $j--)
    {
      # N = 4

      $B  = $A;
      $B ^= pack ("Q>", (4 * $j + 4));
      $B .= $P4;
      $B  = $aes->decrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $P4 = substr ($B, 8, 8);

      # N = 3

      $B  = $A;
      $B ^= pack ("Q>", (4 * $j + 3));
      $B .= $P3;
      $B  = $aes->decrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $P3 = substr ($B, 8, 8);

      # N = 2

      $B  = $A;
      $B ^= pack ("Q>", (4 * $j + 2));
      $B .= $P2;
      $B  = $aes->decrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $P2 = substr ($B, 8, 8);

      # N = 1

      $B  = $A;
      $B ^= pack ("Q>", (4 * $j + 1));
      $B .= $P1;
      $B  = $aes->decrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $P1 = substr ($B, 8, 8);
    }

    if ($A eq "\xa6" x 8)
    {
      for (my $j = 0; $j <= 5; $j++)
      {
        # N = 1

        $B  = $A;
        $B .= $P1;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 1));
        $P1 = substr ($B, 8, 8);

        # N = 2

        $B  = $A;
        $B .= $P2;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 2));
        $P2 = substr ($B, 8, 8);

        # N = 3

        $B  = $A;
        $B .= $P3;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 3));
        $P3 = substr ($B, 8, 8);

        # N = 4

        $B  = $A;
        $B .= $P4;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 4));
        $P4 = substr ($B, 8, 8);
      }

      $blob_bin = $A . $P1 . $P2 . $P3 . $P4;
    }
    else
    {
      $blob_bin = "\xff" x 40;
    }
  }
  else
  {
    $A  = "\xa6" x 8;
    $P1 = "\xff" x 8;
    $P2 = "\xff" x 8;
    $P3 = "\xff" x 8;
    $P4 = "\xff" x 8;

    for (my $j = 0; $j <= 5; $j++)
    {
      # N = 1

      $B  = $A;
      $B .= $P1;
      $B  = $aes->encrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $A ^= pack ("Q>", (4 * $j + 1));
      $P1 = substr ($B, 8, 8);

      # N = 2

      $B  = $A;
      $B .= $P2;
      $B  = $aes->encrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $A ^= pack ("Q>", (4 * $j + 2));
      $P2 = substr ($B, 8, 8);

      # N = 3

      $B  = $A;
      $B .= $P3;
      $B  = $aes->encrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $A ^= pack ("Q>", (4 * $j + 3));
      $P3 = substr ($B, 8, 8);

      # N = 4

      $B  = $A;
      $B .= $P4;
      $B  = $aes->encrypt ($B, $KEK);
      $A  = substr ($B, 0, 8);
      $A ^= pack ("Q>", (4 * $j + 4));
      $P4 = substr ($B, 8, 8);
    }

    $blob_bin = $A . $P1 . $P2 . $P3 . $P4;
  }

  my $hash = sprintf ('$fvde$%d$%d$%s$%d$%s', $Z_PK, length ($salt_bin), unpack ("H*", $salt_bin), $iter, unpack ("H*", $blob_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split ('\$', $digest);

  return unless scalar @data == 7;

  shift @data;

  my $signature = shift @data;

  return unless ($signature eq 'fvde');

  my $Z_PK = shift @data;

  return unless ($Z_PK eq '2');

  my $salt_length = shift @data;

  return unless ($salt_length eq '16');

  my ($ZCRYPTOSALT, $ZCRYPTOITERATIONCOUNT, $ZCRYPTOWRAPPEDKEY) = @data;

  my $salt = $ZCRYPTOSALT;
  my $iter = $ZCRYPTOITERATIONCOUNT;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $ZCRYPTOSALT, $ZCRYPTOITERATIONCOUNT, $Z_PK, $ZCRYPTOWRAPPEDKEY);

  return ($new_hash, $word);
}

1;


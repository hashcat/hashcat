#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::Mode::ECB;

sub module_constraints { [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 50000;
  my $uidkey     = shift // random_hex_string (32);
  my @classkeys  = @_;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => 1,
    output_len => 32
  );

  my $salt_bin = pack ("H*", $salt);

  my $data = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $uidkey_bin = pack ("H*", $uidkey);

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  my $data0 = substr ($data,  0, 16);
  my $data1 = substr ($data, 16, 16);

  my $iterated_key0 = $data0;
  my $iterated_key1 = $data1;

  my $iv = "\x00" x 16;

  for (my $i = 0, my $xorkey = 1; $i < $iterations; $i++, $xorkey++)
  {
    my $xorkey_bin = pack ("LLLL", $xorkey, $xorkey, $xorkey, $xorkey);

    my $in0 = $data0 ^ $iv ^ $xorkey_bin;

    $iv = $m->encrypt ($in0, $uidkey_bin);

    $iterated_key0 ^= $iv;

    my $in1 = $data1 ^ $iv ^ $xorkey_bin;

    $iv = $m->encrypt ($in1, $uidkey_bin);

    $iterated_key1 ^= $iv;
  }

  my $iterated_key = $iterated_key0 . $iterated_key1;

  my $UIDO_BACKUP_KEY = 12008468691120727718; # 0xa6a6a6a6a6a6a6a6

  if (scalar @classkeys)
  {
    my $classkey1_bin = pack ("H*", $classkeys[0]);

    my ($A, $R) = uido_aes_unwrap ($iterated_key, $classkey1_bin);

    if ($A != $UIDO_BACKUP_KEY)
    {
      $classkeys[0] = "0" x 80;
    }
  }
  else
  {
    my $max_number = 18446744073709551615; # 0xffffffffffffffff

    my @R;

    for (my $i = 0; $i < 4; $i++)
    {
      $R[$i] = random_number (0, $max_number);
    }

    my $classkey1_bin = uido_aes_wrap ($iterated_key, $UIDO_BACKUP_KEY, \@R);

    push (@classkeys, unpack ("H*", $classkey1_bin));
  }

  my $hash = sprintf ("\$uido\$%s\$%s\$%u\$%s", unpack ("H*", $uidkey_bin), unpack ("H*", $salt_bin), $iterations, join ("\$", @classkeys));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  shift @data;

  my $signature  = shift @data;
  my $uidkey     = shift @data;
  my $salt       = shift @data;
  my $iterations = shift @data;

  return unless ($signature eq 'uido');

  return unless defined $uidkey;
  return unless length ($uidkey) == 32;
  return unless defined $salt;
  return unless defined $iterations;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $uidkey, @data);

  return ($new_hash, $word);
}

sub uido_aes_wrap
{
  my $key = shift;
  my $A   = shift;
  my $R_l = shift;

  my $k = scalar (@$R_l);
  my $n = $k + 1;

  my @R;

  for (my $i = 0; $i < $n; $i++)
  {
    $R[$i] = @$R_l[$i];
  }

  # AES mode ECB

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  # main wrap loop

  my ($i, $j, $a);

  for ($j = 0; $j <= 5; $j++)
  {
    for ($i = 1, $a = 0; $i <= $k; $i++, $a++)
    {
      my $input;

      $input  = pack ("Q>", $A);
      $input .= pack ("Q>", $R[$a]);

      my $t = $m->encrypt ($input, $key);

      $A     = unpack ("Q>", substr ($t, 0, 8));
      $A    ^= $k * $j + $i;

      $R[$a] = unpack ("Q>", substr ($t, 8, 8));
    }
  }

  my $WPKY = pack ("Q>", $A);

  for (my $i = 0; $i < $k; $i++)
  {
    $WPKY .= pack ("Q>", $R[$i]);
  }

  return $WPKY;
}

sub uido_aes_unwrap
{
  my $key  = shift;
  my $WPKY = shift;

  my @B;

  for (my $i = 0; $i < length ($WPKY) / 8; $i++)
  {
    $B[$i] = unpack ("Q>", substr ($WPKY, $i * 8, 8));
  }

  my $n = scalar (@B);
  my $k = $n - 1;

  my @R;

  for (my $i = 0; $i < $k; $i++)
  {
    $R[$i] = $B[$i + 1];
  }

  # AES mode ECB

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  # main unwrap loop

  my $A = $B[0];

  my ($i, $j, $a);

  for ($j = 5; $j >= 0; $j--)
  {
    for ($i = $k, $a = $k - 1; $i > 0; $i--, $a--)
    {
      my $input;

      $input  = pack ("Q>", $A ^ ($k * $j + $i));
      $input .= pack ("Q>", $R[$a]);

      my $t = $m->decrypt ($input, $key);

      $A     = unpack ("Q>", substr ($t, 0, 8));
      $R[$a] = unpack ("Q>", substr ($t, 8, 8));
    }
  }

  return ($A, \@R);
}

1;

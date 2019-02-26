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
  my $iterations = shift // 10000;
  my $wpky_param = shift;
  my $DPIC       = shift // 1000;
  my $DPSL       = shift // random_bytes (20);

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => $iterations,
    output_len => 32
  );

  $salt = pack ("H*", $salt);

  my $ITUNES_BACKUP_KEY = 12008468691120727718;

  my $WPKY = "\x00" x 40;

  my $pbkdf2x = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2'),
    iterations => $DPIC,
    output_len => 32
  );

  my $key_dpsl = $pbkdf2x->PBKDF2 ($DPSL, $word);

  my $key = $pbkdf2->PBKDF2 ($salt, $key_dpsl);

  if (defined $wpky_param)
  {
    my ($A, $R) = itunes_aes_unwrap ($key, $wpky_param);

    if ($A == $ITUNES_BACKUP_KEY)
    {
      $WPKY = itunes_aes_wrap ($key, $A, $R);
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

    $WPKY = itunes_aes_wrap ($key, $ITUNES_BACKUP_KEY, \@R);
  }

  my $hash = sprintf ("\$itunes_backup\$*10*%s*%i*%s*%i*%s", unpack ("H*", $WPKY), $iterations, unpack ("H*", $salt), $DPIC, unpack ("H*", $DPSL));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my ($signature, $version, $wpky_encoded, $iterations, $salt, $dpic, $dpsl_encoded) = split ('\*', $hash);

  return unless ($signature eq '$itunes_backup$');
  return unless ($version eq '10');
  return unless length ($wpky_encoded) == 80;
  return unless defined $iterations;
  return unless defined $salt;
  return unless defined $dpic;
  return unless defined $dpsl_encoded;

  my $wpky = pack ("H*", $wpky_encoded);
  my $dpsl = pack ("H*", $dpsl_encoded);

  $iterations = int ($iterations);

  $dpic = int ($dpic);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $wpky, $dpic, $dpsl);

  return ($new_hash, $word);
}

sub itunes_aes_wrap
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

sub itunes_aes_unwrap
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

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);
use Crypt::CBC;

sub module_constraints { [[0, 256], [8, 8], [0, 31], [8, 8], [-1, -1]] }

my $BASE58_CHARS   = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
my $BITCOINJ_CHARS = ".abcdefghijklmnopqrstuvwxyz";

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift;

  my $word_salt = $word . $salt;

  my $key1 = md5 (        $word_salt);
  my $key2 = md5 ($key1 . $word_salt);
  my $iv   = md5 ($key2 . $word_salt);

  my $aes_cbc = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    key         => $key1 . $key2,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $type = 0; # 0: MultiBit Classic MD5, 1: KnCGroup Bitcoin Wallet, 2: bitcoinj
  my $key = "";

  if (! defined ($data))
  {
    $type = random_number (0, 2);

    if ($type == 0)
    {
      my @chars_at_start = ('K', 'L', 'Q', '5');

      $data = $chars_at_start[random_number (0, scalar (@chars_at_start) - 1)];

      for (my $i = 1; $i < 32; $i++)
      {
        $data .= substr ($BASE58_CHARS, random_number (0, length ($BASE58_CHARS) - 1), 1);
      }
    }
    elsif ($type == 1)
    {
      $data  = "\n";
      $data .= chr (random_number (0, 127));
      $data .= "org.";

      for (my $i = 6; $i < 32; $i++)
      {
        $data .= substr ($BITCOINJ_CHARS, random_number (0, length ($BITCOINJ_CHARS) - 1), 1);
      }
    }
    elsif ($type == 2)
    {
      # Full string would be:
      # "# KEEP YOUR PRIVATE KEYS SAFE! Anyone who can read this can spend your Bitcoins."

      $data = '# KEEP YOUR PRIVATE KEYS SAFE! A';
    }

    $key = $aes_cbc->encrypt ($data);
  }
  else
  {
    $key = $aes_cbc->decrypt ($data);

    # verification step:

    # first char of $key must be K, L, Q, 5, # or \n

    my $char_at_start = substr ($key, 0, 1);

    if (($char_at_start eq 'K') ||
        ($char_at_start eq 'L') ||
        ($char_at_start eq 'Q') ||
        ($char_at_start eq '5'))
    {
      my $error = 0;

      for (my $i = 1; $i < 32; $i++) # start with 1 (we already checked first char)
      {
        my $c = substr ($key, $i, 1);

        my $idx = index ($BASE58_CHARS, $c);

        next if ($idx >= 0);

        $error = 1;

        last;
      }

      if ($error == 0)
      {
        $key = $data;
      }
    }
    elsif ($char_at_start eq "\n") # bitcoinj
    {
      my $second_char = substr ($key, 1, 1);

      if (ord ($second_char) < 128)
      {
        if (substr ($key, 2, 4) eq "org.")
        {
          my $error = 0;

          for (my $i = 6; $i < 14; $i++) # start with 6 (we already checked first chars)
          {
            my $c = substr ($key, $i, 1);

            my $idx = index ($BITCOINJ_CHARS, $c);

            next if ($idx >= 0);

            $error = 1;

            last;
          }

          if ($error == 0)
          {
            $key = $data;
          }
        }
      }
    }
    elsif ($char_at_start eq '#')  # KnCGroup Bitcoin Wallet
    {
      if (substr ($key, 0, 16) eq '# KEEP YOUR PRIV')
      {
        $key = $data;
      }
    }
  }

  my $hash = sprintf ("\$multibit\$1*%s*%s", unpack ("H*", $salt), unpack ("H*", $key));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 12) eq '$multibit$1*';

  $idx = index ($hash, '*', 12);

  return unless $idx == 28;

  my $salt_hex = substr ($hash, 12, 16); # 28 - 12 = 16
  my $data_hex = substr ($hash, 29);

  return unless length ($salt_hex) == 16;
  return unless length ($data_hex) == 64;

  my $salt = pack ("H*", $salt_hex);
  my $data = pack ("H*", $data_hex);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $data);

  return ($new_hash, $word);
}

1;

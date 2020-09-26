#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Crypt::CBC;

sub module_constraints { [[0, 56], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

my $BUF_SIZE = 0x10000;

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift;

  my $comb = $salt . $word;
  my $len  = length ($comb);

  my $buf = "";

  for (my $i = 0; $i < $BUF_SIZE; $i += $len)
  {
    $buf .= $comb;
  }

  # IMPORTANT: we need to truncate the buffer to $BUF_SIZE:

  $buf = substr ($buf, 0, $BUF_SIZE);

  my $key = sha256 ($buf);

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    iv          => "\x00" x 16,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  if (defined ($data)) # decrypt
  {
    my $plain_text = $aes->decrypt ($data);

    my $part1 = substr ($plain_text,  0, 64);
    my $part2 = substr ($plain_text, 64, 32);

    my $hash = sha256 ($part1);

    if ($hash ne $part2) # wrong => fake the data
    {
      $data = "\x00" x length ($data); # 64 + 32 = 96
    }
  }
  else # encrypt
  {
    $data = random_bytes (64);

    my $hash = sha256 ($data);

    $data = $aes->encrypt ($data . $hash);
  }

  return sprintf ("\$bcve\$3\$08\$%s\$%s", unpack ("H*", $salt), unpack ("H*", $data));
}

sub module_verify_hash
{
  my $line = shift;

  my $idx1 = index ($line, ':');

  return if ($idx1 < 1);

  my $hash = substr ($line, 0, $idx1);
  my $word = substr ($line, $idx1 + 1);

  return if (substr ($hash, 0, 8) ne "\$bcve\$3\$");

  $idx1 = index ($hash, '$', 8);

  return if ($idx1 < 1);

  # crypto type

  my $crypto_type = substr ($hash, 8, $idx1 - 8);

  return unless ($crypto_type eq "08");

  # salt

  my $idx2 = index ($hash, '$', $idx1 + 1);

  my $salt = substr ($hash, $idx1 + 1, $idx2 - $idx1 - 1);

  return unless ($salt =~ m/^[0-9a-fA-F]+$/);

  # data

  my $data = substr ($hash, $idx2 + 1);

  return unless ($data =~ m/^[0-9a-fA-F]+$/);

  # convert to hex:

  $salt = pack ("H*", $salt);
  $data = pack ("H*", $data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $data);

  return ($new_hash, $word);
}

1;

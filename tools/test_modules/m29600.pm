#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use Crypt::CBC;
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

my $ITERATIONS = 100;

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iv   = shift;
  my $data = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => $ITERATIONS,
    output_len => 32
  );

  my $key = $pbkdf2->PBKDF2 ($salt, $word);

  if (! defined ($iv))
  {
    $iv = random_bytes (16);
  }

  my $cipher = Crypt::CBC->new ({
    key         => $key,
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    literal_key => 1,
    keysize     => 32,
    header      => "none",
    padding     => "none",
  });

  if (! defined ($data))
  {
    $data = random_hex_string (64);

    $data .= "\x10" x 16 # padding block
  }
  else
  {
    $data = $cipher->decrypt ($data);

    my $padding_block = substr ($data, 64, 16);

    if ($padding_block ne "\x10" x 16)
    {
      $data = "\x00" x 80; # FAKE data (length: 64 + 16)
    }
  }

  my $encrypted_data = $cipher->encrypt ($data);

  my $hash = sprintf ("%s%s%s", unpack ("H*", $salt), unpack ("H*", $iv), encode_base64 ($encrypted_data, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (":", $line);

  return unless (defined ($hash));
  return unless (defined ($word));

  return unless (length ($hash) == (32 + 32 + 108));

  my $salt = substr ($hash,  0,  32);
  my $iv   = substr ($hash, 32,  32);
  my $data = substr ($hash, 64, 108); # or until the end

  return unless ($salt =~ m/^[0-9a-fA-F]{32}$/);
  return unless ($iv   =~ m/^[0-9a-fA-F]{32}$/);
  return unless ($data =~ m/^[A-Za-z0-9+\/=]{108}$/);

  $salt = pack ("H*", $salt);
  $iv   = pack ("H*", $iv);
  $data = decode_base64 ($data);

  return unless (length ($data) == (64 + 16)); # 80

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iv, $data);

  return ($new_hash, $word);
}

1;

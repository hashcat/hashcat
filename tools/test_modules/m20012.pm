#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64);
use Encode;

sub module_constraints { [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]] }

sub aes_encrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $data_base64 = encode_base64 ($data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import AES
import base64

key1 = base64.b64decode (key_main)
key2 = base64.b64decode (key_tweak)

key = (key1, key2)

cipher = AES.new (key, AES.MODE_XTS)

sequence = b"\x01"

encrypted = cipher.encrypt (base64.b64decode (data), sequence)

print (encrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data_base64"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

  return $output_buf;
}

sub aes_decrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $data_base64 = encode_base64 ($data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import AES
import base64

key1 = base64.b64decode (key_main)
key2 = base64.b64decode (key_tweak)

key = (key1, key2)

cipher = AES.new (key, AES.MODE_XTS)

sequence = b"\x01"

decrypted = cipher.decrypt (base64.b64decode (data), sequence)

print (decrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data_base64"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

  $output_buf = pack ("H*", $output_buf);

  return $output_buf;
}

sub twofish_encrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $data_base64 = encode_base64 ($data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import python_Twofish
import base64

key1 = base64.b64decode (key_main)
key2 = base64.b64decode (key_tweak)

key = (key1, key2)

cipher = python_Twofish.new (key, python_Twofish.MODE_XTS)

sequence = b"\x01"

encrypted = cipher.encrypt (base64.b64decode (data), sequence)

print (encrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data_base64"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

  return $output_buf;
}

sub twofish_decrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $data_base64 = encode_base64 ($data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import python_Twofish
import base64

key1 = base64.b64decode (key_main)
key2 = base64.b64decode (key_tweak)

key = (key1, key2)

cipher = python_Twofish.new (key, python_Twofish.MODE_XTS)

sequence = b"\x01"

decrypted = cipher.decrypt (base64.b64decode (data), sequence)

print (decrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data_base64"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

  $output_buf = pack ("H*", $output_buf);

  return $output_buf;
}

sub serpent_encrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $data_base64 = encode_base64 ($data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import python_Serpent
import base64

key1 = base64.b64decode (key_main)
key2 = base64.b64decode (key_tweak)

key = (key1, key2)

cipher = python_Serpent.new (key, python_Serpent.MODE_XTS)

sequence = b"\x01"

encrypted = cipher.encrypt (base64.b64decode (data), sequence)

print (encrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data_base64"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

  return $output_buf;
}

sub serpent_decrypt
{
  my $key_main  = shift;
  my $key_tweak = shift;
  my $data      = shift;

  my $data_base64 = encode_base64 ($data, "");

  my $python_code = <<'END_CODE';

from CryptoPlus.Cipher import python_Serpent
import base64

key1 = base64.b64decode (key_main)
key2 = base64.b64decode (key_tweak)

key = (key1, key2)

cipher = python_Serpent.new (key, python_Serpent.MODE_XTS)

sequence = b"\x01"

decrypted = cipher.decrypt (base64.b64decode (data), sequence)

print (decrypted.hex ())

END_CODE

  # replace code with these values

  $python_code =~ s/key_main/"$key_main"/;
  $python_code =~ s/key_tweak/"$key_tweak"/;
  $python_code =~ s/data/"$data_base64"/;

  my $output_buf = `python3 -c '$python_code'`;

  $output_buf =~ s/[\r\n]//g;

  $output_buf = substr ($output_buf, 128); # remove the "garbage" from the start (encrypted salt)

  $output_buf = pack ("H*", $output_buf);

  return $output_buf;
}

sub verify_data
{
  my $data = shift;

  if (length ($data) < 16)
  {
    return 0;
  }

  if (substr ($data, 0, 4) ne "DCRP")
  {
    return 0;
  }

  my $flags = unpack ("H*", substr ($data, 8, 6));

  if (($flags ne "020004000000") && ($flags ne "020005000000") && ($flags ne "020008000000"))
  {
    return 0;
  }

  return 1;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $data = shift // "";

  my $iter = 1000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter,
    output_len => 128
  );

  my $word_utf16le = encode ("UTF-16LE", $word);

  my $salt_bin = pack ("H*", $salt);

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word_utf16le);

  my $key1 = encode_base64 (substr ($key,  0, 32), "");
  my $key2 = encode_base64 (substr ($key, 32, 32), "");
  my $key3 = encode_base64 (substr ($key, 64, 32), "");
  my $key4 = encode_base64 (substr ($key, 96, 32), "");

  my $algo = random_number (1, 6);

  my $diskcryptor_data = "";

  $diskcryptor_data .= $salt_bin;

  if (length ($data) == 0) # normal case
  {
    $diskcryptor_data .= "DCRP";

    $diskcryptor_data .= random_bytes (4);

    my $flags = random_number (1, 3);

    if ($flags == 1)
    {
      $diskcryptor_data .= pack ("H*", "02000400");
    }
    elsif ($flags == 2)
    {
      $diskcryptor_data .= pack ("H*", "02000500");
    }
    else
    {
      $diskcryptor_data .= pack ("H*", "02000800");
    }

    $diskcryptor_data .= "\x00" x (2048 - length ($diskcryptor_data)); # fill it up to 2048 bytes
  }
  else # verify
  {
    # decrypt the data and verify:

    $algo = 1;

    my $output_buf = aes_decrypt ($key1, $key2, $data);

    if (verify_data ($output_buf) == 0)
    {
      $algo = 2;

      $output_buf = twofish_decrypt ($key1, $key2, $data);

      if (verify_data ($output_buf) == 0)
      {
        $algo = 3;

        $output_buf = serpent_decrypt ($key1, $key2, $data);

        if (verify_data ($output_buf) == 0)
        {
          $algo = 4;

          $output_buf = aes_decrypt     ($key2, $key4, $data);
          $output_buf = twofish_decrypt ($key1, $key3, $salt_bin . $output_buf);

          if (verify_data ($output_buf) == 0)
          {
            $algo = 5;

            $output_buf = twofish_decrypt ($key2, $key4, $data);
            $output_buf = serpent_decrypt ($key1, $key3, $salt_bin . $output_buf);

            if (verify_data ($output_buf) == 0)
            {
              $algo = 6;

              $output_buf = serpent_decrypt ($key2, $key4, $data);
              $output_buf = aes_decrypt     ($key1, $key3, $salt_bin . $output_buf);

              if (verify_data ($output_buf) == 0)
              {
                return;
              }
            }
          }
        }
      }
    }

    $diskcryptor_data .= $output_buf;
  }

  my $hash_buf = "";

  if ($algo == 1)
  {
    $hash_buf = aes_encrypt ($key1, $key2, $diskcryptor_data);
  }
  elsif ($algo == 2)
  {
    $hash_buf = twofish_encrypt ($key1, $key2, $diskcryptor_data);
  }
  elsif ($algo == 3)
  {
    $hash_buf = serpent_encrypt ($key1, $key2, $diskcryptor_data);
  }
  elsif ($algo == 4)
  {
    $hash_buf = twofish_encrypt ($key1, $key3, $diskcryptor_data);
    $hash_buf = aes_encrypt     ($key2, $key4, $salt_bin . pack ("H*", $hash_buf));
  }
  elsif ($algo == 5)
  {
    $hash_buf = serpent_encrypt ($key1, $key3, $diskcryptor_data);
    $hash_buf = twofish_encrypt ($key2, $key4, $salt_bin . pack ("H*", $hash_buf));
  }
  else
  {
    $hash_buf = aes_encrypt     ($key1, $key3, $diskcryptor_data);
    $hash_buf = serpent_encrypt ($key2, $key4, $salt_bin . pack ("H*", $hash_buf));
  }

  my $hash = sprintf ("\$diskcryptor\$0*%s%s", $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  return unless (substr ($hash_in, 0, 13) eq "\$diskcryptor\$");

  my $word = substr ($line, $index1 + 1);

  my $index2 = index ($hash_in, "\*", 13);

  return if $index2 < 1;

  my $version = substr ($hash_in, 13, $index2 - 13);

  return unless ($version eq "0");

  my $data = substr ($hash_in, $index2 + 1);

  return unless (length ($data) == 4096);

  my $salt = substr ($data, 0, 128);

  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  $data = pack ("H*", $data);

  my $new_hash = module_generate_hash ($word, $salt, $data);

  return ($new_hash, $word);
}

1;

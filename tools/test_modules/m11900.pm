#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1000;
  my $out_len    = shift // 32;

  #
  # call PHP here - WTF
  #

  # sanitize $word_buf and $salt_buf:

  my $word_buf_base64 = encode_base64 ($word, "");
  my $salt_buf_base64 = encode_base64 ($salt, "");

  # sanitize lenghs

  $out_len = int ($out_len);

  # output is in hex encoding, otherwise it could be screwed (but shouldn't)

  my $php_code = <<'END_CODE';

  function pbkdf2 ($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
  {
      $algorithm = strtolower ($algorithm);

      if (! in_array ($algorithm, hash_algos (), true))
      {
        trigger_error ("PBKDF2 ERROR: Invalid hash algorithm.", E_USER_ERROR);
      }

      if ($count <= 0 || $key_length <= 0)
      {
        trigger_error ("PBKDF2 ERROR: Invalid parameters.", E_USER_ERROR);
      }

      if (function_exists ("hash_pbkdf2"))
      {
        if (!$raw_output)
        {
            $key_length = $key_length * 2;
        }

        return hash_pbkdf2 ($algorithm, $password, $salt, $count, $key_length, $raw_output);
      }

      $hash_length = strlen (hash ($algorithm, "", true));
      $block_count = ceil ($key_length / $hash_length);

      $output = "";

      for ($i = 1; $i <= $block_count; $i++)
      {
        $last = $salt . pack ("N", $i);

        $last = $xorsum = hash_hmac ($algorithm, $last, $password, true);

        for ($j = 1; $j < $count; $j++)
        {
          $xorsum ^= ($last = hash_hmac ($algorithm, $last, $password, true));
        }

        $output .= $xorsum;
      }

      if ($raw_output)
      {
        return substr ($output, 0, $key_length);
      }
      else
      {
        return bin2hex (substr ($output, 0, $key_length));
      }
  }

  print pbkdf2 ("md5", base64_decode ("$word_buf_base64"), base64_decode ("$salt_buf_base64"), $iterations, $out_len, False);

END_CODE

  # replace with these command line arguments

  $php_code =~ s/\$word_buf_base64/$word_buf_base64/;
  $php_code =~ s/\$salt_buf_base64/$salt_buf_base64/;
  $php_code =~ s/\$iterations/$iterations/;
  $php_code =~ s/\$out_len/$out_len/;

  my $php_output = `php -r '$php_code'`;

  my $hash_buf = pack ("H*", $php_output);

  $hash_buf = encode_base64 ($hash_buf, "");

  my $base64_salt_buf = encode_base64 ($salt, "");

  my $hash = sprintf ("md5:%i:%s:%s", $iterations, $base64_salt_buf, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split (':', $digest);

  return unless scalar (@data) == 4;

  my $signature = shift @data;

  return unless ($signature eq 'md5');

  my $iterations = int (shift @data);

  my $salt = decode_base64 (shift @data);
  my $hash = decode_base64 (shift @data);

  my $out_len = length ($hash);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $out_len);

  return ($new_hash, $word);
}

1;

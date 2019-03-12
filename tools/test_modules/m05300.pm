#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5  qw (md5);
use Digest::HMAC qw (hmac hmac_hex);

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift || get_random_ike_salt ();

  my @salt_arr = split (":", $salt);

  my $msg = pack ("H*", $salt_arr[0] . $salt_arr[1] . $salt_arr[2] . $salt_arr[3] . $salt_arr[4] . $salt_arr[5]);
  my $nr  = pack ("H*", $salt_arr[6] . $salt_arr[7]);

  my $digest = hmac  ($nr , $word, \&md5, 64);
  $digest    = hmac_hex ($msg, $digest, \&md5, 64);

  my $hash = sprintf ("%s:%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my @data = split (':', $line);

  return unless scalar @data == 10;

  my $hash = $data[0];
  my $salt = join ('', @data[1 .. 8]);
  my $word = $data[9];

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

sub get_random_ike_salt
{
  my $nr_buf = "";

  for (my $i = 0; $i < 40; $i++)
  {
    $nr_buf .= get_random_chr (0, 0xff);
  }

  my $msg_buf = "";

  for (my $i = 0; $i < 440; $i++)
  {
    $msg_buf .= get_random_chr (0, 0xff);
  }

  my $nr_buf_hex  = unpack ("H*", $nr_buf);
  my $msg_buf_hex = unpack ("H*", $msg_buf);

  my $salt_buf = sprintf ("%s:%s:%s:%s:%s:%s:%s:%s", substr ($msg_buf_hex, 0, 256), substr ($msg_buf_hex, 256, 256), substr ($msg_buf_hex, 512, 16), substr ($msg_buf_hex, 528, 16), substr ($msg_buf_hex, 544, 320), substr ($msg_buf_hex, 864, 16), substr ($nr_buf_hex, 0, 40), substr ($nr_buf_hex, 40, 40));

  return $salt_buf;
}

sub get_random_chr
{
  return chr get_random_num (@_);
}

sub get_random_num
{
  my $min = shift;
  my $max = shift;

  return int ((rand ($max - $min)) + $min);
}

1;

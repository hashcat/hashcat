#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Encode;
use Crypt::RC4;
use Digest::HMAC_MD5 qw (hmac_md5);
use Digest::MD4      qw (md4);
use Digest::MD5      qw (md5_hex);
use POSIX            qw (strftime);

sub module_constraints { [[0, 256], [16, 16], [0, 27], [16, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word      = shift;
  my $salt      = shift;
  my $user      = shift // "user";
  my $realm     = shift // "realm";
  my $spn       = shift // "test/spn";
  my $checksum  = shift;
  my $edata2    = shift;

  my $k = md4 (encode ("UTF-16LE", $word));

  my $k1 = hmac_md5 ("\x02\x00\x00\x00", $k);

  my $cleartext_ticket = '6381b03081ada00703050050a00000a11b3019a003020117a1'.
    '12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5'.
    '44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201'.
    '01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353'.
    '134343735305aa711180f32303136303231363030343735305aa811180f32303136303232'.
    '323134343735305a';

  if (defined $checksum)
  {
    $checksum = pack ("H*", $checksum);
  }
  else
  {
    my $nonce = unpack ("H*", random_bytes (8));

    $cleartext_ticket = $nonce . $cleartext_ticket;

    $checksum = hmac_md5 (pack ("H*", $cleartext_ticket), $k1);
  }

  my $k3 = hmac_md5 ($checksum, $k1);

  if (defined $edata2)
  {
    my $cipher_decrypt = Crypt::RC4->new ($k3);

    my $ticket_decrypt = unpack ("H*", $cipher_decrypt->RC4 (pack ("H*", $edata2)));

    my $check_correct  = ((substr ($ticket_decrypt, 16, 4) eq "6381" && substr ($ticket_decrypt, 22, 2) eq "30") ||
                          (substr ($ticket_decrypt, 16, 4) eq "6382")) &&
                         ((substr ($ticket_decrypt, 32, 6) eq "030500") ||
                          (substr ($ticket_decrypt, 32, 8) eq "050307A0"));

    if ($check_correct == 1)
    {
      $cleartext_ticket = $ticket_decrypt;
    }
    else # validation failed
    {
      # fake/wrong ticket (otherwise if we just decrypt/encrypt we end up with false positives all the time)
      $cleartext_ticket = "0" x (length ($cleartext_ticket) + 16);
    }
  }

  my $cipher = Crypt::RC4->new ($k3);

  $edata2 = $cipher->RC4 (pack ("H*", $cleartext_ticket));

  my $tmp_hash = sprintf ('$krb5tgs$23$*%s$%s$%s*$%s$%s', $user, $realm, $spn, unpack ("H*", $checksum), unpack ("H*", $edata2));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 8;

  shift @data;

  my $signature = shift @data;
  my $algorithm = shift @data;
  my $user      = shift @data;
  $user         = substr ($user, 1);
  my $realm     = shift @data;
  my $spn       = shift @data;
  $spn          = substr ($spn, 0, length ($spn) - 1);
  my $checksum  = shift @data;
  my $edata2    = shift @data;

  return unless ($signature eq "krb5tgs");
  return unless (length ($checksum) == 32);
  return unless (length ($edata2) >= 64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $user, $realm, $spn, $checksum, $edata2);

  return ($new_hash, $word);
}

1;

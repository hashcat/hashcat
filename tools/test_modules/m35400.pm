#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::HMAC_MD5 qw(hmac_md5);

# pw: exactly 32 (NT hex), others follow 18200-style ranges
sub module_constraints { [[32, 32], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word                = shift;                              # NT in hex (32 chars)
  my $salt                = shift;
  my $user_principal_name = shift // "user\@domain.com";
  my $checksum            = shift;
  my $edata2              = shift;

  # NT key is supplied directly as hex32 (16 bytes), no MD4(UTF16LE) here
  my $k  = pack("H*", $word);

  my $k1 = hmac_md5("\x08\x00\x00\x00", $k);

  my $cleartext_ticket =
    '7981df3081dca01b3019a003020117a112041071e026814da2' .
    '3f129f0e67a01b73f79aa11c301a3018a003020100a111180f32303138313033303039353' .
    '831365aa206020460fdc6caa311180f32303337303931343032343830355aa40703050050' .
    'c10000a511180f32303138313033303039353831365aa611180f323031383130333030393' .
    '53831365aa711180f32303138313033303139353831365aa811180f323031383130333131' .
    '30303433385aa90d1b0b545952454c4c2e434f5250aa20301ea003020101a11730151b066' .
    'b72627467741b0b545952454c4c2e434f5250';

  if (defined $checksum)
  {
    $checksum = pack("H*", $checksum);
  }
  else
  {
    my $nonce_hex = unpack("H*", random_bytes(8));
    $cleartext_ticket = $nonce_hex . $cleartext_ticket;
    $checksum = hmac_md5(pack("H*", $cleartext_ticket), $k1);
  }

  my $k3 = hmac_md5($checksum, $k1);

  if (defined $edata2)
  {
    my $cipher_decrypt = Crypt::RC4->new ($k3);

    my $ticket_decrypt = unpack ("H*", $cipher_decrypt->RC4 (pack ("H*", $edata2)));

    my $check_correct  = ((substr ($ticket_decrypt, 16, 4) eq "7981" && substr ($ticket_decrypt, 22, 2) eq "30")) ||
                         ((substr ($ticket_decrypt, 16, 2) eq "79") && (substr ($ticket_decrypt, 20, 2) eq "30")) ||
                         ((substr ($ticket_decrypt, 16, 4) eq "7982")  && (substr ($ticket_decrypt, 24, 2) eq "30"));

    if ($check_correct == 1)
    {
      $cleartext_ticket = $ticket_decrypt;
    }
    else
    {
      # fake/wrong ticket (otherwise if we just decrypt/encrypt we end up with false positives all the time)
      $cleartext_ticket = "0" x (length ($cleartext_ticket) + 16);
    }
  }

  my $cipher = Crypt::RC4->new($k3);
  $edata2 = $cipher->RC4(pack("H*", $cleartext_ticket));

  return sprintf(
    '$krb5asrep$23$%s:%s$%s',
    $user_principal_name,
    unpack("H*", $checksum),
    unpack("H*", $edata2)
  );
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $hash2, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $hash2;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 4;

  shift @data;

  my $signature            = shift @data;
  my $algorithm            = shift @data;
  my $user_principal_name  = shift @data;

  return unless ($signature eq "krb5asrep" && $algorithm eq "23");

  my @data2 = split ('\$', $hash2);

  my $checksum             = shift @data2;
  my $edata2               = shift @data2;

  return unless (length ($checksum) == 32);
  return unless (length ($edata2) >= 64);

  # $word is already hex32 NT; do NOT pack_if_HEX_notation here
  my $new_hash = module_generate_hash($word, undef, $user_principal_name, $checksum, $edata2);

  return ($new_hash, $word);
}

1;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (hmac_sha1);
use Crypt::Mode::CBC;
use Crypt::PBKDF2;
use Encode;
use POSIX            qw (strftime);

sub byte2hex
{
  my $input = shift;
  return unpack ("H*", $input);
}

sub hex2byte
{
  my $input = shift;
  return pack ("H*", $input);
}

sub pad
{
  my $n = shift;
  my $size = shift;

  return (~$n + 1) & ($size - 1);
}

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word      = shift;
  my $salt      = shift;
  my $user      = shift // "user";
  my $realm     = shift // "realm";
  my $checksum  = shift;
  my $edata2    = shift;

  my $mysalt = uc $realm;
  $mysalt = $mysalt . $user;

  # first we generate the 'seed'
  my $iter = 4096;
  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 16
  );

  my $b_seed = $pbkdf2->PBKDF2 ($mysalt, $word);

  # we can precompute this
  my $b_kerberos_nfolded = hex2byte('6b65726265726f737b9b5b2b93132b93');

  my $b_iv = hex2byte('0' x 32);

  # 'key_bytes' will be the AES key used to generate 'ki' (for final hmac-sha1)
  # and 'ke' (AES key to decrypt/encrypt the ticket)
  my $cbc       = Crypt::Mode::CBC->new ('AES', 0);
  my $b_key_bytes = $cbc->encrypt ($b_kerberos_nfolded, $b_seed, $b_iv);

  # precomputed stuff
  my $b_nfolded1 = hex2byte('62dc6e371a63a80958ac562b15404ac5');
  my $b_nfolded2 = hex2byte('b5b0582c14b6500aad56ab55aa80556a');

  my $b_ki = $cbc->encrypt ($b_nfolded1, $b_key_bytes, $b_iv);
  my $b_ke = $cbc->encrypt ($b_nfolded2, $b_key_bytes, $b_iv);

  my $cleartext_ticket = '6381b03081ada00703050050a00000a11b3019a003020117a1'.
    '12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5'.
    '44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201'.
    '01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353'.
    '134343735305aa711180f32303136303231363030343735305aa811180f32303136303232'.
    '323134343735305a';

  if (defined $edata2)
  {
    my $len_last_block  = length($edata2) % 32;

    my $tmp = $len_last_block + 32;

    my $b_truncated_enc_ticket = hex2byte (substr $edata2, 0, -$tmp);

    my $b_last_block = hex2byte (substr $edata2, -$len_last_block);

    my $b_n_1_block = hex2byte (substr(substr($edata2, -$tmp), 0, 32));

    my $b_truncated_ticket_decrypted = $cbc->decrypt ($b_truncated_enc_ticket, $b_ke, $b_iv);

    my $truncated_ticket_decrypted = byte2hex($b_truncated_ticket_decrypted);

    my $check_correct  = ((substr ($truncated_ticket_decrypted, 32, 4) eq "6381" && substr ($truncated_ticket_decrypted, 38, 2) eq "30") ||
                          (substr ($truncated_ticket_decrypted, 32, 4) eq "6382")) &&
                         ((substr ($truncated_ticket_decrypted, 48, 6) eq "030500") ||
                          (substr ($truncated_ticket_decrypted, 48, 8) eq "050307A0"));

    if ($check_correct == 1)
    {
      my $b_n_2 = substr $b_truncated_enc_ticket, -16;

      my $b_n_1_decrypted = $cbc->decrypt ($b_n_1_block, $b_ke, $b_iv);

      my $b_last_plain = substr $b_n_1_decrypted, 0, $len_last_block/2;

      $b_last_plain =  $b_last_plain ^ $b_last_block;

      my $omitted = substr $b_n_1_decrypted,  -(16 - $len_last_block/2);

      my $b_n_1 = $b_last_block . $omitted;

      $b_n_1 = $cbc->decrypt ($b_n_1, $b_ke, $b_iv);

      $b_n_1 = $b_n_1 ^ $b_n_2;

      my $b_cleartext_ticket = $b_truncated_ticket_decrypted . $b_n_1 . $b_last_plain;

      $cleartext_ticket = byte2hex($b_cleartext_ticket);
    }
    else # validation failed
    {
      # fake/wrong ticket (otherwise if we just decrypt/encrypt we end
      #up with false positives all the time)
      $cleartext_ticket = "0" x (length ($cleartext_ticket) + 32);
    }
  }

  if (defined $checksum)
  {
    $checksum = pack ("H*", $checksum);
  }
  else
  {
    if (!defined $edata2)
    {
      my $nonce = unpack ("H*", random_bytes (16));

      $cleartext_ticket = $nonce . $cleartext_ticket;
    }
      # we have what is required to compute checksum
    $checksum = hmac_sha1 (hex2byte($cleartext_ticket), $b_ki);

    $checksum = substr $checksum, 0, 12;
  }

  my $len_cleartext_last_block = length($cleartext_ticket) % 32;
  my $cleartext_last_block = substr $cleartext_ticket, -$len_cleartext_last_block;

  my $padding = pad(length($cleartext_ticket), 32);

  my $b_cleartext_last_block_padded = hex2byte($cleartext_last_block . '0' x $padding);

  # we will encrypt until n-1 block (included)
  my $truncated_cleartext_ticket = substr $cleartext_ticket, 0, -$len_cleartext_last_block;

  my $b_truncated_enc_ticket = $cbc->encrypt (hex2byte($truncated_cleartext_ticket), $b_ke, $b_iv);

  my $b_enc_ticket_n_1_block= substr $b_truncated_enc_ticket, -16;

  my $b_enc_last_block = substr $b_enc_ticket_n_1_block, 0, $len_cleartext_last_block/2;

  # we now craft the new n-1 block
  my $tmp = $b_enc_ticket_n_1_block ^ $b_cleartext_last_block_padded;

  $b_enc_ticket_n_1_block = $cbc->encrypt ($tmp, $b_ke, $b_iv);

  $tmp = substr $b_truncated_enc_ticket, 0, -16;

  $edata2 = $tmp . $b_enc_ticket_n_1_block . $b_enc_last_block;

  my $tmp_hash = sprintf ('$krb5tgs$17$%s$%s$%s$%s', $user, $realm, unpack ("H*", $checksum), unpack ("H*", $edata2));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 7;

  shift @data;

  my $signature = shift @data;
  my $algorithm = shift @data;
  my $user      = shift @data;
  my $realm     = shift @data;
  my $checksum  = shift @data;
  my $edata2    = shift @data;

  return unless ($signature eq "krb5tgs");
  return unless ($algorithm eq "17");
  return unless (length ($checksum) == 24);
  return unless (length ($edata2) >= 64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $user, $realm, $checksum, $edata2);

  return ($new_hash, $word);
}

1;
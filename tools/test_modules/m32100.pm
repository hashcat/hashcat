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
  my $realm     = shift // "example.com";
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
  my $b_kerberos_nfolded = hex2byte ('6b65726265726f737b9b5b2b93132b93');

  my $b_iv = hex2byte ('0' x 32);

  # 'key_bytes' will be the AES key used to generate 'ki' (for final hmac-sha1)
  # and 'ke' (AES key to decrypt/encrypt the ticket)
  my $cbc       = Crypt::Mode::CBC->new ('AES', 0);
  my $b_key_bytes = $cbc->encrypt ($b_kerberos_nfolded, $b_seed, $b_iv);

  # precomputed stuff
  my $b_nfolded1 = hex2byte ('6b60b0582a6ba80d5aad56ab55406ad5');
  my $b_nfolded2 = hex2byte ('be349a4d24be500eaf57abd5ea80757a');

  my $b_ki = $cbc->encrypt ($b_nfolded1, $b_key_bytes, $b_iv);
  my $b_ke = $cbc->encrypt ($b_nfolded2, $b_key_bytes, $b_iv);

  my $cleartext_ticket = '7981df3081dca01b3019a003020111a1120410e2aa1c894df7'.
    '23b7277eef29700bf760a11c301a3018a003020100a111180f32303233303333313132303'.
    '434355aa20602041d9d970ba311180f32303337303931343032343830355aa40703050040'.
    'c10000a511180f32303233303333313132303434355aa611180f323032333033333131323'.
    '03434355aa711180f32303233303333313232303434355aa811180f323032333034303731'.
    '32303434355aa90d1b0b4558414d504c452e434f4daa20301ea003020102a11730151b066'.
    'b72627467741b0b6578616d706c652e636f6d';

  if (defined $edata2)
  {
    my $len_last_block  = length ($edata2) % 32;

    my $tmp = $len_last_block + 32;

    my $b_truncated_enc_ticket = hex2byte (substr $edata2, 0, -$tmp);

    my $b_last_block = hex2byte (substr $edata2, -$len_last_block);

    my $b_n_1_block = hex2byte (substr (substr ($edata2, -$tmp), 0, 32));

    my $b_truncated_ticket_decrypted = $cbc->decrypt ($b_truncated_enc_ticket, $b_ke, $b_iv);

    my $truncated_ticket_decrypted = byte2hex ($b_truncated_ticket_decrypted);

    my $check_correct  = ((substr ($truncated_ticket_decrypted, 32, 4) eq "7981" || substr ($truncated_ticket_decrypted, 32, 4) eq "7a81") && (substr ($truncated_ticket_decrypted, 38, 2) eq "30")) ||
 -                       ((substr ($truncated_ticket_decrypted, 32, 2) eq "79" || substr ($truncated_ticket_decrypted, 32, 2) eq "7a") && (substr ($truncated_ticket_decrypted, 36, 2) eq "30")) ||
 -                       ((substr ($truncated_ticket_decrypted, 32, 4) eq "7982" || substr ($truncated_ticket_decrypted, 32, 4) eq "7a82")  && (substr ($truncated_ticket_decrypted, 40, 2) eq "30"));

    if ($check_correct == 1)
    {
      my $b_n_2 = substr $b_truncated_enc_ticket, -16;

      my $b_n_1_decrypted = $cbc->decrypt ($b_n_1_block, $b_ke, $b_iv);

      my $b_last_plain = substr $b_n_1_decrypted, 0, $len_last_block / 2;

      $b_last_plain =  $b_last_plain ^ $b_last_block;

      my $omitted = substr $b_n_1_decrypted, -(16 - $len_last_block / 2);

      my $b_n_1 = $b_last_block . $omitted;

      $b_n_1 = $cbc->decrypt ($b_n_1, $b_ke, $b_iv);

      $b_n_1 = $b_n_1 ^ $b_n_2;

      my $b_cleartext_ticket = $b_truncated_ticket_decrypted . $b_n_1 . $b_last_plain;

      $cleartext_ticket = byte2hex ($b_cleartext_ticket);
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
    if (! defined $edata2)
    {
      my $nonce = unpack ("H*", random_bytes (16));

      $cleartext_ticket = $nonce . $cleartext_ticket;
    }
      # we have what is required to compute checksum
    $checksum = hmac_sha1 (hex2byte ($cleartext_ticket), $b_ki);

    $checksum = substr $checksum, 0, 12;
  }

  my $len_cleartext_last_block = length ($cleartext_ticket) % 32;
  my $cleartext_last_block = substr $cleartext_ticket, -$len_cleartext_last_block;

  my $padding = pad (length ($cleartext_ticket), 32);

  my $b_cleartext_last_block_padded = hex2byte ($cleartext_last_block . '0' x $padding);

  # we will encrypt until n-1 block (included)
  my $truncated_cleartext_ticket = substr $cleartext_ticket, 0, -$len_cleartext_last_block;

  my $b_truncated_enc_ticket = $cbc->encrypt (hex2byte ($truncated_cleartext_ticket), $b_ke, $b_iv);

  my $b_enc_ticket_n_1_block= substr $b_truncated_enc_ticket, -16;

  my $b_enc_last_block = substr $b_enc_ticket_n_1_block, 0, $len_cleartext_last_block / 2;

  # we now craft the new n-1 block
  my $tmp = $b_enc_ticket_n_1_block ^ $b_cleartext_last_block_padded;

  $b_enc_ticket_n_1_block = $cbc->encrypt ($tmp, $b_ke, $b_iv);

  $tmp = substr $b_truncated_enc_ticket, 0, -16;

  $edata2 = $tmp . $b_enc_ticket_n_1_block . $b_enc_last_block;

  my $tmp_hash = sprintf ('$krb5asrep$17$%s$%s$%s$%s', $user, $realm, unpack ("H*", $checksum), unpack ("H*", $edata2));

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

  return unless ($signature eq "krb5asrep");
  return unless ($algorithm eq "17");
  return unless (length ($checksum) == 24);
  return unless (length ($edata2) >= 64);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $user, $realm, $checksum, $edata2);

  return ($new_hash, $word);
}

1;

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
  my $realm     = shift // "realm";
  my $checksum  = shift;
  my $enc_timestamp    = shift;

  my $mysalt = uc $realm;
  $mysalt = $mysalt . $user;

  # first we generate the 'seed'
  my $iter = 4096;
  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 32
  );

  my $b_seed = $pbkdf2->PBKDF2 ($mysalt, $word);

  # we can precompute this
  my $b_kerberos_nfolded = hex2byte ('6b65726265726f737b9b5b2b93132b93');

  my $b_iv = hex2byte ('0' x 32);

  # 'key_bytes' will be the AES key used to generate 'ki' (for final hmac-sha1)
  # and 'ke' (AES key to decrypt/encrypt the ticket)
  my $cbc         = Crypt::Mode::CBC->new ('AES', 0);
  my $b_key_bytes = $cbc->encrypt ($b_kerberos_nfolded, $b_seed, $b_iv);

  $b_key_bytes = $b_key_bytes . $cbc->encrypt ($b_key_bytes, $b_seed, $b_iv);

  # precomputed stuff
  # nfold 0x0000000155 to 16 bytes
  my $b_nfolded1 = hex2byte ('5b582c160a5aa80556ab55aad5402ab5');

  # nfold 0x00000001aa to 16 bytes
  my $b_nfolded2 = hex2byte ('ae2c160b04ad5006ab55aad56a80355a');

  my $b_ki = $cbc->encrypt ($b_nfolded1, $b_key_bytes, $b_iv);

  $b_ki = $b_ki . $cbc->encrypt ($b_ki, $b_key_bytes, $b_iv);

  my $b_ke = $cbc->encrypt ($b_nfolded2, $b_key_bytes, $b_iv);

  $b_ke = $b_ke . $cbc->encrypt ($b_ke, $b_key_bytes, $b_iv);

  my $cleartext_ticket = '';
  my $check_correct  = 0;

  if (defined $enc_timestamp)
  {
    # Do CTS Decryption https://en.wikipedia.org/wiki/Ciphertext_stealing
    # Decrypt n-1 block
    my $len_last_block  = length ($enc_timestamp) % 32;

    my $len_last_2_blocks = $len_last_block + 32;

    my $b_n_1_block = hex2byte (substr ($enc_timestamp, -$len_last_2_blocks, 32));

    my $b_n_1_decrypted = $cbc->decrypt ($b_n_1_block, $b_ke, $b_iv);

    # Pad the last block with last bytes from the decrypted n-1
    my $b_padded_enc_ticket = hex2byte ($enc_timestamp) . (substr $b_n_1_decrypted, -(16 - $len_last_block / 2));

    # Swap the last two blocks
    my $b_cbc_enc_ticket = (substr $b_padded_enc_ticket, 0, -32) . (substr $b_padded_enc_ticket, -16, 16).
    (substr $b_padded_enc_ticket, -32, 16);

    # Decrypt and truncate
    my $b_dec_ticket_padded = $cbc->decrypt ($b_cbc_enc_ticket, $b_ke, $b_iv);

    my $b_cleartext_ticket = substr $b_dec_ticket_padded, 0, length ($enc_timestamp) / 2;

    $cleartext_ticket = byte2hex ($b_cleartext_ticket);

    my $check_correct  = ((substr ($b_cleartext_ticket, 22, 2) eq "20") &&
                          (substr ($b_cleartext_ticket, 36, 1) eq "Z"));

    if ($check_correct == 1 && defined $checksum)
    {
      my $b_checksum = hmac_sha1 (hex2byte ($cleartext_ticket), $b_ki);

      $check_correct = ($checksum eq byte2hex (substr $b_checksum, 0, 12));
    }
  }

  if ($check_correct != 1)
  {
    # fake/wrong ticket (otherwise if we just decrypt/encrypt we end
    #up with false positives all the time)
    $cleartext_ticket = '68c8459f3f10c851b8827118bb459c6e301aa011180f323031'.
'32313131363134323835355aa10502030c28a2';

    # we have what is required to compute checksum
    $checksum = hmac_sha1 (hex2byte ($cleartext_ticket), $b_ki);

    $checksum = byte2hex (substr $checksum, 0, 12);
  }

  # CTS Encrypt our new block
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

  $enc_timestamp = $tmp . $b_enc_ticket_n_1_block . $b_enc_last_block;

  my $tmp_hash = sprintf ('$krb5pa$18$%s$%s$%s%s', $user, $realm, unpack ("H*", $enc_timestamp), $checksum);

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless scalar @data == 6;

  shift @data;

  my $signature = shift @data;
  my $algorithm = shift @data;
  my $user      = shift @data;
  my $realm     = shift @data;
  my $edata     = shift @data;

  return unless ($signature eq "krb5pa");
  return unless ($algorithm eq "18");
  return unless (length ($edata) >= 88);
  return unless (length ($edata) <= 112);

  my $checksum  = substr $edata, -24;
  my $enc_timestamp    = substr $edata, 0, -24;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $user, $realm, $checksum, $enc_timestamp);

  return ($new_hash, $word);
}

1;

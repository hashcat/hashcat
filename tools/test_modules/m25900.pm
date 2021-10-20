#!/usr/bin/env perl

##
## Author......: Robert Guetzkow
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::Mode::CBC;
use Crypt::Mode::ECB;

# Details of the protocol design can be found in ISO 22510:2019 and
# application notes published by the KNX Association.

# ETS 5 allows a maximum of 20 characters in a password.
# The salt is used as Secure Session Identifier, which is 2 Bytes long.
sub module_constraints { [[0, 20], [2, 2], [-1, -1], [-1, -1], [-1, -1]] }

sub device_authentication_code
{
  my $password = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ("HMACSHA2", 256),
    iterations => 65536,
    output_len => 16
  );

  my $device_authentication_code = $pbkdf2->PBKDF2 ("device-authentication-code.1.secure.ip.knx.org",
                                                    $password);

  return $device_authentication_code;
}

sub block_formatting
{
  # Simplified block formatting function, where payload is always empty
  my $b0 = shift;
  my $associated_data = shift;
  my $associated_data_length = pack ("s>", length ($associated_data));
  my $blocks_unpadded = $associated_data_length . $associated_data;
  my $pad_len = int ((length ($blocks_unpadded) + 16 - 1) / 16) * 16;
  my $blocks_padded = $blocks_unpadded . "\0" x ($pad_len - length ($blocks_unpadded));

  return $b0 . $blocks_padded;
}

sub encrypt
{
  # Simplified encryption that only performs steps required for the MAC, not full CCM
  my $blocks = shift;
  my $nonce = shift;
  my $key = shift;
  my $iv = "\0" x 16;

  my $aes_cbc = Crypt::Mode::CBC->new ("AES", 0);
  my $ciphertext = $aes_cbc->encrypt ($blocks, $key, $iv);
  my $y_n = substr ($ciphertext, length ($ciphertext) - 16, 16);

  my $aes_ecb = Crypt::Mode::ECB->new ("AES", 0);
  my $s_0 = $aes_ecb->encrypt ($nonce, $key);

  return $y_n ^ $s_0;
}

sub generate_session_response_mac
{
  my $secure_session_identifier = shift;
  my $public_value_xor          = shift;
  my $key                       = shift;

  # Constants used for the cryptography in Session_Response frames
  my $knx_ip_header = pack ("H*", "061009520038");
  my $b0            = pack ("H*", "00000000000000000000000000000000");
  my $nonce         = pack ("H*", "0000000000000000000000000000ff00");

  my $associated_data = $knx_ip_header . $secure_session_identifier . $public_value_xor;

  my $blocks = block_formatting ($b0, $associated_data);

  return encrypt ($blocks, $nonce, $key);
}

sub module_generate_hash
{
  my $word = shift;

  # Parameters that would be found in the Session_Request and Session_Response frames
  my $secure_session_identifier = shift;
  my $public_value_xor          = shift // random_bytes (32);

  my $device_authentication_code = device_authentication_code ($word);

  my $mac = generate_session_response_mac ($secure_session_identifier,
                                           $public_value_xor,
                                           $device_authentication_code);

  my $hash = sprintf ("\$knx-ip-secure-device-authentication-code\$*%s*%s*%s",
                      unpack ("H*", $secure_session_identifier),
                      unpack ("H*", $public_value_xor),
                      unpack ("H*", $mac));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\*', $hash);

  return unless scalar (@data) == 4;

  my $signature = shift @data;

  return unless ($signature eq "\$knx-ip-secure-device-authentication-code\$");

  my $secure_session_identifier = pack ("H*", shift @data); #  2 Bytes expected (using the "salt" for this purpose)
  my $public_value_xor          = pack ("H*", shift @data); # 32 Bytes expected (xor of client's and server's public value)
  my $mac                       = pack ("H*", shift @data); # 16 Bytes expected

  return unless (length ($secure_session_identifier) == 2);
  return unless (length ($public_value_xor) == 32);
  return unless (length ($mac) == 16);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed,
                                       $secure_session_identifier,
                                       $public_value_xor);

  return ($new_hash, $word);
}

1;

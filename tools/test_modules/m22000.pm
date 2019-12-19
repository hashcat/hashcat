#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::MD5  qw (md5);
use Digest::SHA  qw (sha1 sha256);
use Digest::HMAC qw (hmac hmac_hex);
use Digest::CMAC;

sub module_constraints { [[8, 63], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $type   = shift // random_number (1, 2);
  my $macap  = shift;
  my $macsta = shift;
  my $essid  = shift;
  my $anonce = shift;
  my $eapol  = shift;
  my $mp     = shift;

  my $hash;

  if ($type == 1)
  {
    if (!defined ($macap))
    {
      $macap = unpack ("H*", random_bytes (6));
    }

    if (!defined ($macsta))
    {
      $macsta = unpack ("H*", random_bytes (6));
    }

    if (!defined ($essid))
    {
      $essid = unpack ("H*", random_bytes (random_number (0, 32) & 0x1e));
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => 4096,
      output_len => 32,
    );

    my $essid_bin = pack ("H*", $essid);

    my $pmk = $pbkdf2->PBKDF2 ($essid_bin, $word);

    my $macap_bin  = pack ("H*", $macap);
    my $macsta_bin = pack ("H*", $macsta);

    my $data = "PMK Name" . $macap_bin . $macsta_bin;

    my $pmkid = hmac_hex ($data, $pmk, \&sha1);

    $hash = sprintf ("WPA*%02x*%s*%s*%s*%s***", $type, substr ($pmkid, 0, 32), $macap, $macsta, $essid);
  }
  elsif ($type == 2)
  {
    if (!defined ($macap))
    {
      $macap = random_bytes (6);
    }
    else
    {
      $macap = pack ("H*", $macap);
    }

    if (!defined ($macsta))
    {
      $macsta = random_bytes (6);
    }
    else
    {
      $macsta = pack ("H*", $macsta);
    }

    if (!defined ($mp))
    {
      $mp = "\x00";
    }
    else
    {
      $mp = pack ("H*", $mp);
    }

    my $keyver;

    my $snonce;

    if (!defined ($eapol))
    {
      $keyver = random_number (1, 3); # 1, 2 or 3

      $snonce = random_bytes (32);

      $eapol = gen_random_wpa_eapol ($keyver, $snonce);
    }
    else
    {
      $eapol = pack ("H*", $eapol);

      my $key_info = unpack ("n*", substr ($eapol, 5, 2));

      $keyver = $key_info & 3;

      $snonce = substr ($eapol, 17, 32);
    }

    if (!defined ($anonce))
    {
      $anonce = random_bytes (32);
    }
    else
    {
      $anonce = pack ("H*", $anonce);
    }

    if (!defined ($essid))
    {
      $essid = unpack ("H*", random_bytes (random_number (0, 32) & 0x1e));
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => 4096,
      output_len => 32,
    );

    my $essid_bin = pack ("H*", $essid);

    my $pmk = $pbkdf2->PBKDF2 ($essid_bin, $word);

    # Pairwise Transient Key (PTK) transformation

    my $ptk = wpa_prf_512 ($keyver, $pmk, $macsta, $macap, $snonce, $anonce);

    # generate the Message Integrity Code (MIC)

    my $mic = "";

    if ($keyver == 1) # WPA1 => MD5
    {
      $mic = hmac ($eapol, $ptk, \&md5);
    }
    elsif ($keyver == 2) # WPA2 => SHA1
    {
      $mic = hmac ($eapol, $ptk, \&sha1);
    }
    elsif ($keyver == 3) # WPA2 => SHA256 + AES-CMAC
    {
      my $omac1 = Digest::CMAC->new ($ptk, 'Crypt::Rijndael');

      $omac1->add ($eapol);

      $mic = $omac1->digest;
    }

    $mic = substr ($mic, 0, 16);

    $hash = sprintf ("WPA*%02x*%s*%s*%s*%s*%s*%s*%s", $type, unpack ("H*", $mic), unpack ("H*", $macap), unpack ("H*", $macsta), $essid, unpack ("H*", $anonce), unpack ("H*", $eapol), unpack ("H*", $mp));
  }

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $word = substr ($line, $index1 + 1);

  my $hash_in = substr ($line, 0, $index1);

  my @data = split ('\*', $hash_in);

  my ($signature, $type, $pmkidmic, $macap, $macsta, $essid, $anonce, $eapol, $mp) = @data;

  return unless defined $signature;
  return unless defined $type;
  return unless defined $pmkidmic;
  return unless defined $macap;
  return unless defined $macsta;
  return unless defined $essid;

  return unless ($signature eq "WPA");

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $type, $macap, $macsta, $essid, $anonce, $eapol, $mp);

  return ($new_hash, $word);
}

sub gen_random_wpa_eapol
{
  my $keyver = shift;
  my $snonce = shift;

  my $ret = "";

  # version

  my $version = 1; # 802.1X-2001

  $ret .= pack ("C*", $version);

  my $type = 3;    # means that this EAPOL frame is used to transfer key information

  $ret .= pack ("C*", $type);

  my $length; # length of remaining data

  if ($keyver == 1)
  {
    $length = 119;
  }
  else
  {
    $length = 117;
  }

  $ret .= pack ("n*", $length);

  my $descriptor_type;

  if ($keyver == 1)
  {
    $descriptor_type = 254; # EAPOL WPA key
  }
  else
  {
    $descriptor_type = 1; # EAPOL RSN key
  }

  $ret .= pack ("C*", $descriptor_type);

  # key_info is a bit vector:
  # generated from these 13 bits: encrypted key data, request, error, secure, key mic, key ack, install, key index (2), key type, key descriptor (3)

  my $key_info = 0;

  $key_info |= 1 << 8; # set key MIC
  $key_info |= 1 << 3; # set if it is a pairwise key

  if ($keyver == 1)
  {
    $key_info |= 1; # RC4 Cipher, HMAC-MD5 MIC
  }
  elsif ($keyver == 2)
  {
    $key_info |= 2; # AES Cipher, HMAC-SHA1 MIC
  }
  elsif ($keyver == 3)
  {
    $key_info |= 3; # AES-CMAC
  }

  $ret .= pack ("n*", $key_info);

  my $key_length;

  if ($keyver == 1)
  {
    $key_length = 32;
  }
  else
  {
    $key_length = 0;
  }

  $ret .= pack ("n*", $key_length);

  my $replay_counter = 1;

  $ret .= pack ("Q>*", $replay_counter);

  $ret .= $snonce;

  my $key_iv = "\x00" x 16;

  $ret .= $key_iv;

  my $key_rsc = "\x00" x 8;

  $ret .= $key_rsc;

  my $key_id = "\x00" x 8;

  $ret .= $key_id;

  my $key_mic = "\x00" x 16;

  $ret .= $key_mic;

  my $key_data_len;

  if ($keyver == 1)
  {
    $key_data_len = 24; # length of the key_data (== WPA info)
  }
  else
  {
    $key_data_len = 22; # length of the key_data (== RSN info)
  }

  $ret .= pack ("n*", $key_data_len);

  my $key_data = "";

  if ($keyver == 1)
  {
    # wpa info

    my $wpa_info = "";

    my $vendor_specific_data = "";

    my $tag_number = 221; # means it is a vendor specific tag

    $vendor_specific_data .= pack ("C*", $tag_number);

    my $tag_len = 22;     # length of the remaining "tag data"

    $vendor_specific_data .= pack ("C*", $tag_len);

    my $vendor_specific_oui = pack ("H*", "0050f2"); # microsoft

    $vendor_specific_data .= $vendor_specific_oui;

    my $vendor_specific_oui_type = 1; # WPA Information Element

    $vendor_specific_data .= pack ("C*", $vendor_specific_oui_type);

    my $vendor_specific_wpa_version = 1;

    $vendor_specific_data .= pack ("v*", $vendor_specific_wpa_version);

    # multicast

    my $vendor_specific_multicast_oui = pack ("H*", "0050f2");

    $vendor_specific_data .= $vendor_specific_multicast_oui;

    my $vendor_specific_multicast_type = 2; # TKIP

    $vendor_specific_data .= pack ("C*", $vendor_specific_multicast_type);

    # unicast

    my $vendor_specific_unicast_count = 1;

    $vendor_specific_data .= pack ("v*", $vendor_specific_unicast_count);

    my $vendor_specific_unicast_oui = pack ("H*", "0050f2");

    $vendor_specific_data .= $vendor_specific_unicast_oui;

    my $vendor_specific_unicast_type = 2; # TKIP

    $vendor_specific_data .= pack ("C*", $vendor_specific_unicast_type);

    # Auth Key Management (AKM)

    my $auth_key_management_count = 1;

    $vendor_specific_data .= pack ("v*", $auth_key_management_count);

    my $auth_key_management_oui = pack ("H*", "0050f2");

    $vendor_specific_data .= $auth_key_management_oui;

    my $auth_key_management_type = 2; # Pre-Shared Key (PSK)

    $vendor_specific_data .= pack ("C*", $auth_key_management_type);

    $wpa_info = $vendor_specific_data;

    $key_data = $wpa_info;
  }
  else
  {
    # rsn info

    my $rsn_info = "";

    my $tag_number = 48; # RSN info

    $rsn_info .= pack ("C*", $tag_number);

    my $tag_len = 20;    # length of the remaining "tag_data"

    $rsn_info .= pack ("C*", $tag_len);

    my $rsn_version = 1;

    $rsn_info .= pack ("v*", $rsn_version);

    # group cipher suite

    my $group_cipher_suite_oui = pack ("H*", "000fac"); # Ieee8021

    $rsn_info .= $group_cipher_suite_oui;

    my $group_cipher_suite_type = 4; # AES (CCM)

    $rsn_info .= pack ("C*", $group_cipher_suite_type);

    # pairwise cipher suite

    my $pairwise_cipher_suite_count = 1;

    $rsn_info .= pack ("v*", $pairwise_cipher_suite_count);

    my $pairwise_cipher_suite_oui = pack ("H*", "000fac"); # Ieee8021

    $rsn_info .= $pairwise_cipher_suite_oui;

    my $pairwise_cipher_suite_type = 4; # AES (CCM)

    $rsn_info .= pack ("C*", $pairwise_cipher_suite_type);

    # Auth Key Management (AKM)

    my $auth_key_management_count = 1;

    $rsn_info .= pack ("v*", $auth_key_management_count);

    my $auth_key_management_oui = pack ("H*", "000fac"); # Ieee8021

    $rsn_info .= $auth_key_management_oui;

    my $auth_key_management_type = 2; # Pre-Shared Key (PSK)

    $rsn_info .= pack ("C*", $auth_key_management_type);

    # RSN Capabilities

    # bit vector of these 9 bits: peerkey enabled, management frame protection (MFP) capable, MFP required,
    # RSN GTKSA Capabilities (2), RSN PTKSA Capabilities (2), no pairwise Capabilities, Pre-Auth Capabilities

    my $rsn_capabilities = pack ("H*", "0000");

    $rsn_info .= $rsn_capabilities;

    $key_data = $rsn_info;
  }

  $ret .= $key_data;

  return $ret;
}

sub wpa_prf_512
{
  my $keyver = shift;
  my $pmk    = shift;
  my $macsta = shift;
  my $macap  = shift;
  my $snonce = shift;
  my $anonce = shift;

  my $data = "Pairwise key expansion";

  if (($keyver == 1) || ($keyver == 2))
  {
    $data .= "\x00";
  }

  #
  # Min(AA, SPA) || Max(AA, SPA)
  #

  # compare if greater: Min()/Max() on the MACs (6 bytes)

  if (memcmp ($macsta, $macap, 6) < 0)
  {
    $data .= $macsta;
    $data .= $macap;
  }
  else
  {
    $data .= $macap;
    $data .= $macsta;
  }

  #
  # Min(ANonce,SNonce) || Max(ANonce,SNonce)
  #

  # compare if greater: Min()/Max() on the nonces (32 bytes)

  if (memcmp ($snonce, $anonce, 32) < 0)
  {
    $data .= $snonce;
    $data .= $anonce;
  }
  else
  {
    $data .= $anonce;
    $data .= $snonce;
  }

  my $prf_buf;

  if (($keyver == 1) || ($keyver == 2))
  {
    $data .= "\x00";

    $prf_buf = hmac ($data, $pmk, \&sha1);
  }
  else
  {
    my $data3 = "\x01\x00" . $data . "\x80\x01";

    $prf_buf = hmac ($data3, $pmk, \&sha256);
  }

  $prf_buf = substr ($prf_buf, 0, 16);

  return $prf_buf;
}

sub memcmp
{
  my $str1 = shift;
  my $str2 = shift;
  my $len  = shift;

  my $len_str1 = length ($str1);
  my $len_str2 = length ($str2);

  if (($len > $len_str1) || ($len > $len_str2))
  {
    print "ERROR: memcmp () lengths wrong";

    exit (1);
  }

  for (my $i = 0; $i < $len; $i++)
  {
    my $c_1 = ord (substr ($str1, $i, 1));
    my $c_2 = ord (substr ($str2, $i, 1));

    return -1 if ($c_1 < $c_2);
    return  1 if ($c_1 > $c_2);
  }

  return 0;
}

1;

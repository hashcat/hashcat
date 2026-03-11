#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::SHA  qw (sha256);
use Digest::HMAC qw (hmac);
use Digest::CMAC;

sub module_constraints { [[8, 63], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

##
## Compute one round of the 802.11r SHA256-based KDF:
##   HMAC-SHA256 (key, counter_LE16 || label || context || size_LE16)
## Returns 32 raw bytes.
##

sub ft_kdf_block
{
  my $key     = shift;
  my $counter = shift;  # 1 or 2
  my $label   = shift;  # e.g. "FT-R0"
  my $context = shift;  # raw bytes
  my $size    = shift;  # KDF output size in bits (e.g. 384 or 256)

  my $data = pack ("v", $counter) . $label . $context . pack ("v", $size);

  return hmac ($data, $key, \&sha256);
}

##
## Build a minimal 802.11r EAPOL-Key frame (keyver = 3, AES-CMAC) with
## the MIC field zeroed, ready for CMAC computation.
##

sub gen_ft_eapol
{
  my $snonce = shift;

  # Auth-packet body (everything after the 4-byte EAPOL header)
  my $body = "";

  $body .= pack ("C", 2);           # key_descriptor = RSN (2)

  my $key_info = 0;
  $key_info |= 3;         # keyver = 3 (AES-CMAC)
  $key_info |= (1 << 3);  # pairwise key
  $key_info |= (1 << 8);  # key MIC present

  $body .= pack ("n",  $key_info);
  $body .= pack ("n",  0);            # key_length = 0
  $body .= pack ("Q>", 1);            # replay_counter = 1
  $body .= $snonce;                   # wpa_key_nonce (32 bytes)
  $body .= "\x00" x 16;              # key_iv
  $body .= "\x00" x 8;               # key_rsc
  $body .= "\x00" x 8;               # key_id
  $body .= "\x00" x 16;              # key_mic  (zeroed)

  # RSN IE as key_data (22 bytes, enough to push total above 99-byte minimum)
  my $key_data = "";
  $key_data .= pack ("C",  48);         # IE tag = RSN
  $key_data .= pack ("C",  20);         # tag length
  $key_data .= pack ("v",  1);          # RSN version
  $key_data .= pack ("H*", "000fac");   # group cipher OUI
  $key_data .= pack ("C",  4);          # group cipher = AES-CCMP
  $key_data .= pack ("v",  1);          # pairwise cipher count
  $key_data .= pack ("H*", "000fac");   # pairwise OUI
  $key_data .= pack ("C",  4);          # pairwise = AES-CCMP
  $key_data .= pack ("v",  1);          # AKM count
  $key_data .= pack ("H*", "000fac");   # AKM OUI
  $key_data .= pack ("C",  4);          # AKM = FT/PSK
  $key_data .= pack ("H*", "0000");     # RSN capabilities

  $body .= pack ("n", length ($key_data));
  $body .= $key_data;

  # EAPOL framing
  my $frame = "";
  $frame .= pack ("C", 1);                # EAPOL version
  $frame .= pack ("C", 3);                # type = Key
  $frame .= pack ("n", length ($body));   # length
  $frame .= $body;

  return $frame;
}

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $type   = shift // random_number (3, 4);
  my $macap  = shift;
  my $macsta = shift;
  my $essid  = shift;
  my $anonce = shift;
  my $eapol  = shift;
  my $mp     = shift;
  my $mdid   = shift;
  my $r0khid = shift;
  my $r1khid = shift;

  # Provide random values for fields not supplied by the caller
  $macap  //= unpack ("H*", random_bytes (6));
  $macsta //= unpack ("H*", random_bytes (6));
  $essid  //= unpack ("H*", random_bytes (random_number (0, 32) & 0x1e));
  $mdid   //= unpack ("H*", random_bytes (2));
  $r0khid //= unpack ("H*", random_bytes (random_number (0, 48)));
  $r1khid //= unpack ("H*", random_bytes (6));

  my $macap_bin  = pack ("H*", $macap);
  my $macsta_bin = pack ("H*", $macsta);
  my $essid_bin  = pack ("H*", $essid);
  my $mdid_bin   = pack ("H*", $mdid);
  my $r0khid_bin = pack ("H*", $r0khid);
  my $r1khid_bin = pack ("H*", $r1khid);

  # PMK = PBKDF2-HMAC-SHA1 (passphrase, SSID, 4096, 32)
  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => 4096,
    output_len => 32,
  );

  my $pmk = $pbkdf2->PBKDF2 ($essid_bin, $word);

  # Shared FT-R0 KDF context: ESSIDlen || ESSID || MDID || R0KHIDlen || R0KHID || SPA
  my $r0_ctx = chr (length ($essid_bin)) . $essid_bin
             . $mdid_bin
             . chr (length ($r0khid_bin)) . $r0khid_bin
             . $macsta_bin;

  my $hash;

  if ($type == 3)
  {
    ##
    ## FT PMKID path (type = 3)
    ##
    ## IEEE 802.11r PMK-R0 KDF is 384 bits, requiring two HMAC rounds.
    ## The PMKID is derived from bytes 32-47 of that KDF output (counter = 2).
    ##

    # PMK-R0 KDF block 2 (bytes 32-47 of 384-bit output)
    my $pmkr0_b2 = ft_kdf_block ($pmk, 2, "FT-R0", $r0_ctx, 384);

    # PMK-R0-Name = Truncate-128 (SHA-256 ("FT-R0N" || PMK-R0-block2[0:16]))
    my $pmkr0_name = substr (sha256 ("FT-R0N" . substr ($pmkr0_b2, 0, 16)), 0, 16);

    # PMKID = Truncate-128 (SHA-256 ("FT-R1N" || PMK-R0-Name || R1KH-ID || SPA))
    my $pmkid = substr (sha256 ("FT-R1N" . $pmkr0_name . $r1khid_bin . $macsta_bin), 0, 16);

    $hash = sprintf ("WPA*%02x*%s*%s*%s*%s****%s*%s*%s",
      $type,
      unpack ("H*", $pmkid),
      $macap,
      $macsta,
      $essid,
      $mdid,
      $r0khid,
      $r1khid);
  }
  elsif ($type == 4)
  {
    ##
    ## FT EAPOL path (type = 4, keyver = 3 = AES-CMAC)
    ##

    my $snonce_bin;

    if (!defined ($eapol))
    {
      # Generate a fresh EAPOL for this candidate
      $snonce_bin = random_bytes (32);
      $anonce     = random_bytes (32);
      $eapol      = gen_ft_eapol ($snonce_bin);
      $mp         = "\x00";
    }
    else
    {
      $eapol      = pack ("H*", $eapol);
      $snonce_bin = substr ($eapol, 17, 32);  # wpa_key_nonce from auth_packet_t
      $anonce     = pack ("H*", $anonce);
      $mp         = (defined $mp && $mp =~ /^[0-9a-fA-F]{2}$/) ? pack ("H*", $mp) : "\x00";
    }

    # PMK-R0 = KDF-384 block 1: counter = 1
    my $pmkr0 = ft_kdf_block ($pmk, 1, "FT-R0", $r0_ctx, 384);

    # PMK-R1 = KDF-256: HMAC-SHA256 (PMK-R0, "\x01\x00FT-R1" || R1KH-ID || SPA || "\x00\x01")
    my $r1_ctx = $r1khid_bin . $macsta_bin;
    my $pmkr1  = ft_kdf_block ($pmkr0, 1, "FT-R1", $r1_ctx, 256);

    # PTK = KDF-384 block 1: HMAC-SHA256 (PMK-R1, "\x01\x00FT-PTK" || SNonce || ANonce || AP-MAC || SPA || "\x80\x01")
    my $ptk_ctx = $snonce_bin . $anonce . $macap_bin . $macsta_bin;
    my $ptk     = ft_kdf_block ($pmkr1, 1, "FT-PTK", $ptk_ctx, 384);

    my $kck = substr ($ptk, 0, 16);   # KCK = first 16 bytes of PTK

    # Zero the MIC field in the stored EAPOL before CMAC (bytes 81-96 of auth_packet_t)
    substr ($eapol, 81, 16) = "\x00" x 16;

    # MIC = AES-128-CMAC (KCK, EAPOL)
    my $omac1 = Digest::CMAC->new ($kck, 'Crypt::Rijndael');
    $omac1->add ($eapol);
    my $mic = substr ($omac1->digest, 0, 16);

    $hash = sprintf ("WPA*%02x*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s",
      $type,
      unpack ("H*", $mic),
      $macap,
      $macsta,
      $essid,
      unpack ("H*", $anonce),
      unpack ("H*", $eapol),
      unpack ("H*", $mp),
      $mdid,
      $r0khid,
      $r1khid);
  }

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $word    = substr ($line, $index1 + 1);
  my $hash_in = substr ($line, 0, $index1);

  my @data = split ('\*', $hash_in);

  my ($signature, $type_hex, $pmkidmic, $macap, $macsta, $essid,
      $anonce, $eapol, $mp, $mdid, $r0khid, $r1khid) = @data;

  return unless defined $signature && $signature eq "WPA";
  return unless defined $type_hex;
  return unless defined $pmkidmic;
  return unless defined $macap && defined $macsta && defined $essid;
  return unless defined $mdid  && defined $r0khid && defined $r1khid;

  my $type = hex ($type_hex);

  return unless $type == 3 || $type == 4;

  $anonce //= "";
  $eapol  //= "";
  $mp     //= "00";

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $type,
    $macap, $macsta, $essid,
    $anonce, $eapol, $mp,
    $mdid, $r0khid, $r1khid);

  return ($new_hash, $word);
}

1;

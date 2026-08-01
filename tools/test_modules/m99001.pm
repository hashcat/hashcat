#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Rijndael;

# password: raw PSK candidate. 1..16 bytes -> zero-padded to 16 (AES-128 key);
#           17..32 bytes -> zero-padded to 32 (AES-256 key). Anything past 32 is truncated.
# "salt":  unused -- per-frame data lives in our esalt and is built from the optional args below.
sub module_constraints { [[1, 32], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub _xor_byte
{
  my $bytes = shift;

  my $x = 0;

  for my $b (unpack ("C*", $bytes))
  {
    $x ^= $b;
  }

  return $x;
}

sub _pad_psk
{
  # Length <= 16 -> AES-128 key (zero-padded to 16). 17..32 -> AES-256 key (zero-padded to 32).
  my $word = shift;
  my $len  = length ($word);

  if ($len > 32) { return substr ($word, 0, 32); }
  if ($len > 16) { return $word . ("\x00" x (32 - $len)); }
  return $word . ("\x00" x (16 - $len));
}

sub _aes_ctr_first_block
{
  my ($key, $packet_id, $from_node, $plaintext) = @_;

  # CTR nonce: packet_id_LE || 0x00000000 || from_node_LE || 0x00000000
  my $nonce = pack ("V", $packet_id) . "\x00\x00\x00\x00" . pack ("V", $from_node) . "\x00\x00\x00\x00";

  # Crypt::Rijndael picks AES-128 or AES-256 from the key length (16 or 32 bytes).
  my $aes = Crypt::Rijndael->new ($key, Crypt::Rijndael::MODE_ECB ());

  my $ks = $aes->encrypt ($nonce);

  return $ks ^ $plaintext;
}

sub module_generate_hash
{
  my $word      = shift;
  my $salt_in   = shift; # ignored
  my $name      = shift;
  my $packet_id = shift;
  my $from_node = shift;
  my $portnum   = shift;
  my $payload   = shift;

  # randomise anything not supplied so test.pl single-mode produces fresh hashes each run
  $name      = "LongFast"                      if (! defined ($name));
  $packet_id = unpack ("V", random_bytes (4))  if (! defined ($packet_id));
  $from_node = unpack ("V", random_bytes (4))  if (! defined ($from_node));
  $portnum   = 1                               if (! defined ($portnum));
  $payload   = "hashcat"                       if (! defined ($payload));

  my $key = _pad_psk ($word);

  # Meshtastic Data envelope (protobuf):
  #   tag 0x08 (field 1 / varint) + portnum
  #   tag 0x12 (field 2 / length-delimited) + length + payload
  my $plaintext = pack ("CCCC", 0x08, $portnum & 0x7f, 0x12, length ($payload)) . $payload;

  # we only need a single 16-byte CTR block for the verifier; pad to 16
  if (length ($plaintext) < 16)
  {
    $plaintext .= "\x00" x (16 - length ($plaintext));
  }
  else
  {
    $plaintext = substr ($plaintext, 0, 16);
  }

  my $ct = _aes_ctr_first_block ($key, $packet_id, $from_node, $plaintext);

  my $chash = _xor_byte ($name) ^ _xor_byte ($key);

  # packet_id and from_node are written as the 4 on-wire LE bytes in hex
  # (so "deadbeef" represents the byte sequence de ad be ef).
  my $hash = sprintf ('$meshtastic$1*%02x*%s*%s*%s*%s',
    $chash,
    unpack ("H*", pack ("V", $packet_id)),
    unpack ("H*", pack ("V", $from_node)),
    unpack ("H*", $name),
    unpack ("H*", $ct));

  return $hash;
}

# Build a $meshtastic$2 multi-frame line for cross-frame testing. The PSK,
# channel name, and (chash, name_xor) all carry over between frames; what
# differs per frame is (packet_id, from_node, payload).
#
# $frames is an arrayref of arrayrefs: [ [pkt, from, portnum, payload], ... ]
sub module_generate_hash_multi
{
  my $word   = shift;
  my $name   = shift // "LongFast";
  my $frames = shift;

  die "module_generate_hash_multi: need at least 2 frames for v2\n" unless (ref $frames eq 'ARRAY' && @$frames >= 2);

  my $key   = _pad_psk ($word);
  my $chash = _xor_byte ($name) ^ _xor_byte ($key);

  my $line = sprintf ('$meshtastic$2*%02x*%s*%d', $chash, unpack ("H*", $name), scalar @$frames);

  for my $fr (@$frames)
  {
    my ($pkt, $from, $portnum, $payload) = @$fr;

    my $plaintext = pack ("CCCC", 0x08, $portnum & 0x7f, 0x12, length ($payload)) . $payload;
    if (length ($plaintext) < 16) { $plaintext .= "\x00" x (16 - length ($plaintext)); }
    else                          { $plaintext = substr ($plaintext, 0, 16); }

    my $ct = _aes_ctr_first_block ($key, $pkt, $from, $plaintext);

    $line .= sprintf ('*%s*%s*%s',
      unpack ("H*", pack ("V", $pkt)),
      unpack ("H*", pack ("V", $from)),
      unpack ("H*", $ct));
  }

  return $line;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\*', $hash);

  return unless (scalar (@data) >= 6);
  return unless ($data[0] =~ /^\$meshtastic\$(\d+)$/);

  my $version = $1;

  if ($version eq '1')
  {
    return unless (scalar (@data) == 6);
    return unless (length ($data[1]) == 2);
    return unless (length ($data[2]) == 8);
    return unless (length ($data[3]) == 8);

    my $name      = pack ("H*", $data[4]);
    my $packet_id = unpack ("V", pack ("H*", $data[2]));
    my $from_node = unpack ("V", pack ("H*", $data[3]));
    my $ct_hex    = $data[5];

    my $word_packed = pack_if_HEX_notation ($word);
    my $key         = _pad_psk ($word_packed);
    my $ct          = pack ("H*", substr ($ct_hex, 0, 32));
    my $pt          = _aes_ctr_first_block ($key, $packet_id, $from_node, $ct);

    my @pb = unpack ("CCCC", substr ($pt, 0, 4));
    return unless ($pb[0] == 0x08);
    return unless ($pb[1] >  0);
    return unless ($pb[2] == 0x12);
    return unless ($pb[3] >  0);
    return unless ($pb[3] + 4 <= 16);

    my $portnum     = $pb[1];
    my $payload_len = $pb[3];
    my $payload     = substr ($pt, 4, $payload_len);

    my $new_hash = module_generate_hash ($word_packed, undef, $name, $packet_id, $from_node, $portnum, $payload);

    return ($new_hash, $word);
  }
  elsif ($version eq '2')
  {
    # v2 layout: [signature, chash, name, N, pkt1, from1, ct1, ..., pktN, fromN, ctN]
    # Token count: 4 + 3*N
    return unless (scalar (@data) >= 4 + 3 * 2);
    return unless (length ($data[1]) == 2);

    my $n = $data[3];
    return unless ($n =~ /^\d+$/ && $n >= 2 && $n <= 16);

    return unless (scalar (@data) == 4 + 3 * $n);

    my $name        = pack ("H*", $data[2]);
    my $word_packed = pack_if_HEX_notation ($word);
    my $key         = _pad_psk ($word_packed);

    my @decoded_frames;
    for (my $f = 0; $f < $n; $f++)
    {
      my $pkt_hex  = $data[4 + 3 * $f + 0];
      my $from_hex = $data[4 + 3 * $f + 1];
      my $ct_hex   = $data[4 + 3 * $f + 2];

      return unless (length ($pkt_hex) == 8);
      return unless (length ($from_hex) == 8);

      my $packet_id = unpack ("V", pack ("H*", $pkt_hex));
      my $from_node = unpack ("V", pack ("H*", $from_hex));

      my $ct = pack ("H*", substr ($ct_hex, 0, 32));
      my $pt = _aes_ctr_first_block ($key, $packet_id, $from_node, $ct);

      my @pb = unpack ("CCCC", substr ($pt, 0, 4));
      return unless ($pb[0] == 0x08);
      return unless ($pb[1] >  0);
      return unless ($pb[2] == 0x12);
      return unless ($pb[3] >  0);
      return unless ($pb[3] + 4 <= 16);

      my $portnum = $pb[1];
      my $payload = substr ($pt, 4, $pb[3]);

      push @decoded_frames, [ $packet_id, $from_node, $portnum, $payload ];
    }

    my $new_hash = module_generate_hash_multi ($word_packed, $name, \@decoded_frames);

    return ($new_hash, $word);
  }

  return;
}

1;

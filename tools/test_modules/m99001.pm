#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Rijndael;

# password: raw PSK candidate, padded/truncated to 16 bytes for AES-128
# "salt": unused -- the per-frame data lives in our esalt and is built from the optional args below
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

sub _pad16
{
  my $word = shift;

  if (length ($word) >= 16)
  {
    return substr ($word, 0, 16);
  }

  return $word . ("\x00" x (16 - length ($word)));
}

sub _aes_ctr_first_block
{
  my ($key16, $packet_id, $from_node, $plaintext) = @_;

  # CTR nonce: packet_id_LE || 0x00000000 || from_node_LE || 0x00000000
  my $nonce = pack ("V", $packet_id) . "\x00\x00\x00\x00" . pack ("V", $from_node) . "\x00\x00\x00\x00";

  my $aes = Crypt::Rijndael->new ($key16, Crypt::Rijndael::MODE_ECB ());

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

  my $key16 = _pad16 ($word);

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

  my $ct = _aes_ctr_first_block ($key16, $packet_id, $from_node, $plaintext);

  my $chash = _xor_byte ($name) ^ _xor_byte ($key16);

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

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  # split on '*' yields: [ "$meshtastic$1", chash, pkt, from, name, ct ]
  my @data = split ('\*', $hash);

  return unless (scalar (@data) == 6);

  return unless ($data[0] =~ /^\$meshtastic\$(\d+)$/);

  my $version = $1;

  return unless ($version eq '1');
  return unless (length ($data[1]) == 2);
  return unless (length ($data[2]) == 8);
  return unless (length ($data[3]) == 8);

  my $chash_hex = $data[1];
  my $pkt_hex   = $data[2];
  my $from_hex  = $data[3];
  my $name_hex  = $data[4];
  my $ct_hex    = $data[5];

  my $name      = pack ("H*", $name_hex);
  my $packet_id = unpack ("V", pack ("H*", $pkt_hex));
  my $from_node = unpack ("V", pack ("H*", $from_hex));

  my $word_packed = pack_if_HEX_notation ($word);

  # decrypt the first 16 ciphertext bytes; if it's a real Meshtastic frame
  # we recover the portnum and payload-length-prefixed payload.
  my $key16 = _pad16 ($word_packed);

  my $ct = pack ("H*", substr ($ct_hex, 0, 32));

  my $pt = _aes_ctr_first_block ($key16, $packet_id, $from_node, $ct);

  my @pb = unpack ("CCCC", substr ($pt, 0, 4));

  return unless ($pb[0] == 0x08);
  return unless ($pb[1] >  0);
  return unless ($pb[2] == 0x12);
  return unless ($pb[3] >  0);

  my $portnum     = $pb[1];
  my $payload_len = $pb[3];

  return unless ($payload_len + 4 <= 16);

  my $payload = substr ($pt, 4, $payload_len);

  my $new_hash = module_generate_hash ($word_packed, undef, $name, $packet_id, $from_node, $portnum, $payload);

  return ($new_hash, $word);
}

1;

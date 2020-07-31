#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1 qw (sha1);
use Digest::HMAC qw (hmac);

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 4096;

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 20
  );

  my $key = $kdf->PBKDF2 ($salt, $word);

  my $digest_hmac = hmac ("Client Key", $key, \&sha1, 64);

  my $digest_sha1 = sha1 ($digest_hmac);

  my $hash = sprintf ("\$xmpp-scram\$0\$%d\$%d\$%s\$%s", $iter, length ($salt), unpack ("H*", $salt), unpack ("H*", $digest_sha1));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 13) eq '$xmpp-scram$0';

  my (undef, $signature, $type, $iter, $salt_len, $salt_hex, $hash_hex) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $type;
  return unless defined $iter;
  return unless defined $salt_len;
  return unless defined $salt_hex;
  return unless defined $hash_hex;

  return unless ($signature eq 'xmpp-scram');
  return unless ($type eq '0');

  my $salt = pack ("H*", $salt_hex);

  return unless ($salt_len == length $salt);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;

#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;

sub module_constraints { [[-1, -1], [-1, -1], [9, 9], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $dropN = shift;
  my $ciphertext = shift;
  my $plaintext_offset = shift;
  my $plaintext = shift;

  if (!defined $plaintext || !defined $dropN)
  {
    $dropN      = random_number (0, 512);
    $plaintext  = random_string (random_number (5, 64));
  }

  my $cipher = Crypt::RC4->new ($word);

  if ($dropN gt 0)
  {
    $cipher->RC4("\x00" x $dropN);
  }

  my $digest = unpack ("H*", $cipher->RC4 ($plaintext));

  if (defined $ciphertext)
  {
    if (substr ($ciphertext, 0, 10) eq $digest)
    {
      $digest = $ciphertext;
    }
  }

  my $hash = sprintf ('$rc4$72$%d$%s$0$%s', $dropN, $digest, substr (unpack ("H*", $plaintext), 0, 10));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 8);

  return unless ($signature eq "\$rc4\$72\$");

  my @data = split ('\$', $hash);

  return unless scalar (@data) == 7;

  shift @data;
  shift @data;
  shift @data;

  my $dropN = shift @data;
  my $ciphertext = shift @data;
  my $plaintext_offset = shift @data;
  my $plaintext = pack ("H*", shift @data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $dropN, $ciphertext, $plaintext_offset, $plaintext);

  return ($new_hash, $word);
}

1;

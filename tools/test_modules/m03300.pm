#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[0, 256], [1, 8], [-1, -1], [-1, -1], [-1, -1]] }

my $constant_phrase =
  "To be, or not to be,--that is the question:--\n" .
  "Whether 'tis nobler in the mind to suffer\n" .
  "The slings and arrows of outrageous fortune\n" .
  "Or to take arms against a sea of troubles,\n" .
  "And by opposing end them?--To die,--to sleep,--\n" .
  "No more; and by a sleep to say we end\n" .
  "The heartache, and the thousand natural shocks\n" .
  "That flesh is heir to,--'tis a consummation\n" .
  "Devoutly to be wish'd. To die,--to sleep;--\n" .
  "To sleep! perchance to dream:--ay, there's the rub;\n" .
  "For in that sleep of death what dreams may come,\n" .
  "When we have shuffled off this mortal coil,\n" .
  "Must give us pause: there's the respect\n" .
  "That makes calamity of so long life;\n" .
  "For who would bear the whips and scorns of time,\n" .
  "The oppressor's wrong, the proud man's contumely,\n" .
  "The pangs of despis'd love, the law's delay,\n" .
  "The insolence of office, and the spurns\n" .
  "That patient merit of the unworthy takes,\n" .
  "When he himself might his quietus make\n" .
  "With a bare bodkin? who would these fardels bear,\n" .
  "To grunt and sweat under a weary life,\n" .
  "But that the dread of something after death,--\n" .
  "The undiscover'd country, from whose bourn\n" .
  "No traveller returns,--puzzles the will,\n" .
  "And makes us rather bear those ills we have\n" .
  "Than fly to others that we know not of?\n" .
  "Thus conscience does make cowards of us all;\n" .
  "And thus the native hue of resolution\n" .
  "Is sicklied o'er with the pale cast of thought;\n" .
  "And enterprises of great pith and moment,\n" .
  "With this regard, their currents turn awry,\n" .
  "And lose the name of action.--Soft you now!\n" .
  "The fair Ophelia!--Nymph, in thy orisons\n" .
  "Be all my sins remember'd.\n";

my $constant_phrase_with_nul = $constant_phrase . "\x00";

sub md5bit
{
  my ($digest, $n) = @_;

  $n %= 128;

  my $byte_off = int ($n / 8);
  my $bit_off  = $n % 8;

  my $byte = ord (substr ($digest, $byte_off, 1));

  return ($byte >> $bit_off) & 1;
}

sub sunmd5_coin
{
  my ($digest, $round) = @_;

  my @db;

  for (my $i = 0; $i < 16; $i++)
  {
    $db[$i] = ord (substr ($digest, $i, 1));
  }

  my $x = 0;
  my $y = 0;

  for (my $i = 0; $i < 8; $i++)
  {
    my ($a, $b, $r, $v);

    $a = $db[($i + 0) % 16];
    $b = $db[($i + 3) % 16];
    $r = $a >> ($b % 5);
    $v = $db[$r % 16];

    if ($b & (1 << ($a % 8)))
    {
      $v >>= 1;
    }

    $x |= md5bit ($digest, $v) << $i;

    $a = $db[($i + 8) % 16];
    $b = $db[($i + 11) % 16];
    $r = $a >> ($b % 5);
    $v = $db[$r % 16];

    if ($b & (1 << ($a % 8)))
    {
      $v >>= 1;
    }

    $y |= md5bit ($digest, $v) << $i;
  }

  if (md5bit ($digest, $round))
  {
    $x >>= 1;
  }

  if (md5bit ($digest, $round + 64))
  {
    $y >>= 1;
  }

  return md5bit ($digest, $x & 0x7f) ^ md5bit ($digest, $y & 0x7f);
}

sub to64
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $ret = "";

  while (($n - 1) >= 0)
  {
    $n = $n - 1;

    $ret .= substr ($itoa64, $v & 0x3f, 1);

    $v = $v >> 6;
  }

  return $ret;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $extra_rounds = 0;

  if (defined ($iter))
  {
    $extra_rounds = int ($iter);
  }

  my $total_rounds = 4096 + $extra_rounds;

  my $puresalt;

  if ($extra_rounds > 0)
  {
    $puresalt = sprintf ("\$md5,rounds=%d\$%s\$", $extra_rounds, $salt);
  }
  else
  {
    $puresalt = sprintf ("\$md5\$%s\$", $salt);
  }

  my $digest = md5 ($word . $puresalt);

  for (my $round = 0; $round < $total_rounds; $round++)
  {
    my $coin = sunmd5_coin ($digest, $round);

    my $buf = $digest;

    if ($coin == 1)
    {
      $buf .= $constant_phrase_with_nul;
    }

    $buf .= sprintf ("%d", $round);

    $digest = md5 ($buf);
  }

  my $hash = "";

  $hash .= to64 ((ord (substr ($digest,  0, 1)) << 16) | (ord (substr ($digest,  6, 1)) << 8) | (ord (substr ($digest, 12, 1))), 4);
  $hash .= to64 ((ord (substr ($digest,  1, 1)) << 16) | (ord (substr ($digest,  7, 1)) << 8) | (ord (substr ($digest, 13, 1))), 4);
  $hash .= to64 ((ord (substr ($digest,  2, 1)) << 16) | (ord (substr ($digest,  8, 1)) << 8) | (ord (substr ($digest, 14, 1))), 4);
  $hash .= to64 ((ord (substr ($digest,  3, 1)) << 16) | (ord (substr ($digest,  9, 1)) << 8) | (ord (substr ($digest, 15, 1))), 4);
  $hash .= to64 ((ord (substr ($digest,  4, 1)) << 16) | (ord (substr ($digest, 10, 1)) << 8) | (ord (substr ($digest,  5, 1))), 4);
  $hash .= to64 (ord (substr ($digest, 11, 1)), 2);

  return sprintf ("%s\$%s", $puresalt, $hash);
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  return unless (substr ($hash, 0, 4) eq '$md5');

  my $extra_rounds = 0;
  my $salt;
  my $pos = 4;

  my $c = substr ($hash, $pos, 1);

  return unless ($c eq ',' || $c eq '$');

  $pos++;

  if (substr ($hash, $pos, 7) eq 'rounds=')
  {
    $pos += 7;

    my $rounds_end = index ($hash, '$', $pos);

    return if ($rounds_end < 0);

    $extra_rounds = int (substr ($hash, $pos, $rounds_end - $pos));

    $pos = $rounds_end + 1;
  }

  my $last_sep = rindex ($hash, '$');

  return if ($last_sep < $pos);

  $salt = substr ($hash, $pos, $last_sep - $pos);

  $salt =~ s/\$$//;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $extra_rounds);

  return ($new_hash, $word);
}

1;

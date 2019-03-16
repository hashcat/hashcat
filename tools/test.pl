#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Data::Types qw (is_count is_int is_whole);
use File::Basename;
use FindBin;
use List::Util 'shuffle';

# allows require by filename
use lib "$FindBin::Bin/test_modules";

my $IS_OPTIMIZED = 1;

if (exists $ENV{"IS_OPTIMIZED"} && defined $ENV{"IS_OPTIMIZED"})
{
  $IS_OPTIMIZED = $ENV{"IS_OPTIMIZED"};
}

my $TYPES = [ 'single', 'passthrough', 'verify' ];

my $TYPE = shift @ARGV;
my $MODE = shift @ARGV;

is_in_array ($TYPE, $TYPES) or usage_exit ();

is_whole ($MODE) or die "Mode must be a number\n";

my $MODULE_FILE = sprintf ("m%05d.pm", $MODE);

eval { require $MODULE_FILE } or die "Could not load test module: $MODULE_FILE\n$@";

exists &{module_constraints}   or die "Module function 'module_constraints' not found\n";
exists &{module_generate_hash} or die "Module function 'module_generate_hash' not found\n";
exists &{module_verify_hash}   or die "Module function 'module_verify_hash' not found\n";

my $giveup_at      = 1000000;
my $single_outputs = 8;

my $constraints = get_module_constraints ();

if ($TYPE eq 'single')
{
  single (@ARGV);
}
elsif ($TYPE eq 'passthrough')
{
  passthrough ();
}
elsif ($TYPE eq "verify")
{
  usage_exit () if scalar @ARGV != 3;

  verify (@ARGV);
}
else
{
  usage_exit ();
}

sub single
{
  my $len = shift;

  # fallback to incrementing length
  undef $len unless is_count ($len);

  my $word_min = ($IS_OPTIMIZED == 1) ? $constraints->[2]->[0] : $constraints->[0]->[0];
  my $word_max = ($IS_OPTIMIZED == 1) ? $constraints->[2]->[1] : $constraints->[0]->[1];
  my $salt_min = ($IS_OPTIMIZED == 1) ? $constraints->[3]->[0] : $constraints->[1]->[0];
  my $salt_max = ($IS_OPTIMIZED == 1) ? $constraints->[3]->[1] : $constraints->[1]->[1];

  my $db_word_len = init_db_word_rand ($word_min, $word_max);
  my $db_salt_len = init_db_salt_rand ($salt_min, $salt_max);

  my $db_prev;

  my $giveup = 0;

  my $idx = 0;

  while ($idx < $single_outputs)
  {
    last if ($giveup++ == $giveup_at);

    my $word_len = 0;

    if (defined $len)
    {
      next if $len < $word_min;
      next if $len > $word_max;

      $word_len = $len;
    }
    else
    {
      $word_len = $db_word_len->[$idx];
    }

    my $salt_len = 0;

    if ($salt_min != -1)
    {
      if ($salt_min == $salt_max)
      {
        $salt_len = $salt_min;
      }
      else
      {
        $salt_len = $db_salt_len->[$giveup % scalar @{$db_salt_len}];
      }
    }

    # mostly important for raw hashes in optimized mode

    my $comb_len = $word_len + $salt_len;

    if ($IS_OPTIMIZED == 1)
    {
      my $comb_min = $constraints->[4]->[0];
      my $comb_max = $constraints->[4]->[1];

      if ($comb_min != -1)
      {
        next if $comb_len < $comb_min;
        next if $comb_len > $comb_max;
      }
    }

    my $word = random_numeric_string ($word_len) // "";
    my $salt = random_numeric_string ($salt_len) // "";

    # check if this combination out of word and salt was previously checked
    next if exists $db_prev->{$word}->{$salt};

    $db_prev->{$word}->{$salt} = undef;

    $idx++;

    last if ($idx >= scalar @{$db_word_len});
  }

  for my $word (sort { length $a <=> length $b } keys %{$db_prev})
  {
    for my $salt (sort { length $a <=> length $b } keys %{$db_prev->{$word}})
    {
      my $hash = module_generate_hash ($word, $salt);

      # possible if the requested length is not supported by algorithm
      next unless defined $hash;

      my $format = "echo %-31s | ./hashcat \${OPTS} -a 0 -m %d '%s'\n";

      printf ($format, $word, $MODE, $hash);
    }
  }
}

sub passthrough
{
  while (my $word = <>)
  {
    chomp $word;

    my $word_len = length $word;

    if ($IS_OPTIMIZED == 1)
    {
      next if ($word_len > 31);
    }

    my $giveup = 0;

    my $idx = 0;

    while ($idx < 1)
    {
      last if ($giveup++ == $giveup_at);

      my $salt_len = 0;

      my $salt_min = ($IS_OPTIMIZED == 1) ? $constraints->[3]->[0] : $constraints->[1]->[0];
      my $salt_max = ($IS_OPTIMIZED == 1) ? $constraints->[3]->[1] : $constraints->[1]->[1];

      if ($salt_min != -1)
      {
        if ($salt_min == $salt_max)
        {
          $salt_len = $salt_min;
        }
        else
        {
          $salt_len = random_number ($salt_min, $salt_max);
        }
      }

      my $comb_len = $word_len + $salt_len;

      if ($IS_OPTIMIZED == 1)
      {
        my $comb_min = $constraints->[4]->[0];
        my $comb_max = $constraints->[4]->[1];

        if ($comb_min != -1)
        {
          next if $comb_len < $comb_min;
          next if $comb_len > $comb_max;
        }
      }

      my $salt = random_numeric_string ($salt_len) // "";

      $idx++;

      my $hash = module_generate_hash ($word, $salt);

      next unless defined $hash;

      print "$hash\n";
    }
  }
}

sub verify
{
  my $hashes_file = shift;
  my $cracks_file = shift;
  my $out_file    = shift;

  open (IN, '<', $hashes_file) or die "$hashes_file: $!\n";

  my @hashlist;

  while (my $line = <IN>)
  {
    $line =~ s/\n$//;
    $line =~ s/\r$//;

    push (@hashlist, $line);
  }

  close (IN);

  open (IN,  '<', $cracks_file) or die "$cracks_file: $!\n";
  open (OUT, '>', $out_file)    or die "$out_file: $!\n";

  while (my $line = <IN>)
  {
    $line =~ s/\n$//;
    $line =~ s/\r$//;

    my ($hash, $word) = module_verify_hash ($line);

    # possible if the hash:password pair does not match
    next unless defined $hash;

    # check if the crack is okay
    next unless $line eq ($hash . ":" . $word);

    # possible if the hash is in cracksfile, but not in hashfile
    next unless is_in_array ($hash, \@hashlist);

    print OUT "$line\n";
  }

  close (IN);
  close (OUT);
}

sub is_in_array
{
  my $value = shift;
  my $array = shift;

  return unless defined $value;
  return unless defined $array;

  return grep { $_ eq $value } @{$array};
}

sub get_module_constraints
{
  my $constraints = module_constraints ();

  if (($constraints->[0]->[0] == -1) && ($constraints->[0]->[1] == -1))
  {
    # hash-mode doesn't have a pure kernel, use optimized password settings

    $constraints->[0]->[0] = $constraints->[2]->[0];
    $constraints->[0]->[1] = $constraints->[2]->[1];
    $constraints->[1]->[0] = $constraints->[3]->[0];
    $constraints->[1]->[1] = $constraints->[3]->[1];

    $IS_OPTIMIZED = 1;
  }
  elsif (($constraints->[2]->[0] == -1) && ($constraints->[2]->[1] == -1))
  {
    # hash-mode doesn't have a optimized kernel, use pure password settings

    $constraints->[2]->[0] = $constraints->[0]->[0];
    $constraints->[2]->[1] = $constraints->[0]->[1];
    $constraints->[3]->[0] = $constraints->[1]->[0];
    $constraints->[3]->[1] = $constraints->[1]->[1];

    $IS_OPTIMIZED = 0;
  }

  return $constraints;
}

sub init_db_word_rand
{
  my $len_min = shift;
  my $len_max = shift;

  return if ($len_min == -1);
  return if ($len_max == -1);

  if ($IS_OPTIMIZED == 1)
  {
    if ($constraints->[4]->[0] != -1)
    {
      my $salt_min = $constraints->[3]->[0];
      my $salt_max = $constraints->[3]->[1];

      if ($salt_min == $salt_max)
      {
        $len_max -= $salt_min;
      }
    }

    # for non-fixed password length algorithms

    if ($len_min != $len_max)
    {
      # longer than 31 does not work for -a 0 in optimized mode

      $len_max = ($len_max >= 31) ? 31 : $len_max;
    }

    $len_min = ($len_min < $len_max) ? $len_min : $len_max;
  }

  my @pool;

  for (my $len = $len_min; $len <= $len_max; $len++)
  {
    next if ($len == 0);

    push @pool, $len;
  }

  while (scalar @pool < $single_outputs)
  {
    @pool = shuffle (@pool);

    push @pool, $pool[0];
  }

  @pool = shuffle (@pool);

  my $db_out;

  $db_out->[0] = $len_min;
  $db_out->[1] = $len_max;

  for (my $idx = 2; $idx < $single_outputs; $idx++)
  {
    $db_out->[$idx] = shift @pool;
  }

  # make sure the password length is only increasing, which is important for test.sh in -a 1 mode to work

  @{$db_out} = sort { length $a <=> length $b } @{$db_out};

  return $db_out;
}

sub init_db_salt_rand
{
  my $len_min = shift;
  my $len_max = shift;

  return if ($len_min == -1);
  return if ($len_max == -1);

  if ($IS_OPTIMIZED == 1)
  {
    # longer than 51 triggers a parser bug in old hashcat, have to leave this during migration phase
    # #define SALT_MAX_OLD        51
    # salt_max = SALT_MAX_OLD;

    $len_max = ($len_max >= 51) ? 51 : $len_max;

    $len_min = ($len_min < $len_max) ? $len_min : $len_max;
  }

  my @pool;

  for (my $len = $len_min; $len <= $len_max; $len++)
  {
    next if ($len == 0);

    push @pool, $len;
  }

  while (scalar @pool < $single_outputs)
  {
    @pool = shuffle (@pool);

    push @pool, $pool[0];
  }

  @pool = shuffle (@pool);

  my $db_out;

  $db_out->[0] = $len_min;
  $db_out->[1] = $len_max;

  for (my $idx = 2; $idx < $single_outputs; $idx++)
  {
    $db_out->[$idx] = shift @pool;
  }

  @{$db_out} = sort { length $b <=> length $a } @{$db_out};

  return $db_out;
}

# detect hashcat $HEX[...] notation and pack as binary
sub pack_if_HEX_notation
{
  my $string = shift;

  return unless defined $string;

  if ($string =~ m/^\$HEX\[[0-9a-fA-F]*\]$/)
  {
    return pack ("H*", substr ($string, 5, -1));
  }

  return $string;
}

# random_count (max)
# returns integer from 1 to max
sub random_count
{
  my $max = shift;

  return unless is_count $max;

  return int ((rand ($max - 1)) + 1);
}

# random_number (min, max)
sub random_number
{
  my $min = shift;
  my $max = shift;

  return if $min > $max;

  return int ((rand (($max + 1) - $min)) + $min);
}

sub random_bytes
{
  # length in bytes
  my $count = shift;

  return pack ("H*", random_hex_string (2 * $count));
}

sub random_hex_string
{
  # length in characters
  my $count = shift;

  return if ! is_count ($count);

  my $string;

  $string .= sprintf ("%x", rand 16) for (1 .. $count);

  return $string;
}

sub random_lowercase_string
{
  my $count = shift;

  return if ! is_count ($count);

  my @chars = ('a'..'z');

  my $string;

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_uppercase_string
{
  my $count = shift;

  return if ! is_count ($count);

  my @chars = ('A'..'Z');

  my $string;

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_mixedcase_string
{
  my $count = shift;

  return if ! is_count ($count);

  my @chars = ('A'..'Z', 'a'..'z');

  my $string;

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_numeric_string
{
  my $count = shift;

  return if ! is_count ($count);

  my @chars = ('0'..'9');

  my $string;

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_string
{
  my $count = shift;

  return if ! is_count ($count);

  my @chars = ('A'..'Z', 'a'..'z', '0'..'9');

  my $string;

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub usage_exit
{
  my $f = basename ($0);

  print "\n"
    . "Usage:\n"
    . " $f single      <mode> [length]\n"
    . " $f passthrough <mode>\n"
    . " $f verify      <mode> <hashfile> <cracksfile> <outfile>\n"
    . "\n"
    . "Single:\n"
    . " Generates up to 32 hashes of random numbers of incrementing length, or up to 32\n"
    . " hashes of random numbers of exact [length]. Writes shell commands to stdout that\n"
    . " can be processed by the test.sh script.\n"
    . "\n"
    . "Passthrough:\n"
    . " Generates hashes for strings entered via stdin and prints them to stdout.\n"
    . "\n"
    . "Verify:\n"
    . " Reads a list of hashes from <hashfile> and a list of hash:password pairs from\n"
    . " <cracksfile>. Hashes every password and compares the hash to the corresponding\n"
    . " entry in the <cracksfile>. If the hashes match and the hash is present in the\n"
    . " list from <hashfile>, it will be written to the <outfile>.\n";

  exit 1;
}

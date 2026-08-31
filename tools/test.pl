#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use File::Basename;
use FindBin;
use List::Util 'shuffle';

my $TYPES = [ 'edge', 'single', 'password', 'passthrough', 'potthrough', 'verify' ];

my $TYPE = shift @ARGV;
my $MODE = shift @ARGV;

is_in_array ($TYPE, $TYPES) or usage_exit ();

eval {
    require Data::Types;  Data::Types->import(qw(is_count is_whole));
    require Digest::MD4;  Digest::MD4->import('md4_hex');
    1;
} or die "Missing Perl modules, read: docs/hashcat-plugin-development-guide.md (search test.pl), and run: ./tools/install_modules.sh\n";

# allows require by filename
use lib "$FindBin::Bin/test_modules";

my $IS_OPTIMIZED = 1;

if (exists $ENV{"IS_OPTIMIZED"} && defined $ENV{"IS_OPTIMIZED"})
{
  $IS_OPTIMIZED = $ENV{"IS_OPTIMIZED"};
}

is_whole ($MODE) or die "Mode must be a number\n";

my $MODULE_FILE = sprintf ("m%05d.pm", $MODE);

eval { require $MODULE_FILE } or die "Could not load test module: $MODULE_FILE\n$@";

exists &{module_constraints}   or die "Module function 'module_constraints' not found\n";
exists &{module_generate_hash} or die "Module function 'module_generate_hash' not found\n";
exists &{module_verify_hash}   or die "Module function 'module_verify_hash' not found\n";

my $giveup_at      = 1000000;
my $single_outputs = 8;

my $constraints = get_module_constraints ();

# Multi byte UTF-8 characters the generated passwords are seeded with. Every entry is a raw
# byte string, and together they cover the lead bytes a kernel has to get right: a euro sign,
# hiragana, katakana, CJK, hangul, devanagari, fullwidth latin and one 4 byte character.
# Passwords made only of digits never leave the ASCII path, so a mode that mangles anything
# above 0x7f used to pass the suite unnoticed.

my @NON_ASCII_CHARS =
(
  "\xe0\xa4\xb9",      # U+0939  devanagari letter ha
  "\xe2\x82\xac",      # U+20AC  euro sign
  "\xe3\x81\x8b",      # U+304B  hiragana letter ka
  "\xe3\x82\xab",      # U+30AB  katakana letter ka
  "\xe4\xb8\xad",      # U+4E2D  cjk ideograph 'middle'
  "\xe6\x96\x87",      # U+6587  cjk ideograph 'script'
  "\xe7\xa0\x81",      # U+7801  cjk ideograph 'code'
  "\xe9\xbe\x8d",      # U+9F8D  cjk ideograph 'dragon'
  "\xea\xb0\x80",      # U+AC00  hangul syllable ga
  "\xef\xbc\xa1",      # U+FF21  fullwidth latin capital a
  "\xf0\x9f\x98\x80",  # U+1F600 grinning face
);

# Where the characters may land. Anywhere, including the first byte: tools/test.sh rewrites
# the '?d' at a position whose byte is not a digit into that byte, so a mask can spell one
# wherever it turns up.
#
# The multi hash tests are the reason the layout is not drawn from rand(). They share one mask
# across every password of a given length, so the characters have to sit in the same places in
# all of them. The generator below is seeded from the length alone, which makes the shape of a
# password a function of its length while the digits around it stay random per password.

my $NON_ASCII_SKIP_BYTES = 0;

# A character is only written where the password keeps at least one byte outside it. -a 1, -a 6,
# -a 7 and -a 12 cut the password in two and both halves have to land on a character boundary,
# so a password that is nothing but one character cannot be cut at all and leaves one of the two
# dictionaries empty. This is the smallest rule that avoids it: it costs nothing above 4 bytes,
# where the old flat minimum of 6 cost every password of 4 and 5 bytes as well.

my $NON_ASCII_MIN_SPARE = 1;

# Roughly how often an eligible position is turned into a multi byte character. Low enough
# that a generated set still holds plain ASCII passwords, high enough that a set of 8 almost
# always holds at least one that is not.

my $NON_ASCII_RATE = 0.34;

my $NON_ASCII_OK = non_ascii_supported ($MODE);

if ($TYPE eq 'edge')
{
  usage_exit () if scalar @ARGV > 2;

  edge (@ARGV);
}
elsif ($TYPE eq 'single')
{
  single (@ARGV);
}
elsif ($TYPE eq 'password')
{
  usage_exit () if scalar @ARGV > 1;

  password (@ARGV);
}
elsif ($TYPE eq 'passthrough')
{
  usage_exit () if scalar @ARGV > 1;

  # taken OFF @ARGV, because the read loop below uses the diamond operator and would otherwise treat
  # the iteration count as a file to read candidates from

  passthrough ('', shift @ARGV);
}
elsif ($TYPE eq 'potthrough')
{
  usage_exit () if scalar @ARGV > 1;

  passthrough ('potthrough', shift @ARGV);
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

sub edge_format
{
  my $word_len = shift;
  my $salt_len = shift;
  my $attack_type = shift;
  my $optimized = shift;

  my $hash = "";
  my $word = "";
  my $salt = "";

  my $cond = 0;

  do
  {
    $word = random_non_ascii_string ($word_len) // "";
    $salt = random_numeric_string ($salt_len) // "";

    if (exists &{module_get_random_password}) # if hash mode requires special format of passwords
    {
      $word = module_get_random_password ($word);
    }

    $hash = module_generate_hash ($word, $salt);

    $cond = 1;

    if ($MODE == 30901 && length ($hash) != 34)
    {
      $cond = 0;
    }

  } while ($cond != 1);

  if (defined $hash)
  {
    my $format = "%d,%d,%d,%d,%d,'%s','%s','%s'\n";

    printf ($format, $MODE, $attack_type, $optimized, $word_len, $salt_len, $word, $salt, $hash);
  }
}

sub edge
{
  my $attack_type = shift // 0;
  my $optimized = shift // 0;

  my @attack_types = (0, 1, 3, 4, 6, 7, 8, 9, 12);

  if (not grep $_ == $attack_type, @attack_types)
  {
    return -1;
  }

  if ($optimized != 0 && $optimized != 1)
  {
    return -1;
  }

  my $idx_max = 0;
  my $idx = 0;

  my $word_min = ($optimized == 1) ? $constraints->[2]->[0] : $constraints->[0]->[0];
  my $word_max = ($optimized == 1) ? $constraints->[2]->[1] : $constraints->[0]->[1];

  my $salt_min = ($optimized == 1) ? $constraints->[3]->[0] : $constraints->[1]->[0];
  my $salt_max = ($optimized == 1) ? $constraints->[3]->[1] : $constraints->[1]->[1];

  my $comb_min = ($optimized == 1) ? $constraints->[4]->[0] : -1;
  my $comb_max = ($optimized == 1) ? $constraints->[4]->[1] : -1;

  if ($attack_type != 3)
  {
    if ($optimized == 1)
    {
      if ($word_min != $word_max && $word_max > 31)
      {
        $word_max = 31;
      }
    }
  }

  # An attack that cuts the word in two needs a word with two halves. Attack types 0, 4, 8 and 9 hand
  # the whole word to hashcat in one piece, so a one character word is a valid test for them.

  my @whole_word_attack_types = (0, 4, 8, 9);

  if (not grep $_ == $attack_type, @whole_word_attack_types)
  {
    if ($word_min < 2)
    {
      $word_min = 2;
    }
  }

  my $word_len = 0;
  my $salt_len = 0;

  # word_min, salt_min
  # word_min, salt_max
  # word_max, salt_min
  # word_max, salt_max

  if ($word_min != -1)
  {
    if ($salt_min != $salt_max)
    {
      if ($salt_min != -1) # word_min, salt_min
      {
        $word_len = $word_min;
        $salt_len = $salt_min;

        edge_format ($word_len, $salt_len, $attack_type, $optimized);
      }

      if ($salt_max != -1) # word_min, salt_max
      {
        my $salt_max_tmp = $salt_max;

        if ($optimized == 1)
        {
          if ($salt_max_tmp > 51)
          {
            $salt_max_tmp = 51;
          }

          if ($comb_max != -1)
          {
            if (($word_len + $salt_max_tmp) > $comb_max)
            {
              my $off = $word_len + $salt_max_tmp - $comb_max;

              if ($salt_max_tmp > $off)
              {
                $salt_max_tmp -= $off;
              }
            }
          }
        }

        $word_len = $word_min;
        $salt_len = $salt_max_tmp;

        edge_format ($word_len, $salt_len, $attack_type, $optimized);
      }
    }
    else
    {
      if ($salt_min != -1) # word_min, salt_min/salt_max (are the same)
      {
        $word_len = $word_min;
        $salt_len = $salt_min;

        edge_format ($word_len, $salt_len, $attack_type, $optimized);
      }
      else
      {
        # no salt

        $word_len = $word_min;
        $salt_len = 0;

        edge_format ($word_len, $salt_len, $attack_type, $optimized);
      }
    }
  }

  if ($word_max != -1)
  {
    if ($salt_min != $salt_max)
    {
      my $last_word_len = -1;
      my $last_salt_len = -1;

      if ($salt_min != -1) # word_max, salt_min
      {
        $word_len = $word_max;
        $salt_len = $salt_min;

        if ($optimized == 1)
        {
          my $comb_max_cur = 55;

          if ($comb_max != -1)
          {
            $comb_max_cur = $comb_max;
          }

          if (($word_len + $salt_len) > $comb_max_cur)
          {
            my $off = $word_len + $salt_len - $comb_max_cur;

            if ($word_len > $off)
            {
              $word_len -= $off;
            }
            else
            {
              print ("ERROR with MODE $MODE, WORD $word_len, SALT $salt_len, MAX $comb_max_cur");
              exit  (1);
            }
          }
        }

        edge_format ($word_len, $salt_len, $attack_type, $optimized);

        # save last
        $last_word_len = $word_len;
        $last_salt_len = $salt_len;
      }

      if ($salt_max != -1) # word_max, salt_max
      {
        $word_len = $word_max;
        $salt_len = $salt_max;

        if ($optimized == 1)
        {
          # limit comb_max to 55 if is not set
          my $comb_max_cur = 55;

          if ($comb_max != -1)
          {
            $comb_max_cur = $comb_max;
          }

          # limit salt_max to 51
          my $salt_max_tmp = $salt_len;

          if ($salt_max_tmp > 51)
          {
            $salt_max_tmp = 51;
          }

          if (($word_len + $salt_max_tmp) > $comb_max_cur)
          {
            my $off = $word_len + $salt_max_tmp - $comb_max_cur;

            if ($last_word_len == $word_len)
            {
              $word_len -= $off;
              if ($word_len < $word_min)
              {
                $off = $word_min - $word_len;
                $word_len = $word_min;
                $salt_max_tmp -= $off;
              }
            }
            else
            {
              $salt_max_tmp -= $off;
              if ($salt_max_tmp < $salt_min)
              {
                $off = $salt_min - $salt_max_tmp;
                $salt_max_tmp = $salt_min;
                $word_len -= $off;
              }
            }
          }

          $salt_len = $salt_max_tmp;
        }

        edge_format ($word_len, $salt_len, $attack_type, $optimized);

        # reset last
        $last_word_len = -1;
        $last_salt_len = -1;
      }
    }
    else
    {
      if ($salt_min != -1) # word_max, salt_min/salt_max (are the same)
      {
        $word_len = $word_max;
        $salt_len = $salt_max;

        if ($optimized == 1)
        {
          if ($comb_max != -1)
          {
            if (($word_len + $salt_len) > $comb_max)
            {
              my $off = $word_len + $salt_len - $comb_max;

              if ($word_len > $off)
              {
                $word_len -= $off;

                if ($word_len < $word_min)
                {
                  $word_len = $word_min;
                }
              }
            }
          }
        }

        edge_format ($word_len, $salt_len, $attack_type, $optimized);
      }
      else
      {
        $word_len = $word_max;
        $salt_len = 0;

        edge_format ($word_len, $salt_len, $attack_type, $optimized);
      }
    }
  }
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

    my $word = random_non_ascii_string ($word_len) // "";
    my $salt = random_numeric_string ($salt_len) // "";

    if (exists &{module_get_random_password}) # if hash mode requires special format of passwords
    {
      $word = module_get_random_password ($word);
    }

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
      if ($MODE == 31600 || $MODE == 31500)
      {
        my $utf16le = encode("UTF-16LE", decode("utf-8", $word));

        $word = md4_hex ($utf16le);
      }

      my $hash = module_generate_hash ($word, $salt);

      # possible if the requested length is not supported by algorithm
      next unless defined $hash;

      my $format = "echo %-31s | ./hashcat \${OPTS} -a 0 -m %d '%s'\n";

      printf ($format, $word, $MODE, $hash);
    }
  }
}

sub password
{
  # One password for this mode, on stdout, nothing else. tools/test.sh builds its -g containers
  # with it, so a container gets the same multi byte characters the oracle passwords get, and
  # the same per mode gate decides whether it gets any.

  my $count = shift // 12;

  return unless is_count ($count);

  my $string = random_non_ascii_string ($count) // "";

  print "$string\n";
}

sub passthrough
{
  my $option = shift || '';

  # The iteration count is whatever the module's third generator argument means: a bcrypt cost, a
  # PBKDF2 round count, and so on. Left out, the module picks its own default and the output is
  # exactly what it always was.

  my $iter = shift;

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

      my $hash = defined ($iter) ? module_generate_hash ($word, $salt, $iter) : module_generate_hash ($word, $salt);

      next unless defined $hash;

      if ($option eq 'potthrough')
      {
        print "$hash:$word\n";
      }
      else
      {
        print "$hash\n";
      }
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

  # Parentheses are required. is_count is imported at RUNTIME inside the eval at the top of this file,
  # so at COMPILE time it is not a known sub, and Perl parses the bareword form as an indirect method
  # call on the argument instead: random_count (20) dies with "Can't locate object method is_count via
  # package 20". Every other call site here already has them.

  return unless is_count ($max);

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

  return if ! is_whole ($count);

  my $string = "";

  $string .= sprintf ("%x", rand 16) for (1 .. $count);

  return $string;
}

sub random_lowercase_string
{
  my $count = shift;

  return if ! is_whole ($count);

  my @chars = ('a'..'z');

  my $string = "";

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_uppercase_string
{
  my $count = shift;

  return if ! is_whole ($count);

  my @chars = ('A'..'Z');

  my $string = "";

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_mixedcase_string
{
  my $count = shift;

  return if ! is_whole ($count);

  my @chars = ('A'..'Z', 'a'..'z');

  my $string = "";

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_numeric_string
{
  my $count = shift;

  return if ! is_whole ($count);

  my @chars = ('0'..'9');

  my $string = "";

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub random_non_ascii_string
{
  # A password for a mode that can take one that is not 7 bit ASCII: digits with a euro sign,
  # kana or a CJK character substituted into them, which is what proves the kernel decodes
  # UTF-8 rather than widening the bytes. Comes back as plain digits for a mode that cannot
  # take one, and for a password too short to hold one, so a caller gets a valid password
  # either way and never has to ask which.
  #
  # Salts, site keys and challenge characters keep calling random_numeric_string(). A salt is
  # a different thing: its length is often counted in characters by the module, it can end up
  # hex encoded or compared against a username, and none of that has anything to do with the
  # kernel's UTF-8 handling.

  my $count = shift;

  my $string = random_numeric_string ($count);

  return if ! defined $string;

  return sprinkle_non_ascii ($string);
}

sub sprinkle_non_ascii
{
  # Replace some of the digits with multi byte UTF-8 characters, in place, so the byte length
  # of the password does not change and it still fits whatever Pwd.Len.Max the mode declares.
  # A character is only ever written at a position where a whole one fits, and the scan then
  # steps over it, so the result is always valid UTF-8.

  my $string = shift;

  return $string if $NON_ASCII_OK == 0;

  my $len = length $string;

  # Seeded from the length, so every password of a given length comes out with its characters
  # in the same places. A plain rand() here would give each of the eight multi hash passwords
  # of a length a different shape, and no single mask could spell all eight.

  my $seed = ($len * 2654435761) % 4294967291;

  my $rand = sub
  {
    $seed = ($seed * 1103515245 + 12345) % 2147483648;

    return $seed / 2147483648;
  };

  my $pos = $NON_ASCII_SKIP_BYTES;

  while ($pos < $len)
  {
    my $char = $NON_ASCII_CHARS[int ($rand->() * scalar @NON_ASCII_CHARS)];

    my $char_len = length $char;

    if ((($pos + $char_len) <= ($len - $NON_ASCII_MIN_SPARE + ($pos > 0 ? 1 : 0))) && ($rand->() < $NON_ASCII_RATE))
    {
      substr ($string, $pos, $char_len) = $char;

      $pos += $char_len;
    }
    else
    {
      $pos += 1;
    }
  }

  return $string;
}

sub non_ascii_supported
{
  # Decide whether this mode can be handed a password that is not 7 bit ASCII. hashcat has no
  # single flag for it, so the module source is read for the option bits that pin the
  # plaintext to a charset, the same way tools/test.sh reads OPTS_TYPE_SUGGEST_KG and friends
  # straight out of src/modules.

  my $mode = shift;

  return 0 if exists $ENV{"NO_NON_ASCII"};

  # a module that builds the password out of the generated string, a bitcoin seed or a
  # NetNTLM response for instance, needs that string in the format it expects

  return 0 if exists &{module_get_random_password};

  my $module_file = sprintf ("%s/../src/modules/module_%05d.c", $FindBin::Bin, $mode);

  open (my $fh, "<", $module_file) or return 0;

  my $src = do { local $/; <$fh> };

  close ($fh);

  # OPTS_TYPE_PT_ALWAYS_ASCII says the plaintext is ASCII by definition, PT_LM and PT_UPPER
  # case fold it, which the kernels only do for ASCII, and PT_HEX, PT_BASE58 and
  # PT_ALWAYS_HEXIFY spell the password in an alphabet of their own.

  for my $opt (qw (OPTS_TYPE_PT_ALWAYS_ASCII
                   OPTS_TYPE_PT_ALWAYS_HEXIFY
                   OPTS_TYPE_PT_BASE58
                   OPTS_TYPE_PT_HEX
                   OPTS_TYPE_PT_LM
                   OPTS_TYPE_PT_LOWER
                   OPTS_TYPE_PT_UPPER))
  {
    return 0 if $src =~ /\Q$opt\E/;
  }

  # A kernel that needs UTF-16 either decodes the UTF-8 with hc_enc or widens the bytes, and a
  # password above 0x7f only survives the first kind. module_01000.c says as much in its own
  # advice notice. Inject only where the kernel that is going to run is the decoding one.

  my $decoding = utf16_decoding_helpers ();

  my $any_utf16    = 0;
  my $pure_decodes = 0;

  for my $kernel (glob (sprintf ("%s/../OpenCL/m%05d*.cl", $FindBin::Bin, $mode)))
  {
    open (my $kh, "<", $kernel) or next;

    my $ksrc = do { local $/; <$kh> };

    close ($kh);

    my $decodes = ($ksrc =~ /\bhc_enc_next\s*\(/) ? 1 : 0;
    my $widens  = ($ksrc =~ /\bmake_utf16/)       ? 1 : 0;

    $any_utf16 = 1 if $widens;

    while ($ksrc =~ /\b(\w+_utf16\w*)\s*\(/g)
    {
      $any_utf16 = 1;

      if ($decoding->{$1}) { $decodes = 1; } else { $widens = 1; }
    }

    $pure_decodes ||= $decodes if $kernel =~ /-pure\.cl$/;
  }

  if ($any_utf16)
  {
    # nothing in this mode ever decodes, UTF-16BE for instance has no hc_enc path at all

    return 0 if $pure_decodes == 0;

    # -O changes the plaintext path even for a mode that has no optimized kernel of its own.
    # m11600 is one: the same generated vector cracks under -P and comes back not found under
    # -O, which is the default the suite runs with. So a mode that converts UTF-16 at all keeps
    # its passwords ASCII whenever -O is in play, rather than only when an optimized kernel of
    # its own would have widened them.

    return 0 if $IS_OPTIMIZED == 1;
  }

  return 1;
}

sub utf16_decoding_helpers
{
  # Split the inc_hash_* conversion helpers into the ones that decode UTF-8 through hc_enc and
  # the ones that only widen the bytes. The scalar UTF-16LE variants decode; the vector ones,
  # the HMAC ones and every UTF-16BE variant do not.

  my %decoding;

  for my $inc (glob (sprintf ("%s/../OpenCL/inc_hash_*.cl", $FindBin::Bin)))
  {
    open (my $ih, "<", $inc) or next;

    my $isrc = do { local $/; <$ih> };

    close ($ih);

    for my $chunk (split (/\nDECLSPEC /, $isrc))
    {
      next unless $chunk =~ /^\w[\w ]*?\s(\w+)\s*\(/;

      my $fn = $1;

      next unless $fn =~ /utf16/;

      $decoding{$fn} = 1 if $chunk =~ /hc_enc_next/;
    }
  }

  return \%decoding;
}

sub random_string
{
  my $count = shift;

  return if ! is_whole ($count);

  my @chars = ('A'..'Z', 'a'..'z', '0'..'9');

  my $string = "";

  $string .= $chars[rand @chars] for (1 .. $count);

  return $string;
}

sub usage_exit
{
  my $f = basename ($0);

  print "\n"
    . "Usage:\n"
    . " $f edge        <mode> [attack-type] [optimized]\n"
    . " $f single      <mode> [length]\n"
    . " $f passthrough <mode> [iter]\n"
    . " $f potthrough  <mode> [iter]\n"
    . " $f verify      <mode> <hashfile> <cracksfile> <outfile>\n"
    . "\n"
    . "Edge:\n"
    . " Generates edge case for selected <mode>.\n"
    . " Will be generated a list of value separated by comma to stdout:\n"
    . " <mode>,<attack-type>,<optimized>,<word_len>,<salt_len>,<word>,<salt>,<hash>\n"
    . " The output can be processed by the test_edge.sh script.\n"
    . "\n"
    . "Single:\n"
    . " Generates up to 32 hashes of random numbers of incrementing length, or up to 32\n"
    . " hashes of random numbers of exact [length]. Writes shell commands to stdout that\n"
    . " can be processed by the test.sh script.\n"
    . "\n"
    . "Passthrough:\n"
    . " Generates hashes for strings entered via stdin and prints them to stdout.\n"
    . " Each call generates a hash with a new random salt. [iter] sets the mode's work\n"
    . " factor where it has one, such as a bcrypt cost, and defaults to the module's own.\n"
    . "\n"
    . "Potthrough:\n"
    . " Like passthrough, but includes both the hash and the plain in hash:plain format,\n"
    . " similar to the classic potfile format. Each call generates a hash wit a new \n"
    . " random salt.\n"
    . "\n"
    . "Verify:\n"
    . " Reads a list of hashes from <hashfile> and a list of hash:password pairs from\n"
    . " <cracksfile>. Hashes every password and compares the hash to the corresponding\n"
    . " entry in the <cracksfile>. If the hashes match and the hash is present in the\n"
    . " list from <hashfile>, it will be written to the <outfile>. The salt of the hash\n"
    . " is ignored in the comparison.\n"
    . "\n";

  exit 1;
}

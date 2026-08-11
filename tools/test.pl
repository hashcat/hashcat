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

my $TYPES = [ 'edge', 'single', 'passthrough', 'potthrough', 'verify' ];

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

if ($TYPE eq 'edge')
{
  usage_exit () if scalar @ARGV > 2;

  edge (@ARGV);
}
elsif ($TYPE eq 'single')
{
  single (@ARGV);
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
    $word = random_numeric_string ($word_len) // "";
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

  my @attack_types = (0, 1, 3, 6, 7, 12);

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

  if ($attack_type != 0)
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

    my $word = random_numeric_string ($word_len) // "";
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

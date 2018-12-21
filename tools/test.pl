#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Data::Types qw (is_count is_whole);
use File::Basename;
use FindBin;

# allows require by filename
use lib "$FindBin::Bin/test_modules";

my $TYPES = [ 'single', 'passthrough', 'verify' ];

my $TYPE = shift @ARGV;
my $MODE = shift @ARGV;

is_in_array ($TYPE, $TYPES) or usage_exit ();

is_whole ($MODE) or die "Mode must be a number\n";

my $module = sprintf ("m%05d.pm", $MODE);

eval { require $module; } or die "Could not load test module: $module\n$@";

exists &{module_generate_hash} or die "Module function 'module_generate_hash' not found\n";
exists &{module_verify_hash}   or die "Module function 'module_verify_hash' not found\n";

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

  undef $len unless is_count ($len);

  my $format = "echo -n %-32s | ./hashcat \${OPTS} -a 0 -m %d '%s'\n";

  for (my $i = 1; $i <= 32; $i++)
  {
    my $cur_len = $len // $i;

    my $word = random_numeric_string ($cur_len);

    my $hash = module_generate_hash ($word);

    next unless defined $hash;

    print sprintf ($format, $word, $MODE, $hash);
  }
}

sub passthrough
{
  while (my $word = <>)
  {
    chomp $word;

    my $hash = module_generate_hash ($word);

    next unless defined $hash;

    print "$hash\n";
  }
}

sub verify
{
  my $hashes_file = shift;
  my $cracks_file = shift;
  my $out_file    = shift;

  open (IN, '<', $hashes_file) or die "$hashes_file: $!\n";

  my $hashlist;

  while (my $line = <IN>)
  {
    $line =~ s/\n$//;
    $line =~ s/\r$//;

    push (@{$hashlist}, $line);
  }

  close (IN);

  open (IN,  '<', $cracks_file) or die "$cracks_file: $!\n";
  open (OUT, '>', $out_file   ) or die "$out_file: $!\n";

  while (my $line = <IN>)
  {
    $line =~ s/\n$//;
    $line =~ s/\r$//;

    my $hash = module_verify_hash ($line);

    next unless defined $hash;

    next unless is_in_array ($hash, $hashlist);

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

sub random_bytes
{
  my $count = shift;

  return pack ("H*", random_hex_string (2 * $count));
}

sub random_hex_string
{
  my $count = shift;

  return if ! is_count ($count);

  my $string;

  $string .= sprintf ("%x", rand 16) for (1 .. $count);

  return $string;
}

sub random_numeric_string
{
  my $count = shift;

  return if ! is_count ($count);

  my $string;

  $string .= sprintf ("%d", rand 10) for (1 .. $count);

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

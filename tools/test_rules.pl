#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;
use Digest::MD5    qw (md5_hex);
use File::Basename qw (dirname);
use YAML::XS       qw (LoadFile);
use Test::More;

# Use `eq_or_diff` from Test::Differences if it's available for an easier to read comparison
# between expected and actual output.
# Fall back to `is` from Test::More if it isn't available.

BEGIN
{
  if (!eval q{ use Test::Differences; 1 })
  {
    *eq_or_diff = \&is;
  }
}


my $hashcat     = "./hashcat";
my $OPTS        = "--stdout --force";
my $CURRENT_DIR = dirname (__FILE__);
my $OUT_DIR     = $CURRENT_DIR . "/". "rules-test";

mkdir $OUT_DIR || die $! unless -d $OUT_DIR;

# Make sure to cleanup on forced exit
$SIG{INT} = \&cleanup_and_exit;

my %cases = load_cases ();

if (scalar @ARGV > 2 || defined $ARGV[0] && $ARGV[0] eq '--help')
{
  usage_die ();
}
elsif (scalar @ARGV == 1)
{
  my $rule = $ARGV[0];

  die ("No test case was found for rule: $rule") unless exists $cases{$rule};

  run_case_all_mods ($rule);
}
elsif (scalar @ARGV == 2)
{
  my $rule = $ARGV[0];
  my $mode = $ARGV[1];

  die ("No test case was found for rule: $rule") unless exists $cases{$rule};

  if ($mode == 1)
  {
    run_case_mode1 ($rule);
  }
  elsif ($mode == 2)
  {
    run_case_mode2 ($rule);
  }
  else
  {
    die ("Invalid mode: $mode. Mode can be either 1 or 2.");
  }
}
else
{
  run_case_all_mods ($_) for (sort keys %cases);
}

cleanup ();

done_testing ();


# Mode 1: host mode, using -j

sub run_case_mode1
{
  my $rule = shift;

  my $case = $cases{$rule};

  die ("Expected output for mode 1 (expected_cpu) isn't defined for rule: $rule") unless defined $case->{expected_cpu};

  my $input_file = input_to_file ($case, $rule);

  my $quoted_rule   = quotemeta ($rule);
  my $actual_output = qx($hashcat $OPTS -j $quoted_rule $input_file);

  eq_or_diff ($actual_output, $case->{expected_cpu}, $rule . " - mode 1");
}

# Mode 2: GPU mode, using -r

sub run_case_mode2
{
  my $rule = shift;

  my $case = $cases{$rule};

  die ("Expected output for mode 2 (expected_opencl) isn't defined for rule: $rule") unless defined $case->{expected_opencl};

  my $input_file = input_to_file ($case, $rule);
  my $rule_file  = rule_to_file ($rule);

  my $quoted_rule   = quotemeta ($rule);
  my $actual_output = qx($hashcat $OPTS -r $rule_file $input_file);

  eq_or_diff ($actual_output, $case->{expected_opencl}, $rule . " - mode 2");
}

sub run_case_all_mods
{
  my $rule = shift;

  my $case = $cases{$rule};

  run_case_mode1 ($rule) if defined $case->{expected_cpu};
  run_case_mode2 ($rule) if defined $case->{expected_opencl};
}

sub input_to_file
{
  my $case = shift;
  my $rule = shift;

  my $file_name = $OUT_DIR . "/" . rule_file_name ($rule);
  open my $fh, ">", $file_name || die $!;
  print $fh $case->{input};
  close $fh;

  return $file_name;
}

sub rule_to_file
{
  my $rule = shift;

  my $file_name = $OUT_DIR . "/" . rule_file_name ($rule, "rule");
  open my $fh, ">", $file_name || die $!;
  print $fh $rule;
  close $fh;

  return $file_name;
}

sub rule_file_name
{
  my $rule = shift;
  my $ext  = shift || "in";

  return sprintf ("rule-%s.%s", md5_hex ($rule), $ext);
}

sub usage_die
{
  die ("usage: $0 [rule] [mode] \n" .
       "       [mode]: 1 for host/cpu mode, 2 for GPU/opencl mode \n" .
       "       run all test cases if [rule] was not specified \n" .
       "       run test for both modes if [mode] was not specified \n" .
       "       --help will show this help message \n" .
       "\n" .
       "examples: \n" .
       "run all available cases      : perl $0 \n" .
       "run i3! case on modes 1 & 2  : perl $0 i3! \n" .
       "run O04 case on mode 1       : perl $0 O04 1 \n" .
       "run sab case on mode 2       : perl $0 sab 2 \n");
}

sub load_cases
{
  my $file_path = $CURRENT_DIR . "/" . "rules-test-cases.yaml";
  return %{ LoadFile ($file_path) };
}

sub cleanup
{
  unlink <$OUT_DIR/*.in $OUT_DIR/*.rule>;
  rmdir $OUT_DIR;
}

sub cleanup_and_exit
{
  cleanup ();
  done_testing ();
  exit 0;
}

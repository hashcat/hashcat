#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use File::Path qw(make_path);

my $startTime        = time();
my $workdir          = "test_benchmarkDeep_$startTime";

my $nvidia_cache     = "~/.nv";
my $amd_cache        = "~/.AMD";
my $hashcat_path     = ".";
my $kernels_cache    = "$hashcat_path/kernels";
my $hashcat_bin      = "$hashcat_path/hashcat";
my $device           = 1;
my $workload_profile = 3;
my $runtime          = 11;
my $sleep_sec        = 13;
my $default_mask     = "?a?a?a?a?a?a?a";
my $result           = "$workdir/result.txt";
my $old_hashcat      = 0; # requires to have ran with new hashcat before to create the hashfiles
my $repeats          = 0;
my $cpu_benchmark    = 0;

unless (-d $workdir)
{
  make_path($workdir) or die "Unable to create '$workdir': $!";
}

print "\n[$workdir] > Hardware preparations... You may need to adjust some settings and probably can ignore some of the error\n\n";

if ($^O eq 'linux')
{
  system ("echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor");

  if ($cpu_benchmark == 1)
  {
    system ("sudo echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo"); ## for CPU benchmark Intel
    system ("sudo echo 0 > /sys/devices/system/cpu/cpufreq/boost");         ## for CPU benchmark AMD
  }
  else
  {
    #system ("rocm-smi --resetprofile --resetclocks --resetfans");
    #system ("rocm-smi --setfan 100% --setperflevel high");

    system ("nvidia-settings -a GPUPowerMizerMode=1 -a GPUFanControlState=1 -a GPUTargetFanSpeed=100");
  }

  system ("rm -rf $nvidia_cache");
  system ("rm -rf $amd_cache");
}
elsif ($^O eq 'darwin')
{
  open(my $stderr_orig, '>&', STDERR) or die "Can't dup STDERR: $!";

  open(STDERR, '>', '/dev/null') or die "Can't redirect STDERR: $!";

  chomp(my $temp_dir  = `getconf DARWIN_USER_TEMP_DIR`);
  chomp(my $cache_dir = `getconf DARWIN_USER_CACHE_DIR`);

  # cleanup OpenCL cache
  system("find \"$temp_dir\" -mindepth 1 -exec rm -rf {} +");
  # cleanup OpenCL/Metal cache
  system("rm -rf \"$cache_dir/com.apple.metalfe/*\"");
  # cleanup Metal cache
  system("rm -rf \"$cache_dir/com.apple.metal/*\"");

  open(STDERR, '>&', $stderr_orig) or die "Can't restore STDERR: $!";
}

system ("rm -rf $kernels_cache");

print "\n\n[$workdir] > Starting...\n\n";

my @hash_types_selection =
(
  900,
  0,
  100,
  1400,
  1700,
  17400,
  17600,
  31000,
  600,
  11700,
  11800,
  5100,
  31100,
  11500,
  18700,
  34000,
  8900,
  400,
  1000,
  3000,
  22000,
  13100,
  5500,
  5600,
  15300,
  15900,
  33700,
  28100,
  9200,
  9300,
  5700,
  1100,
  2100,
  7100,
  3200,
  500,
  1500,
  7400,
  1800,
  35100,
  14000,
  14100,
  26401,
  26403,
  12300,
  300,
  8300,
  1600,
  16700,
  18300,
  22100,
  29511,
  34100,
  29421,
  29341,
  12200,
  10400,
  10510,
  10500,
  10600,
  10700,
  9400,
  9500,
  9600,
  9700,
  9800,
  13400,
  6800,
  23400,
  26100,
  23100,
  11600,
  12500,
  23800,
  13000,
  17220,
  17200,
  20500,
  13600,
  18100,
  17010,
  17030,
  22921,
  22961,
  25500,
  16300,
  15600,
  15700,
  22500,
  27700,
  22700,
  2611,
  2711,
  31900,
  26610,
  11300,
  16600,
  21700,
  21800,
  10,
  20,
  110,
  120,
  1410,
  1420,
  10810,
  10820,
  1710,
  1720,
);

my @hash_types =
(
  900,
  0,
  100,
  1400,
  1700,
  17400,
  17600,
  6000,
  33600,
  600,
  31000,
  11700,
  11800,
  6900,
  5100,
  17800,
  18000,
  31100,
  6100,
  610,
  620,
  10,
  20,
  110,
  120,
  1410,
  1420,
  1710,
  1720,
  10100,
  11500,
  27900,
  28000,
  18700,
  25700,
  27800,
  34200,
  34201,
  34211,
  33502,
  33500,
  33501,
  14100,
  14000,
  26401,
  26403,
  15400,
  14500,
  14900,
  32900,
  11900,
  12000,
  10900,
  12100,
  34000,
  8900,
  400,
  16100,
  30420,
  11400,
  5300,
  5400,
  25000,
  25200,
  26800,
  27300,
  22000,
  22001,
  7350,
  7300,
  10200,
  31300,
  16500,
  19600,
  19800,
  28800,
  32100,
  19700,
  19900,
  28900,
  32200,
  7500,
  13100,
  18200,
  5500,
  5600,
  29100,
  4800,
  8500,
  14200,
  6300,
  6700,
  6400,
  6500,
  3000,
  19000,
  19100,
  19200,
  19210,
  15300,
  15310,
  15900,
  15910,
  7200,
  12800,
  12400,
  1000,
  9900,
  5800,
  33700,
  28100,
  13800,
  2410,
  9200,
  9300,
  5700,
  2400,
  33900,
  8100,
  22200,
  1100,
  2100,
  7000,
  26300,
  125,
  501,
  22,
  15100,
  26500,
  122,
  1722,
  7100,
  3200,
  500,
  1500,
  7400,
  1800,
  35100,
  131,
  132,
  1731,
  24100,
  24200,
  12,
  11100,
  28600,
  3100,
  112,
  12300,
  7401,
  11200,
  200,
  300,
  8000,
  8300,
  25900,
  16400,
  1411,
  1711,
  29200,
  24900,
  10901,
  15000,
  12600,
  1600,
  141,
  1441,
  1421,
  101,
  111,
  7700,
  7701,
  7800,
  7801,
  10300,
  35000,
  20712,
  32031,
  32041,
  133,
  13500,
  32000,
  32050,
  32060,
  32070,
  32020,
  32030,
  32040,
  32010,
  21500,
  21501,
  24,
  8600,
  8700,
  9100,
  26200,
  20600,
  4711,
  20711,
  22400,
  27400,
  29511,
  34100,
  29421,
  23900,
  24000,
  16700,
  27500,
  27600,
  20011,
  22100,
  12900,
  8800,
  18300,
  29341,
  12200,
  10400,
  10410,
  10420,
  10510,
  10500,
  25400,
  10600,
  10700,
  9400,
  9500,
  9600,
  25300,
  9700,
  9710,
  9720,
  9810,
  9820,
  9800,
  18400,
  18600,
  16200,
  23300,
  6600,
  8200,
  31800,
  9000,
  5200,
  6800,
  13400,
  23400,
  16900,
  26000,
  26100,
  23100,
  11600,
  12500,
  23800,
  23700,
  13000,
  17220,
  17200,
  20500,
  20510,
  23001,
  23002,
  23003,
  31200,
  13600,
  18900,
  32700,
  24700,
  13200,
  13300,
  23500,
  23600,
  14700,
  14800,
  33400,
  8400,
  33800,
  2612,
  121,
  3711,
  4521,
  22800,
  24800,
  32300,
  11,
  13900,
  11000,
  16000,
  7900,
  32600,
  4522,
  2811,
  2611,
  2711,
  21,
  18100,
  21600,
  16501,
  10000,
  124,
  12150,
  12001,
  19500,
  27200,
  30000,
  30120,
  20200,
  20300,
  20400,
  24410,
  24420,
  15500,
  17010,
  17020,
  17030,
  17040,
  22911,
  22921,
  22931,
  22941,
  22951,
  22961,
  23200,
  28300,
  22600,
  24500,
  22301,
  23,
  30700,
  29600,
  31900,
  26600,
  26610,
  29800,
  21000,
  11300,
  16600,
  21700,
  21800,
  12700,
  15200,
  18800,
  32500,
  25500,
  16300,
  15600,
  15700,
  22500,
  27700,
  22700,
  28200,
  29910,
  29920,
  29930,
  29940,
  24600,
  31400,
  28700,
);

if (scalar @ARGV)
{
  @hash_types = @ARGV;
}

unlink ($result);

chdir ($hashcat_path);

for my $hash_type (@hash_types)
{
  # benchmark always in optimized mode with single hash and mask!

  my $mask = $default_mask;

  my $filepath = "$workdir/tmp.hash.$hash_type";

  if ($old_hashcat == 0)
  {
    my $module = get_module ($hash_type);

    my $st_hash   = $module->{"st_hash"};
    my $is_binary = $module->{"is_binary"};

    open (OUT, ">", $filepath) or die;

    if ($is_binary)
    {
      print OUT pack ("H*", $st_hash), "\n";
    }
    else
    {
      print OUT "$st_hash\n";
    }

    close (OUT);

    $mask = $module->{"mask"};
  }

  my @command =
  (
    $hashcat_bin, "-D2",
    "--quiet",
    $filepath,
    "--keep-guessing",
    "--self-test-disable",
    "--markov-disable",
    "--restore-disable",
    "--outfile-autohex-disable",
    "--wordlist-autohex-disable",
    "--potfile-disable",
    "--logfile-disable",
    "--status",
    "--status-timer", 1,
    "--runtime", $runtime,
    "--machine-readable",
    "--optimized-kernel-enable",
    "--workload-profile", $workload_profile,
    "--hash-type", $hash_type,
    "--attack-mode", 3,
    $mask
  );

  if ($cpu_benchmark == 1)
  {
    push (@command, "--opencl-device-types", 1);
  }
  else
  {
    push (@command, "--backend-devices", $device);
  }

  print "[$workdir] > Executing command: ", join (" ", @command), "\n";

  my $final_speed = 0;

  for (my $i = 0; $i <= $repeats; $i++)
  {
    printf ("[$workdir] > Run #%d\n", $i);

    open (IN, "-|", @command, "--runtime", 1);
    close (IN);

    my $was_slower = 0;

    my $speed = 0;

    my $sample = 0;

    open (IN, "-|", @command);

    while (my $line = <IN>)
    {
      chomp $line;

      print "$line\n";

      my @data = split "\t", $line;

      next unless defined $data[1];

      next if ($data[1] != '3');

      $sample++;

      if ($sample > 5)
      {
        if ($data[3] > $speed)
        {
          $speed = $data[3];
        }
        else
        {
          $was_slower++;

          last if ($was_slower == 3);
        }
      }
    }

    close (IN);

    sleep ($sleep_sec);

    $final_speed = $speed if ($speed > $final_speed);
  }

  open (OUT, ">>", $result) or die;
  print OUT $final_speed, "\n";
  close (OUT);

  my $endTime = time();
  my $elapsed = $endTime - $startTime;

  my $days    = int($elapsed / 86400);
  my $hours   = int(($elapsed % 86400) / 3600);
  my $minutes = int(($elapsed % 3600) / 60);
  my $seconds = $elapsed % 60;

  printf("\n\n[$workdir] > All tests done in: %d days, %02d hours, %02d minutes, %02d seconds\n", $days, $hours, $minutes, $seconds);
}

sub get_module
{
  my $hash_type = shift;

  my $st_hash         = undef;
  my $is_binary       = 0;
  my $pw_min          = -1;
  my $pw_max          = -1;
  my $benchmark_mask  = undef;

  my $path = sprintf ("src/modules/module_%05d.c", $hash_type);

  open (IN, $path) or die;

  while (my $line = <IN>)
  {
    chomp $line;

    if ($line =~ /OPTS_TYPE_BINARY_HASHFILE/)
    {
      if (($hash_type == 22000) || ($hash_type == 22001))
      {
        ## problem while in -m 2500 backward compatibility mode
      }
      else
      {
        $is_binary = 1;
      }
    }

    if ($line =~ /ST_HASH *= \"(.*)\"/)
    {
      $st_hash = $1;
    }

    if ($line =~ /const u32 pw_min = (\d+);/)
    {
      $pw_min = $1;
    }

    if ($line =~ /const u32 pw_max = (\d+);/)
    {
      $pw_max = $1;
    }

    if ($line =~ /BENCHMARK_MASK *= \"(.*)\"/)
    {
      $benchmark_mask = $1;
    }
  }

  close (IN);

  my $mask = $default_mask;

  if ($pw_min != -1)
  {
    if ($pw_min < 7)
    {
      $mask = substr ($mask, 0, $pw_min * 2);
    }
    else
    {
      my $left = $pw_min - 7;

      $mask .= "x" x $left;
    }
  }
  elsif ($pw_max != -1)
  {
    if ($pw_max < 7)
    {
      $mask = substr ($mask, 0, $pw_min * 2);
    }
  }

  $mask = (defined $benchmark_mask) ? $benchmark_mask : $mask;

  my $module =
  {
    "is_binary" => $is_binary,
    "st_hash"   => $st_hash,
    "mask"      => $mask,
  };

  return $module;
}

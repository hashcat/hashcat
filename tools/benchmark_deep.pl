#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

my $nvidia_cache     = "~/.nv";
my $amd_cache        = "~/.AMD";
my $hashcat_path     = ".";
my $kernels_cache    = "$hashcat_path/kernels";
my $hashcat_bin      = "$hashcat_path/hashcat";
my $device           = 3;
my $workload_profile = 3;
my $runtime          = 24;
my $sleep_sec        = 12;
my $default_mask     = "?b?b?b?b?b?b?b";
my $result           = "result.txt";
my $old_hashcat      = 0; # requires to have ran with new hashcat before to create the hashfiles
my $repeats          = 0;
my $cpu_benchmark    = 0;

print "\nHardware preparations... You may need to adjust some settings and probably can ignore some of the error\n\n";

system ("echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor");

if ($cpu_benchmark == 1)
{
  system ("echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo"); ## for CPU benchmark Intel
  system ("echo 0 > /sys/devices/system/cpu/cpufreq/boost");         ## for CPU benchmark AMD
}
else
{
  system ("rocm-smi --resetprofile --resetclocks --resetfans");
  system ("rocm-smi --setfan 100% --setperflevel high");

  system ("nvidia-smi -rac");
  system ("nvidia-smi -pm ENABLED");
  system ("nvidia-smi -acp UNRESTRICTED");
  system ("nvidia-smi -pl 225"); ## needs per-gpu adjust
  system ("nvidia-settings -a GPUPowerMizerMode=1 -a GPUFanControlState=1 -a GPUTargetFanSpeed=100");
}

print "\n\nStarting...\n\n";

system ("rm -rf $nvidia_cache");
system ("rm -rf $amd_cache");
system ("rm -rf $kernels_cache");

my @hash_types_selection =
(
  0,
  100,
  1400,
  1700,
  22000,
  1000,
  3000,
  5500,
  5600,
  1500,
  500,
  3200,
  1800,
  7500,
  13100,
  15300,
  15900,
  7100,
  11600,
  12500,
  13000,
  6241,
  13400,
  6800,
  11300,
);

my @hash_types =
(
  0,
  20,
  50,
  60,
  100,
  120,
  150,
  160,
  200,
  300,
  400,
  500,
  600,
  900,
  1000,
  1100,
  1300,
  1400,
  1420,
  1450,
  1460,
  1600,
  1600,
  1700,
  1720,
  1750,
  1760,
  1800,
  2100,
  2400,
  2410,
  2611,
  2711,
  2811,
  3000,
  3100,
  3200,
  3710,
  3800,
  3910,
  4010,
  4110,
  4300,
  4400,
  4500,
  4520,
  4700,
  4800,
  4900,
  5100,
  5200,
  5300,
  5400,
  5500,
  5600,
  5800,
  6000,
  6100,
  6211,
  6221,
  6231,
  6241,
  6300,
  6400,
  6500,
  6600,
  6700,
  6800,
  6900,
  7000,
  7100,
  7300,
  7400,
  7500,
  7700,
  7701,
  7800,
  7801,
  7900,
  8000,
  8100,
  8200,
  8300,
  8400,
  8500,
  8600,
  8700,
  8800,
  8900,
  9000,
  9100,
  9400,
  9500,
  9600,
  9700,
  9710,
  9720,
  9800,
  9810,
  9820,
  9900,
  10100,
  10300,
  10400,
  10410,
  10420,
  10500,
  10700,
  10800,
  10900,
  11000,
  11100,
  11200,
  11300,
  11400,
  11500,
  11600,
  11700,
  11750,
  11760,
  11800,
  11850,
  11860,
  11900,
  12000,
  12200,
  12300,
  12400,
  12500,
  12600,
  12700,
  12800,
  12900,
  13000,
  13100,
  13200,
  13300,
  13400,
  13500,
  13600,
  13711,
  13721,
  13731,
  13741,
  13751,
  13761,
  13771,
  13781,
  13800,
  13900,
  14000,
  14100,
  14400,
  14500,
  14700,
  14800,
  14900,
  15000,
  15100,
  15200,
  15300,
  15400,
  15500,
  15600,
  15900,
  16000,
  16100,
  16200,
  16300,
  16400,
  16500,
  16600,
  16700,
  16900,
  17210,
  17300,
  17400,
  17500,
  17600,
  17700,
  17800,
  17900,
  18000,
  18100,
  18200,
  18300,
  18400,
  18500,
  18600,
  18700,
  18800,
  18900,
  19000,
  19100,
  19200,
  19300,
  19500,
  19600,
  19700,
  19800,
  19900,
  20011,
  20012,
  20013,
  20500,
  20510,
  20600,
  20710,
  20800,
  20900,
  21000,
  21100,
  21200,
  21300,
  21400,
  21500,
  21600,
  21700,
  21800,
  22000,
  22100,
  22200,
  22300,
  22400,
  22500,
  22600,
  22700,
  22911,
  22921,
  22931,
  22941,
  22951,
  23001,
  23002,
  23003,
  23100,
  23200,
  23300,
  23400,
  23500,
  23600,
  23700,
  23800,
  23900,
  24100,
  24200,
  24300,
  24410,
  24420,
  24500,
  24600,
  24700,
  24800,
  24900,
  25000,
  25100,
  25200,
  25300,
  25400,
  25500,
  25700,
  25900,
  26000,
  26100,
  26200,
  26300,
  26401,
  26402,
  26403,
  26500,
  26600,
  26700,
  26800,
  26900,
  27000,
  27100,
  27200,
  27300,
  27400,
  27500,
  27600,
  27700,
  27800,
  27900,
  28000,
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

  if ($old_hashcat == 0)
  {
    my $module = get_module ($hash_type);

    my $st_hash   = $module->{"st_hash"};
    my $is_binary = $module->{"is_binary"};

    open (OUT, ">", "tmp.hash.$hash_type") or die;

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
    "tmp.hash.$hash_type",
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

  print "Executing command: ", join (" ", @command), "\n";

  my $final_speed = 0;

  for (my $i = 0; $i <= $repeats; $i++)
  {
    printf ("Run #%d\n", $i);

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

  my $mask = (defined $benchmark_mask) ? $benchmark_mask : $default_mask;

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

  my $module =
  {
    "is_binary" => $is_binary,
    "st_hash"   => $st_hash,
    "mask"      => $mask,
  };

  return $module;
}

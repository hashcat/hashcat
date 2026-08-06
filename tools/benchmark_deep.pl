#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use File::Path qw(make_path);
use Getopt::Long;

my $startTime        = time();
my $workdir          = "test_benchmarkDeep_$startTime";

my $nvidia_cache     = "~/.nv";
my $amd_cache        = "~/.AMD";
my $hashcat_path     = ".";
my $kernels_cache    = "$hashcat_path/kernels";
my $hashcat_bin      = "$hashcat_path/hashcat";
my $workload_profile = 3;
my $runtime          = 11;
my $sleep_sec        = 13;
my $default_mask     = "?a?a?a?a?a?a?a";
my $result           = "$workdir/result.txt";
my $old_hashcat      = 0; # requires to have ran with new hashcat before to create the hashfiles
my $repeats          = 0;
my $attack_mode      = 3;
my $wordlist_path    = "example.dict";
my $backend_devices  = "1";
my $pcfg_mode        = 0;
my $pcfg_model       = undef;

unless (-d $workdir)
{
  make_path($workdir) or die "Unable to create '$workdir': $!";
}

print "[$workdir] > Hardware preparations... You may need to adjust some settings and probably can ignore some of the error\n";

if ($^O eq 'linux')
{
  system ("echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null") if (glob ("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"));

  system ("sudo sh -c 'echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo'") if (-e "/sys/devices/system/cpu/intel_pstate/no_turbo"); ## for CPU benchmark Intel
  system ("sudo sh -c 'echo 0 > /sys/devices/system/cpu/cpufreq/boost'")         if (-e "/sys/devices/system/cpu/cpufreq/boost");         ## for CPU benchmark AMD

  #system ("rocm-smi --resetprofile --resetclocks --resetfans");
  #system ("rocm-smi --setfan 100% --setperflevel high");

  system ("nvidia-settings -a GPUPowerMizerMode=1 -a GPUFanControlState=1 -a GPUTargetFanSpeed=100") if (`which nvidia-settings 2>/dev/null` =~ /\S/);
}

clean_cache();

print "[$workdir] > Starting...\n";

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

#my @hash_types =
#(
#  0, 20, 50, 60, 100, 120, 150, 160, 200, 300, 400, 500, 600, 900, 1000, 1100, 1300, 1400, 1420, 1450, 1460, 1500, 1600, 1700, 1720, 1750, 1760, 1800, 2100, 2400, 2410, 2611, 2711, 2811, 3000, 3100, 3200, 3710, 3800, 3910, 4010, 4110, 4300, 4400, 4500, 4520, 4700, 4800, 4900, 5100, 5200, 5300, 5400, 5500, 5600, 5800, 6000, 6100, 6211, 6221, 6231, 6241, 6300, 6400, 6500, 6600, 6700, 6800, 6900, 7000, 7100, 7300, 7400, 7500, 7700, 7701, 7800, 7801, 7900, 8000, 8100, 8200, 8300, 8400, 8500, 8600, 8700, 8800, 8900, 9000, 9100, 9400, 9500, 9600, 9700, 9710, 9720, 9800, 9810, 9820, 9900, 10100, 10300, 10400, 10410, 10420, 10500, 10700, 10800, 10900, 11000, 11100, 11200, 11300, 11400, 11500, 11600, 11700, 11750, 11760, 11800, 11850, 11860, 11900, 12000, 12200, 12300, 12400, 12500, 12600, 12700, 12800, 12900, 13000, 13100, 13200, 13300, 13400, 13500, 13600, 13711, 13721, 13731, 13741, 13751, 13761, 13771, 13800, 13900, 14000, 14100, 14400, 14700, 14800, 14900, 15000, 15100, 15300, 15400, 15500, 15600, 15900, 16000, 16100, 16200, 16300, 16400, 16600, 16900, 17300, 17400, 17500, 17600, 17700, 17800, 17900, 18000, 18100, 18200, 18300, 18400, 18500, 18600, 18700, 18800, 18900, 19000, 19100, 19200, 19300, 19500, 19600, 19700, 19800, 19900, 20011, 20012, 20013, 20500, 20510, 20600, 20710, 20800, 20900, 21000, 21100, 21200, 21300, 21400, 21500, 21600, 21700, 21800, 22000, 22100, 22200, 22300, 22400, 22500, 22600, 22700, 22911, 22921, 22931, 22941, 22951, 23001, 23002, 23003, 23100, 23200, 23300, 23400, 23500, 23600, 23700, 23800, 23900, 24100, 24200, 24300, 24410, 24420, 24500, 24600, 24700, 24800, 24900, 25300, 25400, 25500, 26000, 26100,
#);

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

GetOptions(
  'attack-mode|a=i'     => \$attack_mode,
  'wordlist|w=s'        => \$wordlist_path,
  'backend-devices|d=s' => \$backend_devices,
  'runtime|r=i'         => \$runtime,
  'pcfg-mode=i'         => \$pcfg_mode,
  'pcfg-model=s'        => \$pcfg_model,
) or die "Usage: $0 [--attack-mode 0|3|10] [--wordlist path] [--backend-devices 1,3] [--runtime secs] [--pcfg-mode 0-7] [--pcfg-model path] [hash_types...]\n";

if ($attack_mode != 0 && $attack_mode != 3 && $attack_mode != 10)
{
  die "Error: only attack-mode 0, 3 and 10 are supported\n";
}

if (scalar @ARGV)
{
  @hash_types = @ARGV;
}

unlink ($result);

chdir ($hashcat_path);

my $effective_wordlist = $wordlist_path;

if ($attack_mode == 0 || $attack_mode == 10)
{
  my %passwords_to_exclude;

  for my $ht (@hash_types)
  {
    my $module = get_module ($ht);

    next if ($module->{"is_binary"} || $module->{"is_binary_pass"});

    my $st_pass = $module->{"st_pass"};

    if (defined $st_pass && $st_pass ne "")
    {
      $passwords_to_exclude{$st_pass} = 1;
    }
  }

  if (scalar keys %passwords_to_exclude > 0)
  {
    my $filtered = "$workdir/wordlist_filtered.txt";

    open (my $wl_in,  "<", $wordlist_path) or die "Cannot open $wordlist_path: $!";
    open (my $wl_out, ">", $filtered)      or die "Cannot open $filtered: $!";

    while (my $word = <$wl_in>)
    {
      chomp $word;
      next if (exists $passwords_to_exclude{$word});
      print $wl_out "$word\n";
    }

    close ($wl_in);
    close ($wl_out);

    $effective_wordlist = $filtered;

    printf("[$workdir] > Filtered wordlist: excluded %d password(s), saved to %s\n",
      scalar keys %passwords_to_exclude, $filtered);
  }
}

if ($attack_mode == 10 && !defined $pcfg_model)
{
  $pcfg_model = "$workdir/benchmark.pcfg";

  printf("[$workdir] > Training PCFG model from %s...\n", $effective_wordlist);

  my $train_cmd = sprintf("%s --quiet --attack-mode 10 --pcfg-train %s --pcfg-model-save %s --pcfg-train-af-disable --pcfg-model-info > /dev/null 2>&1",
    $hashcat_bin, $effective_wordlist, $pcfg_model);

  system ($train_cmd) == 0 or die "Error: PCFG training failed\n";
}

if ($attack_mode == 10 && !-e $pcfg_model)
{
  die "Error: pcfg model file '$pcfg_model' not found\n";
}

for my $hash_type (@hash_types)
{
  # benchmark always in optimized mode with single hash and mask!

  my $mask = $default_mask;

  my $filepath = "$workdir/tmp.hash.$hash_type";

  if ($old_hashcat == 0)
  {
    my $module = get_module ($hash_type);

    if ($attack_mode == 0 || $attack_mode == 10)
    {
      if ($module->{"is_binary"} || $module->{"is_binary_pass"})
      {
        printf("[$workdir] > Skipping hash type %d (binary hash or password)\n", $hash_type);
        open (OUT, ">>", $result) or die;
        print OUT "$hash_type:-1\n";
        close (OUT);
        next;
      }
    }

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

    if ($attack_mode == 3)
    {
      $mask = $module->{"mask"};
    }
  }

  my @command =
  (
    $hashcat_bin, "-D1,2",
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
    "--backend-devices", $backend_devices,
    "--hash-type", $hash_type,
    "--attack-mode", $attack_mode,
  );

  if ($attack_mode == 3)
  {
    push @command, $mask;
  }
  elsif ($attack_mode == 0)
  {
    push @command, $effective_wordlist;
  }
  elsif ($attack_mode == 10)
  {
    push @command, "--pcfg-model", $pcfg_model;
    push @command, "--pcfg-mode", $pcfg_mode;
  }

  print "[$workdir] > Executing command: ", join (" ", @command), "\n";

  my $final_speed = 0;

  for (my $i = 0; $i <= $repeats; $i++)
  {
    printf("[$workdir] > Run #%d\n", $i);

    open (IN, "-|", @command, "--runtime", 1);
    close (IN);

    my $speed = 0;

    open (IN, "-|", @command);

    my $was_slower = 0;

    my $sample = 0;

    while (my $line = <IN>)
    {
      chomp $line;

      print "$line\n";

      my @data = split "\t", $line;

      next unless defined $data[1];

      next if ($data[1] != '3');

      $sample++;

      my $warmup = ($attack_mode == 0) ? 2 : 5;

      if ($sample > $warmup)
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
  print OUT "$hash_type:$final_speed\n";
  close (OUT);
}

my $endTime = time();
my $elapsed = $endTime - $startTime;

my $days    = int($elapsed / 86400);
my $hours   = int(($elapsed % 86400) / 3600);
my $minutes = int(($elapsed % 3600) / 60);
my $seconds = $elapsed % 60;

printf("\n\n[$workdir] > All tests done in: %d days, %02d hours, %02d minutes, %02d seconds\n", $days, $hours, $minutes, $seconds);

sub clean_cache
{
  print "[$workdir] > Cleaning cache...\n";

  if ($^O eq 'linux')
  {
    system ("rm -rf $nvidia_cache");
    system ("rm -rf $amd_cache");
  }
  elsif ($^O eq 'darwin')
  {
    chomp(my $temp_dir  = `getconf DARWIN_USER_TEMP_DIR`);
    chomp(my $cache_dir = `getconf DARWIN_USER_CACHE_DIR`);

    if (-d "$temp_dir/homed")
    {
      system("find \"$temp_dir\" -mindepth 1 -exec rm -rf {} + 2>/dev/null");
    }

    if (-d "$cache_dir/com.apple.metalfe")
    {
      system("rm -rf \"$cache_dir/com.apple.metalfe\"");
    }

    if (-d "$cache_dir/com.apple.metal")
    {
      system("rm -rf \"$cache_dir/com.apple.metal\"");
    }
  }

  if (-d $kernels_cache)
  {
    system ("rm -rf $kernels_cache/*");
  }
}

sub get_module
{
  my $hash_type = shift;

  my $st_hash         = undef;
  my $st_pass         = undef;
  my $is_binary       = 0;
  my $is_binary_pass  = 0;
  my $pw_min          = -1;
  my $pw_max          = -1;
  my $benchmark_mask  = undef;

  my $path = sprintf("src/modules/module_%05d.c", $hash_type);

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

    if ($line =~ /ST_PASS\s*=\s*"(.*)"/)
    {
      $st_pass = $1;

      if ($st_pass =~ /\\x/)
      {
        $is_binary_pass = 1;
      }
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
    "is_binary"      => $is_binary,
    "is_binary_pass" => $is_binary_pass,
    "st_hash"        => $st_hash,
    "st_pass"        => $st_pass,
    "mask"           => $mask,
  };

  return $module;
}

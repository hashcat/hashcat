/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "interface.h"
#include "usage.h"

static const char *const USAGE_MINI[] =
{
  "Usage: hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...",
  "",
  "Try --help for more help.",
  NULL
};

static const char *const USAGE_BIG_PRE_HASHMODES[] =
{
  "Usage: hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...",
  "",
  "- [ Options ] -",
  "",
  " Options Short / Long           | Type | Description                                          | Example",
  "================================+======+======================================================+=======================",
  " -m, --hash-type                | Num  | Hash-type, references below (otherwise autodetect)   | -m 1000",
  " -a, --attack-mode              | Num  | Attack-mode, see references below                    | -a 3",
  " -V, --version                  |      | Print version                                        |",
  " -h, --help                     |      | Print help                                           |",
  "     --quiet                    |      | Suppress output                                      |",
  "     --hex-charset              |      | Assume charset is given in hex                       |",
  "     --hex-salt                 |      | Assume salt is given in hex                          |",
  "     --hex-wordlist             |      | Assume words in wordlist are given in hex            |",
  "     --force                    |      | Ignore warnings                                      |",
  "     --deprecated-check-disable |      | Enable deprecated plugins                            |",
  "     --status                   |      | Enable automatic update of the status screen         |",
  "     --status-json              |      | Enable JSON format for status output                 |",
  "     --status-timer             | Num  | Sets seconds between status screen updates to X      | --status-timer=1",
  "     --stdin-timeout-abort      | Num  | Abort if there is no input from stdin for X seconds  | --stdin-timeout-abort=300",
  "     --machine-readable         |      | Display the status view in a machine-readable format |",
  "     --keep-guessing            |      | Keep guessing the hash after it has been cracked     |",
  "     --self-test-disable        |      | Disable self-test functionality on startup           |",
  "     --loopback                 |      | Add new plains to induct directory                   |",
  "     --markov-hcstat2           | File | Specify hcstat2 file to use                          | --markov-hcstat2=my.hcstat2",
  "     --markov-disable           |      | Disables markov-chains, emulates classic brute-force |",
  "     --markov-classic           |      | Enables classic markov-chains, no per-position       |",
  "     --markov-inverse           |      | Enables inverse markov-chains, no per-position       |",
  " -t, --markov-threshold         | Num  | Threshold X when to stop accepting new markov-chains | -t 50",
  "     --runtime                  | Num  | Abort session after X seconds of runtime             | --runtime=10",
  "     --session                  | Str  | Define specific session name                         | --session=mysession",
  "     --restore                  |      | Restore session from --session                       |",
  "     --restore-disable          |      | Do not write restore file                            |",
  "     --restore-file-path        | File | Specific path to restore file                        | --restore-file-path=x.restore",
  " -o, --outfile                  | File | Define outfile for recovered hash                    | -o outfile.txt",
  "     --outfile-format           | Str  | Outfile format to use, separated with commas         | --outfile-format=1,3",
  "     --outfile-autohex-disable  |      | Disable the use of $HEX[] in output plains           |",
  "     --outfile-check-timer      | Num  | Sets seconds between outfile checks to X             | --outfile-check-timer=30",
  "     --wordlist-autohex-disable |      | Disable the conversion of $HEX[] from the wordlist   |",
  " -p, --separator                | Char | Separator char for hashlists and outfile             | -p :",
  "     --stdout                   |      | Do not crack a hash, instead print candidates only   |",
  "     --show                     |      | Compare hashlist with potfile; show cracked hashes   |",
  "     --left                     |      | Compare hashlist with potfile; show uncracked hashes |",
  "     --username                 |      | Enable ignoring of usernames in hashfile             |",
  "     --remove                   |      | Enable removal of hashes once they are cracked       |",
  "     --remove-timer             | Num  | Update input hash file each X seconds                | --remove-timer=30",
  "     --potfile-disable          |      | Do not write potfile                                 |",
  "     --potfile-path             | File | Specific path to potfile                             | --potfile-path=my.pot",
  "     --encoding-from            | Code | Force internal wordlist encoding from X              | --encoding-from=iso-8859-15",
  "     --encoding-to              | Code | Force internal wordlist encoding to X                | --encoding-to=utf-32le",
  "     --debug-mode               | Num  | Defines the debug mode (hybrid only by using rules)  | --debug-mode=4",
  "     --debug-file               | File | Output file for debugging rules                      | --debug-file=good.log",
  "     --induction-dir            | Dir  | Specify the induction directory to use for loopback  | --induction=inducts",
  "     --outfile-check-dir        | Dir  | Specify the outfile directory to monitor for plains  | --outfile-check-dir=x",
  "     --logfile-disable          |      | Disable the logfile                                  |",
  "     --hccapx-message-pair      | Num  | Load only message pairs from hccapx matching X       | --hccapx-message-pair=2",
  "     --nonce-error-corrections  | Num  | The BF size range to replace AP's nonce last bytes   | --nonce-error-corrections=16",
  "     --keyboard-layout-mapping  | File | Keyboard layout mapping table for special hash-modes | --keyb=german.hckmap",
  "     --truecrypt-keyfiles       | File | Keyfiles to use, separated with commas               | --truecrypt-keyf=x.png",
  "     --veracrypt-keyfiles       | File | Keyfiles to use, separated with commas               | --veracrypt-keyf=x.txt",
  "     --veracrypt-pim-start      | Num  | VeraCrypt personal iterations multiplier start       | --veracrypt-pim-start=450",
  "     --veracrypt-pim-stop       | Num  | VeraCrypt personal iterations multiplier stop        | --veracrypt-pim-stop=500",
  " -b, --benchmark                |      | Run benchmark of selected hash-modes                 |",
  "     --benchmark-all            |      | Run benchmark of all hash-modes (requires -b)        |",
  "     --speed-only               |      | Return expected speed of the attack, then quit       |",
  "     --progress-only            |      | Return ideal progress step size and time to process  |",
  " -c, --segment-size             | Num  | Sets size in MB to cache from the wordfile to X      | -c 32",
  "     --bitmap-min               | Num  | Sets minimum bits allowed for bitmaps to X           | --bitmap-min=24",
  "     --bitmap-max               | Num  | Sets maximum bits allowed for bitmaps to X           | --bitmap-max=24",
  "     --cpu-affinity             | Str  | Locks to CPU devices, separated with commas          | --cpu-affinity=1,2,3",
  "     --hook-threads             | Num  | Sets number of threads for a hook (per compute unit) | --hook-threads=8",
  "     --hash-info                |      | Show information for each hash-mode                  |",
  "     --example-hashes           |      | Alias of --hash-info                                 |",
  "     --backend-ignore-cuda      |      | Do not try to open CUDA interface on startup         |",
  "     --backend-ignore-hip       |      | Do not try to open HIP interface on startup          |",
  "     --backend-ignore-metal     |      | Do not try to open Metal interface on startup        |",
  "     --backend-ignore-opencl    |      | Do not try to open OpenCL interface on startup       |",
  " -I, --backend-info             |      | Show system/evironment/backend API info              | -I or -II",
  " -d, --backend-devices          | Str  | Backend devices to use, separated with commas        | -d 1",
  " -D, --opencl-device-types      | Str  | OpenCL device-types to use, separated with commas    | -D 1",
  " -O, --optimized-kernel-enable  |      | Enable optimized kernels (limits password length)    |",
  " -M, --multiply-accel-disable   |      | Disable multiply kernel-accel with processor count   |",
  " -w, --workload-profile         | Num  | Enable a specific workload profile, see pool below   | -w 3",
  " -n, --kernel-accel             | Num  | Manual workload tuning, set outerloop step size to X | -n 64",
  " -u, --kernel-loops             | Num  | Manual workload tuning, set innerloop step size to X | -u 256",
  " -T, --kernel-threads           | Num  | Manual workload tuning, set thread count to X        | -T 64",
  "     --backend-vector-width     | Num  | Manually override backend vector-width to X          | --backend-vector=4",
  "     --spin-damp                | Num  | Use CPU for device synchronization, in percent       | --spin-damp=10",
  "     --hwmon-disable            |      | Disable temperature and fanspeed reads and triggers  |",
  "     --hwmon-temp-abort         | Num  | Abort if temperature reaches X degrees Celsius       | --hwmon-temp-abort=100",
  "     --scrypt-tmto              | Num  | Manually override TMTO value for scrypt to X         | --scrypt-tmto=3",
  " -s, --skip                     | Num  | Skip X words from the start                          | -s 1000000",
  " -l, --limit                    | Num  | Limit X words from the start + skipped words         | -l 1000000",
  "     --keyspace                 |      | Show keyspace base:mod values and quit               |",
  " -j, --rule-left                | Rule | Single rule applied to each word from left wordlist  | -j 'c'",
  " -k, --rule-right               | Rule | Single rule applied to each word from right wordlist | -k '^-'",
  " -r, --rules-file               | File | Multiple rules applied to each word from wordlists   | -r rules/best64.rule",
  " -g, --generate-rules           | Num  | Generate X random rules                              | -g 10000",
  "     --generate-rules-func-min  | Num  | Force min X functions per rule                       |",
  "     --generate-rules-func-max  | Num  | Force max X functions per rule                       |",
  "     --generate-rules-func-sel  | Str  | Pool of rule operators valid for random rule engine  | --generate-rules-func-sel=ioTlc",
  "     --generate-rules-seed      | Num  | Force RNG seed set to X                              |",
  " -1, --custom-charset1          | CS   | User-defined charset ?1                              | -1 ?l?d?u",
  " -2, --custom-charset2          | CS   | User-defined charset ?2                              | -2 ?l?d?s",
  " -3, --custom-charset3          | CS   | User-defined charset ?3                              |",
  " -4, --custom-charset4          | CS   | User-defined charset ?4                              |",
  "     --identify                 |      | Shows all supported algorithms for input hashes      | --identify my.hash",
  " -i, --increment                |      | Enable mask increment mode                           |",
  "     --increment-min            | Num  | Start mask incrementing at X                         | --increment-min=4",
  "     --increment-max            | Num  | Stop mask incrementing at X                          | --increment-max=8",
  " -S, --slow-candidates          |      | Enable slower (but advanced) candidate generators    |",
  #ifdef WITH_BRAIN
  "     --brain-server             |      | Enable brain server                                  |",
  "     --brain-server-timer       | Num  | Update the brain server dump each X seconds (min:60) | --brain-server-timer=300",
  " -z, --brain-client             |      | Enable brain client, activates -S                    |",
  "     --brain-client-features    | Num  | Define brain client features, see below              | --brain-client-features=3",
  "     --brain-host               | Str  | Brain server host (IP or domain)                     | --brain-host=127.0.0.1",
  "     --brain-port               | Port | Brain server port                                    | --brain-port=13743",
  "     --brain-password           | Str  | Brain server authentication password                 | --brain-password=bZfhCvGUSjRq",
  "     --brain-session            | Hex  | Overrides automatically calculated brain session     | --brain-session=0x2ae611db",
  "     --brain-session-whitelist  | Hex  | Allow given sessions only, separated with commas     | --brain-session-whitelist=0x2ae611db",
  #endif
  "",
  "- [ Hash modes ] -",
  "",
  "      # | Name                                                       | Category",
  "  ======+============================================================+======================================",
  NULL
};

static const char *const USAGE_BIG_POST_HASHMODES[] =
{
  #ifdef WITH_BRAIN
  "- [ Brain Client Features ] -",
  "",
  "  # | Features",
  " ===+========",
  "  1 | Send hashed passwords",
  "  2 | Send attack positions",
  "  3 | Send hashed passwords and attack positions",
  "",
  #endif
  "- [ Outfile Formats ] -",
  "",
  "  # | Format",
  " ===+========",
  "  1 | hash[:salt]",
  "  2 | plain",
  "  3 | hex_plain",
  "  4 | crack_pos",
  "  5 | timestamp absolute",
  "  6 | timestamp relative",
  "",
  "- [ Rule Debugging Modes ] -",
  "",
  "  # | Format",
  " ===+========",
  "  1 | Finding-Rule",
  "  2 | Original-Word",
  "  3 | Original-Word:Finding-Rule",
  "  4 | Original-Word:Finding-Rule:Processed-Word",
  "  5 | Original-Word:Finding-Rule:Processed-Word:Wordlist",
  "",
  "- [ Attack Modes ] -",
  "",
  "  # | Mode",
  " ===+======",
  "  0 | Straight",
  "  1 | Combination",
  "  3 | Brute-force",
  "  6 | Hybrid Wordlist + Mask",
  "  7 | Hybrid Mask + Wordlist",
  "  9 | Association",
  "",
  "- [ Built-in Charsets ] -",
  "",
  "  ? | Charset",
  " ===+=========",
  "  l | abcdefghijklmnopqrstuvwxyz [a-z]",
  "  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]",
  "  d | 0123456789                 [0-9]",
  "  h | 0123456789abcdef           [0-9a-f]",
  "  H | 0123456789ABCDEF           [0-9A-F]",
  "  s |  !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
  "  a | ?l?u?d?s",
  "  b | 0x00 - 0xff",
  "",
  "- [ OpenCL Device Types ] -",
  "",
  "  # | Device Type",
  " ===+=============",
  "  1 | CPU",
  "  2 | GPU",
  "  3 | FPGA, DSP, Co-Processor",
  "",
  "- [ Workload Profiles ] -",
  "",
  "  # | Performance | Runtime | Power Consumption | Desktop Impact",
  " ===+=============+=========+===================+=================",
  "  1 | Low         |   2 ms  | Low               | Minimal",
  "  2 | Default     |  12 ms  | Economic          | Noticeable",
  "  3 | High        |  96 ms  | High              | Unresponsive",
  "  4 | Nightmare   | 480 ms  | Insane            | Headless",
  "",
  "- [ License ] -",
  "",
  "  hashcat is licensed under the MIT license",
  "  Copyright and license terms are listed in docs/license.txt",
  "",
  "- [ Basic Examples ] -",
  "",
  "  Attack-          | Hash- |",
  "  Mode             | Type  | Example command",
  " ==================+=======+==================================================================",
  "  Wordlist         | $P$   | hashcat -a 0 -m 400 example400.hash example.dict",
  "  Wordlist + Rules | MD5   | hashcat -a 0 -m 0 example0.hash example.dict -r rules/best64.rule",
  "  Brute-Force      | MD5   | hashcat -a 3 -m 0 example0.hash ?a?a?a?a?a?a",
  "  Combinator       | MD5   | hashcat -a 1 -m 0 example0.hash example.dict example.dict",
  "  Association      | $1$   | hashcat -a 9 -m 500 example500.hash 1word.dict -r rules/best64.rule",
  "",
  "If you still have no idea what just happened, try the following pages:",
  "",
  "* https://hashcat.net/wiki/#howtos_videos_papers_articles_etc_in_the_wild",
  "* https://hashcat.net/faq/",
  "",
  "If you think you need help by a real human come to the hashcat Discord:",
  "",
  "* https://hashcat.net/discord",
  NULL
};

int sort_by_usage (const void *p1, const void *p2)
{
  const usage_sort_t *u1 = (const usage_sort_t *) p1;
  const usage_sort_t *u2 = (const usage_sort_t *) p2;

  if (u1->hash_category > u2->hash_category) return  1;
  if (u1->hash_category < u2->hash_category) return -1;

  const bool first1_is_lc = ((u1->hash_name[0] >= 'a') && (u1->hash_name[0] <= 'z')) ? true :  false;
  const bool first2_is_lc = ((u2->hash_name[0] >= 'a') && (u2->hash_name[0] <= 'z')) ? true :  false;

  if (first1_is_lc != first2_is_lc)
  {
    if (first1_is_lc) return  1;
    else              return -1;
  }

  const int rc_name = strncmp (u1->hash_name + 1, u2->hash_name + 1, 20); // yes, strange...

  if (rc_name > 0) return  1;
  if (rc_name < 0) return -1;

  if (u1->hash_mode > u2->hash_mode) return  1;
  if (u1->hash_mode < u2->hash_mode) return -1;

  return 0;
}

void usage_mini_print (const char *progname)
{
  for (int i = 0; USAGE_MINI[i] != NULL; i++)
  {
    printf (USAGE_MINI[i], progname);

    fwrite (EOL, strlen (EOL), 1, stdout);
  }

  #if defined (_WIN)
  printf ("\n");
  printf ("Press any key to exit\n");

  getch ();
  #endif
}

void usage_big_print (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
        user_options_t  *user_options  = hashcat_ctx->user_options;

  char *modulefile = (char *) hcmalloc (HCBUFSIZ_TINY);

  usage_sort_t *usage_sort_buf = (usage_sort_t *) hccalloc (MODULE_HASH_MODES_MAXIMUM, sizeof (usage_sort_t));

  int usage_sort_cnt = 0;

  for (int i = 0; i < MODULE_HASH_MODES_MAXIMUM; i++)
  {
    user_options->hash_mode = i;

    module_filename (folder_config, i, modulefile, HCBUFSIZ_TINY);

    if (hc_path_exist (modulefile) == false) continue;

    const int rc = hashconfig_init (hashcat_ctx);

    if (rc == 0)
    {
      usage_sort_buf[usage_sort_cnt].hash_mode     = hashconfig->hash_mode;
      usage_sort_buf[usage_sort_cnt].hash_name     = hcstrdup (hashconfig->hash_name);
      usage_sort_buf[usage_sort_cnt].hash_category = hashconfig->hash_category;

      usage_sort_cnt++;
    }

    hashconfig_destroy (hashcat_ctx);
  }

  hcfree (modulefile);

  qsort (usage_sort_buf, usage_sort_cnt, sizeof (usage_sort_t), sort_by_usage);

  for (int i = 0; USAGE_BIG_PRE_HASHMODES[i] != NULL; i++)
  {
    printf ("%s", USAGE_BIG_PRE_HASHMODES[i]);

    fwrite (EOL, strlen (EOL), 1, stdout);
  }

  //hc_fwrite (EOL, strlen (EOL), 1, stdout);

  for (int i = 0; i < usage_sort_cnt; i++)
  {
    printf ("%7u | %-58s | %s", usage_sort_buf[i].hash_mode, usage_sort_buf[i].hash_name, strhashcategory (usage_sort_buf[i].hash_category));

    fwrite (EOL, strlen (EOL), 1, stdout);
  }

  fwrite (EOL, strlen (EOL), 1, stdout);

  for (int i = 0; i < usage_sort_cnt; i++)
  {
    hcfree (usage_sort_buf[i].hash_name);
  }

  hcfree (usage_sort_buf);

  for (int i = 0; USAGE_BIG_POST_HASHMODES[i] != NULL; i++)
  {
    printf ("%s", USAGE_BIG_POST_HASHMODES[i]);

    fwrite (EOL, strlen (EOL), 1, stdout);
  }

  fwrite (EOL, strlen (EOL), 1, stdout);
}

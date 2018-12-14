#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

##
## Installation script for all perl and python modules:
##
## tools/install_modules.sh
##

##
## If you want to add a new hash mode, follow the STEP comments.
##

use strict;
use warnings;

use Authen::Passphrase::LANManager;
use Authen::Passphrase::MySQL323;
use Authen::Passphrase::NTHash;
use Authen::Passphrase::PHPass;
use Convert::EBCDIC            qw (ascii2ebcdic);
use Crypt::CBC;
use Crypt::DES;
use Crypt::Digest::RIPEMD160   qw (ripemd160_hex);
use Crypt::Digest::Whirlpool   qw (whirlpool_hex);
use Crypt::ECB                 qw (encrypt);
use Crypt::Eksblowfish::Bcrypt qw (bcrypt en_base64);
use Crypt::GCrypt;
use Crypt::Mode::CBC;
use Crypt::Mode::ECB;
use Crypt::MySQL               qw (password41);
use Crypt::OpenSSH::ChachaPoly;
use Crypt::PBKDF2;
use Crypt::RC4;
use Crypt::Rijndael;
use Crypt::ScryptKDF           qw (scrypt_hash scrypt_raw scrypt_b64);
use Crypt::Skip32;
use Crypt::Twofish;
use Crypt::UnixCrypt_XS        qw (crypt_rounds fold_password base64_to_int24 block_to_base64 int24_to_base64);
use Digest::MD4                qw (md4 md4_hex);
use Digest::MD5                qw (md5 md5_hex);
use Digest::SHA                qw (sha1 sha256 sha384 sha512 sha1_hex sha224_hex sha256_hex sha384_hex sha512_hex hmac_sha1 hmac_sha256 hmac_sha512);
use Digest::SHA1;
use Digest::SHA3               qw (sha3_224_hex sha3_256_hex sha3_384_hex sha3_512_hex);
use Digest::Keccak             qw (keccak_224_hex keccak_256_hex keccak_384_hex keccak_512_hex);
use Digest::HMAC               qw (hmac hmac_hex);
use Digest::BLAKE2             qw (blake2b_hex);
use Digest::GOST               qw (gost gost_hex);
use Digest::HMAC_MD5           qw (hmac_md5);
use Digest::CRC                qw (crc32);
use Digest::CMAC;
use Digest::SipHash            qw (siphash);
use Digest::Perl::MD5;
use Encode;
use JSON;
use MIME::Base32               qw (encode_base32 decode_base32);
use MIME::Base64               qw (encode_base64 decode_base64 encode_base64url decode_base64url);
use Net::DNS::RR::NSEC3;
use Net::DNS::SEC;
use POSIX                      qw (strftime ceil);
use Text::Iconv;

my $hashcat = "./hashcat";

my $MAX_LEN = 55;

## STEP 1: Add your hash mode to this array.
#
# This array contains all supported hash modes.
#
##

my $MODES =
[
      0,    10,    11,    12,    20,    21,    22,    23,    30,    40,    50,
     60,   100,   101,   110,   111,   112,   120,   121,   122,   125,   130,
    131,   132,   133,   140,   141,   150,   160,   200,   300,   400,   500,
    600,   900,  1000,  1100,  1300,  1400,  1410,  1411,  1420,  1430,  1440,
   1441,  1450,  1460,  1500,  1600,  1700,  1710,  1711,  1720,  1730,  1740,
   1722,  1731,  1750,  1760,  1800,  2100,  2400,  2410,  2500,  2600,  2611,
   2612,  2711,  2811,  3000,  3100,  3200,  3710,  3711,  3300,  3500,  3610,
   3720,  3800,  3910,  4010,  4110,  4210,  4300,  4400,  4500,  4520,  4521,
   4522,  4600,  4700,  4800,  4900,  5100,  5300,  5400,  5500,  5600,  5700,
   5800,  6000,  6100,  6300,  6400,  6500,  6600,  6700,  6800,  6900,  7000,
   7100,  7200,  7300,  7400,  7500,  7700,  7701,  7800,  7801,  7900,  8000,
   8100,  8200,  8300,  8400,  8500,  8600,  8700,  8900,  9100,  9200,  9300,
   9400,  9500,  9600,  9700,  9800,  9900, 10000, 10100, 10200, 10300, 10400,
  10500, 10600, 10700, 10800, 10900, 11000, 11100, 11200, 11300, 11400, 11500,
  11600, 11700, 11750, 11760, 11800, 11850, 11860, 11900, 12000, 12001, 12100,
  12200, 12300, 12400, 12600, 12700, 12800, 12900, 13000, 13100, 13200, 13300,
  13400, 13500, 13600, 13800, 13900, 14000, 14100, 14400, 14700, 14800, 14900,
  15000, 15100, 15200, 15300, 15400, 15500, 15600, 15700, 15900, 16000, 16100,
  16200, 16300, 16400, 16500, 16600, 16700, 16800, 16900, 17300, 17400, 17500,
  17600, 17700, 17800, 17900, 18000, 18100, 18200, 18300, 18400, 18500, 18600,
  99999
];

## STEP 2a: If your hash mode does not need a salt, add it to this array.
#
# This array contains all unsalted hash-modes that are handled in the 'default'
# branches in all three single, passthrough and verify test functions. There
# still are some unsalted hash-modes which are handled differently and are not
# listed here; they are caught in separate if conditions accordingly.
#
##

my $COMMON_UNSALTED_MODES =
[
      0,   100,   101,   133,   200,   300,   600,   900,  1000,  1300,  1400,
   1700,  2600,  3500,  4300,  4400,  4500,  4600,  4700,  5100,  5700,  6000,
   6100,  6900,  9900, 10800, 11500, 11700, 11800, 16400, 17300, 17400, 17500,
  17600, 17700, 17800, 17900, 18000, 18500, 99999
];

## STEP 2b: If your hash-mode has a salt without any specific syntax,
##          add it to this array. Else look for STEP 2c (several spots).
#
# Same as above, only for salted hashes without specific salt formats.
#
##

my $COMMON_DEFAULT_SALTED_MODES =
[
     10,    20,    23,    30,    40,    50,    60,   110,   120,   130,   140,
    150,   160,  1410,  1420,  1430,  1440,  1450,  1460,  1710,  1720,  1730,
   1740,  1750,  1760,  3610,  3710,  3720,  3910,  4010,  4110,  4210, 11750,
  11760, 11850, 11860, 18100
];

# Arrays for hash modes with maximum password length 15

my $LESS_FIFTEEN = [500, 1600, 1800, 3200, 6300, 7400, 10500, 10700];

# Arrays for hash modes with unusual salts

my $ALLOW_LONG_SALT =
[
   2500,  4520,  4521,  5500,  5600,  7100,  7200,  7300,  9400,  9500,  9600,
   9700,  9800, 10400, 10500, 10600, 10700,  1100, 11000, 11200, 11300, 11400,
  11600, 12600, 13500, 13800, 15000, 16900
];

my $IS_UTF16LE =
[
     30,    40,   130,   131,   132,   133,   140,   141,  1000,  1100,  1430,
   1440,  1441,  1730,  1740,  1731,  5500,  5600,  8000,  9400,  9500,  9600,
   9700,  9800, 11600, 13500, 13800
];

my $LOTUS_MAGIC_TABLE =
[
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c,
  0x1b, 0x33, 0xfd, 0xd0, 0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a, 0x41, 0x9f, 0xe1, 0xd9,
  0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0,
  0xa6, 0x3f, 0xd8, 0x0c, 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60, 0x48, 0xe6, 0x1e, 0x53,
  0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12,
  0xba, 0x3c, 0x06, 0x4e, 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf, 0x3a, 0xde, 0x96, 0x0e,
  0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02,
  0x75, 0xd5, 0x61, 0xe3, 0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c, 0xb4, 0xc5, 0xcc, 0x70,
  0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b,
  0x82, 0xf9, 0x40, 0xb5, 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5, 0x64, 0x6d, 0x7a, 0xd4,
  0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9,
  0x4c, 0xff, 0x43, 0xab
];

my $PDF_PADDING =
[
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56,
  0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
];

my $CISCO_BASE64_MAPPING =
{
  'A', '.', 'B', '/', 'C', '0', 'D', '1', 'E', '2', 'F', '3', 'G', '4', 'H',
  '5', 'I', '6', 'J', '7', 'K', '8', 'L', '9', 'M', 'A', 'N', 'B', 'O', 'C',
  'P', 'D', 'Q', 'E', 'R', 'F', 'S', 'G', 'T', 'H', 'U', 'I', 'V', 'J', 'W',
  'K', 'X', 'L', 'Y', 'M', 'Z', 'N', 'a', 'O', 'b', 'P', 'c', 'Q', 'd', 'R',
  'e', 'S', 'f', 'T', 'g', 'U', 'h', 'V', 'i', 'W', 'j', 'X', 'k', 'Y', 'l',
  'Z', 'm', 'a', 'n', 'b', 'o', 'c', 'p', 'd', 'q', 'e', 'r', 'f', 's', 'g',
  't', 'h', 'u', 'i', 'v', 'j', 'w', 'k', 'x', 'l', 'y', 'm', 'z', 'n', '0',
  'o', '1', 'p', '2', 'q', '3', 'r', '4', 's', '5', 't', '6', 'u', '7', 'v',
  '8', 'w', '9', 'x', '+', 'y', '/', 'z'
};

if (scalar @ARGV < 1)
{
  usage_die ();
}

my $type;
my $mode;
my $len;

$type = shift @ARGV;

if ($type ne "verify")
{
  if (scalar @ARGV > 1)
  {
    $mode = shift @ARGV;
    $len  = shift @ARGV;
  }
  elsif (scalar @ARGV == 1)
  {
    $mode = shift @ARGV;
    $len  = 0;
  }
  else
  {
    $len = 0;
  }

  if ($type eq "single")
  {
    single ($mode);
  }
  elsif ($type eq "passthrough")
  {
    passthrough ($mode);
  }
  else
  {
    usage_die ();
  }
}
else
{
  if (scalar @ARGV != 4)
  {
    usage_die ();
  }

  my $mode      = shift @ARGV;
  my $hash_file = shift @ARGV;
  my $in_file   = shift @ARGV;
  my $out_file  = shift @ARGV;

  my $db;

  open (IN,  "<", $hash_file) or die ("$hash_file: $!\n");

  # clever ? the resulting database could be huge
  # but we need some way to map lines in hashfile w/ cracks
  # maybe rli2 way would be more clever (needs sorted input)

  while (my $line = <IN>)
  {
    $line =~ s/[\n\r]*$//;

    $db->{$line} = undef;
  }

  close (IN);

  verify ($mode, $db, $in_file, $out_file);
}

# Array lookup
sub is_in_array
{
  my $value = shift;
  my $array = shift;

  return grep { $_ eq $value } @{$array};
}

sub verify
{
  my $mode     = shift;
  my $db       = shift;
  my $in_file  = shift;
  my $out_file = shift;

  my $hash_in;
  my $hash_out;
  my $iter;
  my $salt;
  my $word;
  my $param;
  my $param2;
  my $param3;
  my $param4;
  my $param5;
  my $param6;
  my $param7;
  my $param8;
  my $param9;
  my $param10;
  my $param11;

  open (IN,  "<", $in_file)  or die ("$in_file: $!\n");
  open (OUT, ">", $out_file) or die ("$out_file: $!\n");

  my $len;

  my $base64   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  my $itoa64_1 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  my $itoa64_2 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  while (my $line = <IN>)
  {
    chomp ($line);

    $line =~ s/\n$//;
    $line =~ s/\r$//;

    # remember always do "exists ($db->{$hash_in})" checks as soon as possible and don't forget it

    # unsalted
    if (is_in_array ($mode, $COMMON_UNSALTED_MODES)
     || $mode == 2400 || $mode ==  3000
     || $mode == 8600 || $mode == 16000)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $word = substr ($line, $index + 1);
    }
    # hash:salt
    elsif (is_in_array ($mode, $COMMON_DEFAULT_SALTED_MODES)
        || $mode ==    11 || $mode ==    12 || $mode ==    21 || $mode ==    22
        || $mode ==   112 || $mode ==   121 || $mode ==  1100 || $mode ==  2410
        || $mode ==  2611 || $mode ==  2711 || $mode ==  2811 || $mode ==  3100
        || $mode ==  3800 || $mode ==  4520 || $mode ==  4521 || $mode ==  4522
        || $mode ==  4900 || $mode ==  5800 || $mode ==  8400 || $mode == 11000
        || $mode == 12600 || $mode == 13500 || $mode == 13800 || $mode == 13900
        || $mode == 14000 || $mode == 14100 || $mode == 14400 || $mode == 14900
        || $mode == 15000)
    {
      # get hash
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);

      # identify lenghts of both salt and plain

      my $salt_plain = substr ($line, $index1 + 1);

      my $num_cols = () = $salt_plain =~ /:/g;

      my $index2;
      my $matched = 0;
      my $start = 0;

      $word = undef;

      # fuzzy
      foreach (my $i = 0; $i < $num_cols; $i++)
      {
        $index2 = index ($salt_plain, ":", $start);

        next if $index2 < 0;

        $start = $index2 + 1;

        $salt = substr ($salt_plain, 0, $index2);
        $word = substr ($salt_plain, $index2 + 1);

        # can't be true w/ wrong $hash:$salt, otherwise the
        # algo must have many collisions

        if (exists ($db->{$hash_in . ":" . $salt}))
        {
          $hash_in = $hash_in . ":" . $salt;
          $matched = 1;
          last;
        }
      }

      next unless ($matched); # therefore: true == exists ($db->{$hash_in}
      next unless (! defined ($db->{$hash_in}));
    }
    # dcc2
    elsif ($mode == 2100)
    {
      # get hash
      my $index1 = index ($line, "\$DCC2\$");

      next if $index1 != 0;

      # iterations
      my $index2 = index ($line, "#", $index1 + 1);

      next if $index2 < 1;

      $iter = substr ($line, $index1 + 6, $index2 - $index1 - 6);

      # get hash
      $index1 = index ($line, "#");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1 + 1);

      # identify lenghts of both salt and plain

      my $salt_plain = substr ($line, $index2 + 1);

      my $num_cols = () = $salt_plain =~ /:/g;

      my $matched = 0;
      my $start   = 0;
      my $index3  = 0;
      my $raw_hash;

      $word = undef;

      # fuzzy
      foreach (my $i = 0; $i < $num_cols; $i++)
      {
        $index2 = index ($salt_plain, ":", $start);

        next if $index2 < 0;

        $start = $index2 + 1;

        $index3 = rindex ($salt_plain, "#", $index2);

        $raw_hash = substr ($salt_plain, $index3 + 1, $index2 - $index3 - 1);
        $salt = substr ($salt_plain, 0, $index3);
        $word = substr ($salt_plain, $index2 + 1);

        if (exists ($db->{$hash_in . $salt . "#" .$raw_hash}))
        {
          $hash_in = $hash_in . $salt . "#" . $raw_hash;
          $matched = 1;
          last;
        }
      }

      next unless ($matched); # therefore: true == exists ($db->{$hash_in}
      next unless (! defined ($db->{$hash_in}));
    }
    # salt:hash guaranteed only : because of hex salt
    elsif ($mode == 7300)
    {
      # split hash and plain
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $salt = substr ($line, 0, $index1);

      $salt = pack ("H*", $salt);

      my $rest = substr ($line, $index1 + 1);

      my $index2 = index ($rest, ":");

      next if $index2 < 1;

      $hash_in = substr ($rest, 0, $index2);

      $word = substr ($rest, $index2 + 1);

      next unless (exists ($db->{$salt . ":" . $hash_in}) and (! defined ($db->{$hash_in})));
    }
    # 1salthash fixed
    elsif ($mode == 8100)
    {
      # split hash and plain
      $salt = substr ($line, 1, 8);

      my $rest = substr ($line, 1 + 8);

      my $index2 = index ($rest, ":");

      next if $index2 < 1;

      $hash_in = substr ($rest, 0, $index2);

      $word = substr ($rest, $index2 + 1);

      next unless (exists ($db->{"1" . $salt . $hash_in}) and (! defined ($db->{$hash_in})));
    }
    # base64 and salt embedded SSHA1, salt length = total lenght - 20
    elsif ($mode == 111)
    {
      # split hash and plain
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      # remove signature
      my $plain_base64 = substr ($hash_in, 6);

      # base64 decode to extract salt
      my $decoded = decode_base64 ($plain_base64);

      $salt = substr ($decoded, 20);
    }
    # base64 and salt embedded SSHA512, salt length = total length - 64
    elsif ($mode == 1711)
    {
      # split hash and plain
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      # remove signature
      my $plain_base64 = substr ($hash_in, 9);

      # base64 decode to extract salt
      my $decoded = decode_base64 ($plain_base64);

      $salt = substr ($decoded, 64);
    }
    # macOS (first 8 hex chars is salt)
    # ArubaOS (the signature gets added in gen_hash)
    elsif ($mode == 122 || $mode == 1722 || $mode == 125)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = substr ($hash_in, 0, 8);
    }
    # MSSQL (2000, 2005 AND 2012), salt after version number
    elsif ($mode == 131 || $mode == 132 || $mode == 1731)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = substr ($hash_in, 6, 8);
    }
    # Sybase ASE
    elsif ($mode == 8000)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = substr ($hash_in, 6, 16);
    }
    # episerver salts
    elsif ($mode == 141 || $mode == 1441)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 = index ($line, "*", 14);

      #extract salt from base64
      my $plain_base64 = substr ($hash_in, 14, $index2 - 14);

      $salt = decode_base64 ($plain_base64);
    }
    # phpass (first 8 after $P$/$H$ -- or $S$ with drupal7)
    elsif ($mode == 400 || $mode == 7900)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = substr ($hash_in, 4, 8);

      # iterations = 2 ^ cost (where cost == $iter)
      $iter = index ($itoa64_1, substr ($hash_in, 3, 1));
    }
    # $something$[rounds=iter$]salt$     (get last $, then check iter)
    elsif ($mode == 500 || $mode == 1600 || $mode == 1800 || $mode == 3300 || $mode == 7400)
    {
      my $index1 = index ($line, ":", 30);

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $index1 = index ($hash_in,  ",", 1);
      my $index2 = index ($hash_in, "\$", 1);

      if ($index1 != -1)
      {
        if ($index1 < $index2)
        {
          $index2 = $index1;
        }
      }

      $param = substr ($hash_in, $index2, 1);

      $index2++;

      # rounds= if available
      $iter = 0;

      if (substr ($hash_in, $index2, 7) eq "rounds=")
      {
        my $old_index = $index2;

        $index2 = index ($hash_in, "\$", $index2 + 1);

        next if $index2 < 1;

        $iter = substr ($hash_in, $old_index + 7, $index2 - $old_index - 7);

        $index2++;
      }

      # get salt
      my $index3 = rindex ($hash_in, "\$");

      next if $index3 < 1;

      $salt = substr ($hash_in, $index2, $index3 - $index2);
    }
    # descrypt (salt in first 2 char)
    elsif ($mode == 1500)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = substr ($hash_in, 0, 2);
    }
    # bcrypt $something$something$salt.hash
    elsif ($mode == 3200)
    {
      my $index1 = index ($line, ":", 33);

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 =  index ($hash_in, "\$", 4);

      $iter = substr ($hash_in, 4, $index2 - 4);

      my $plain_base64 = substr ($hash_in, $index2 + 1, 22);

      # base64 mapping
      my $encoded = "";

      for (my $i = 0; $i < length ($plain_base64); $i++)
      {
        my $char  = substr ($plain_base64, $i, 1);
        $encoded .= substr ($base64, index ($itoa64_2, $char), 1);
      }

      $salt = decode_base64 ($encoded);
    }
    # md5 (chap)
    elsif ($mode == 4800)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      my $index3 = index ($line, ":", $index2 + 1);

      next if $index3 < 1;

      $salt = substr ($line, $index1 + 1, $index3 - $index1 - 1);

      $word = substr ($line, $index3 + 1);

      $hash_in = substr ($line, 0, $index3);
    }
    # IKE (md5 and sha1)
    elsif ($mode == 5300 || $mode == 5400)
    {
      my $num_cols = () = $line =~ /:/g;

      next unless ($num_cols >= 9);

      my $index1 = -1;
      my $failed =  0;

      for (my $j = 0; $j < 9; $j++)
      {
        $index1 = index ($line, ":", $index1 + 1);

        if ($index1 < 1)
        {
          $failed = 1;
          last;
        }
      }

      next if ($failed);

      $word = substr ($line, $index1 + 1);

      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 = rindex ($line, ":", $index1 - 1);

      $salt = substr ($line, 0, $index2);
    }
    # NetNTLMv1
    elsif ($mode == 5500)
    {
      my $index1 = index ($line, "::");

      next if $index1 < 1;

      my $index2 = index ($line, ":", $index1 + 2);

      next if $index2 < 1;

      $index2 = index ($line, ":", $index2 + 1);

      next if $index2 < 1;

      $salt = substr ($line, 0, $index2);

      $index2 = index ($line, ":", $index2 + 1);

      next if $index2 < 1;

      $salt .= substr ($line, $index2 + 1, 16);

      $index2 = index ($line, ":", $index2 + 1);

      next if $index2 < 1;

      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $word = substr ($line, $index2 + 1);
    }
    # NetNTLMv2
    elsif ($mode == 5600)
    {
      my $index1 = index ($line, "::");

      next if $index1 < 1;

      my $index2 = index ($line, ":", $index1 + 2);

      next if $index2 < 1;

      $index2 = index ($line, ":", $index2 + 1);

      next if $index2 < 1;

      $salt = substr ($line, 0, $index2);

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $salt .= substr ($line, $index1 + 1, $index2 - $index1 - 1);

      $hash_in = substr ($line, 0, $index2);

      # do it later on for this hash mode:
      # next unless ((exists ($db->{$hash_in}) and (! defined ($db->{$hash_in}))) or (exists ($db->{$mod}) and (! defined ($db->{$mod}))));

      $word = substr ($line, $index2 + 1);
    }
    # AIX smd5 something BRACE salt$
    elsif ($mode == 6300)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 =  index ($hash_in, "}");
      my $index3 = rindex ($hash_in, "\$");

      $salt = substr ($hash_in, $index2 + 1, $index3 - $index2 - 1);
    }
    # AIX: something$salt$ (no $ at position 1)
    elsif ($mode == 6400 || $mode == 6500 || $mode == 6700)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 =  index ($hash_in, "}");
      my $index3 =  index ($hash_in, "\$");
      my $index4 = rindex ($hash_in, "\$");

      $salt = substr ($hash_in, $index3 + 1, $index4 - $index3 - 1);

      $iter = substr ($hash_in, $index2 + 1, $index3 - $index2 - 1);
    }
    # 1Password, agilekeychain
    elsif ($mode == 6600)
    {
      my $num_cols = () = $line =~ /:/g;

      next unless ($num_cols > 2);

      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $iter = substr ($line, 0, $index1);

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      $salt .= substr ($line, $index2 + 1, $index1 - $index2 - 33);

      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $word = substr ($line, $index1 + 1);
    }
    # 1Password, cloudkeychain
    elsif ($mode == 8200)
    {
      my @datas = split (":", $line);

      next if scalar @datas < 4;

      my $hash = shift @datas;
      $salt    = shift @datas;
      $iter    = shift @datas;
      my $data = shift @datas;

      $hash_in = $hash . ":" . $salt . ":" . $iter . ":" . $data;

      $salt .= $data;

      $word = join (":", @datas);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # lastpass (hash:iter:salt)
    elsif ($mode == 6800)
    {
      my $index1 = index ($line, ":", 34);

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);

      # identify lenghts of both salt and plain

      my $salt_plain = substr ($line, $index1 + 1);

      my $num_cols = () = $salt_plain =~ /:/g;

      my $index2;
      my $matched = 0;
      my $start = 0;

      $word = undef;

      # fuzzy
      foreach (my $i = 0; $i < $num_cols; $i++)
      {
        $index2 = index ($salt_plain, ":", $start);

        next if $index2 < 1;

        $start = $index2 + 1;

        $salt = substr ($salt_plain, 0, $index2);
        $word = substr ($salt_plain, $index2 + 1);

        # can't be true w/ wrong $hash:$salt, otherwise the
        # algo must have many collisions

        if (exists ($db->{$hash_in . ":" . $salt}))
        {
          $hash_in = $hash_in . ":" . $salt;
          $matched = 1;
          last;
        }
      }

      next unless ($matched); # therefore: true == exists ($db->{$hash_in}
      next unless (! defined ($db->{$hash_in}));

      $index1 = index ($hash_in, ":");
      $index2 = index ($hash_in, ":", $index1 + 1);

      $iter = substr ($hash_in, $index1 + 1, $index2 - $index1 - 1);
      $salt = substr ($hash_in, $index2 + 1);
    }
    # Fortigate
    elsif ($mode == 7000)
    {
      my $index1 = index ($line, ":");

      next if $index1 != 47;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (substr ($hash_in, 0, 3) eq "AK1");

      my $decoded = decode_base64 (substr ($hash_in, 3));

      $salt = substr ($decoded, 0, 12);
      $salt = unpack ("H*", $salt);
    }
    # macOS 10.* : $something$iter$salt$
    elsif ($mode == 7100)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 =  index ($hash_in, "\$", 5);

      next if $index2 < 1;

      my $index3 =  index ($hash_in, "\$", $index2 + 1);

      $salt = substr ($hash_in, $index2 + 1, $index3 - $index2 - 1);

      $iter = substr ($hash_in, 4, $index2 - 4);

      next if (int ($iter) < 1);
    }
    # grub: something1.something2.something3.iter.salt.
    elsif ($mode == 7200)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index2 =  index ($hash_in, ".", 19);

      next if $index2 < 1;

      my $index3 =  index ($hash_in, ".", $index2 + 1);

      $salt = substr ($hash_in, $index2 + 1, $index3 - $index2 - 1);

      $iter = substr ($hash_in, 19, $index2 - 19);

      next if (int ($iter) < 1);
    }
    # $something1$something2$something3$something4$salt$
    elsif ($mode == 7500 )
    {
      my $index1 = index ($line, "\$", 11);

      next if $index1 < 1;

      my $index2 = index ($line, "\$", $index1 + 1);

      next if $index2 < 1;

      my $index3 = index ($line, "\$", $index2 + 1);

      next if $index3 < 1;

      $index2 = index ($line, ":", $index3 + 1);

      next if $index2 < 1;

      $hash_in = substr ($line, 0, $index2);
      $word    = substr ($line, $index2 + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt  = substr ($hash_in, 11, $index3 - 10);
      $salt .= substr ($hash_in, $index2 - 32) . "\$\$";
      $salt .= substr ($hash_in, $index3 + 1, $index2 - $index3 - 32 - 1);
    }
    # $salt$$hash
    elsif ($mode == 7700 || $mode == 7800 || $mode == 7701 || $mode == 7801)
    {
      my $index1 = index ($line, ":");

      next if $index1 < 1;

      my @split1 = split (":", $line);

      my @split2 = split ('\$', $split1[0]);

      next unless scalar @split2 == 2;

      $hash_in = $split1[0];

      if (scalar @split1 > 1)
      {
        $word = $split1[1];
      }
      else
      {
        $word = "";
      }

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = $split2[0];
    }
    # DNSSEC
    elsif ($mode == 8300)
    {
      my @datas = split (":", $line);

      next if scalar @datas != 5;

      my $hash;
      my $domain;

      ($hash, $domain, $salt, $iter, $word) = @datas;

      $hash_in = $hash . ":" . $domain . ":" . $salt . ":" . $iter;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      $salt = $domain . ":" . $salt;
    }
    # RACF
    elsif ($mode == 8500)
    {
      my @line_elements = split (":", $line);

      next if scalar @line_elements < 2;

      # get hash and word

      $hash_in = shift @line_elements;

      $word = join (":", @line_elements);

      # get signature

      my @hash_elements = split ('\*', $hash_in);

      next unless ($hash_elements[0] eq '$racf$');

      $salt = $hash_elements[1];

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # DOMINO 6
    elsif ($mode == 8700)
    {
      # split hash and plain
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $plain_base64 = substr ($hash_in, 2, -1);

      ($_, $salt, $param) = domino_decode ($plain_base64);
    }
    # PHPS
    elsif ($mode == 2612)
    {
      next unless (substr ($line, 0, 6) eq '$PHPS$');

      # get hash
      my $index1 = index ($line, "\$", 6);

      next if $index1 < 1;

      $salt = substr ($line, 6, $index1 - 6);

      $salt = pack ("H*", $salt);

      my $index2 = index ($line, "\:", $index1 + 1);

      next if $index2 < 1;

      $word = substr ($line, $index2 + 1);

      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Mediawiki B type
    elsif ($mode == 3711)
    {
      next unless (substr ($line, 0, 3) eq '$B$');

      # get hash
      my $index1 = index ($line, "\$", 3);

      next if $index1 < 1;

      $salt = substr ($line, 3, $index1 - 3);

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $word = substr ($line, $index2 + 1);

      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # scrypt
    elsif ($mode == 8900)
    {
      next unless (substr ($line, 0, 7) eq 'SCRYPT:');

      # get hash
      my $index1 = index ($line, ":", 7);

      next if $index1 < 1;

      # N
      my $N = substr ($line, 7, $index1 - 7);

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      # r
      my $r = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      # p
      my $p = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      $param  = $N;
      $param2 = $r;
      $param3 = $p;

      $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      # salt
      $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      $salt = decode_base64 ($salt);

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      # digest

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # LOTUS 8
    elsif ($mode == 9100)
    {
      # split hash and plain
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $base64_part = substr ($hash_in, 2, -1);

      ($_, $salt, $iter, $param) = domino_85x_decode ($base64_part);

      next if ($iter < 1);
    }
    # Cisco $8$ - PBKDF2-HMAC-SHA256
    elsif ($mode == 9200)
    {
      next unless (substr ($line, 0, 3) eq '$8$');

      # get hash
      my $index1 = index ($line, "\$", 3);

      next if $index1 != 17;

      my $index2 = index ($line, "\$", $index1 + 1);

      # salt
      $salt = substr ($line, 3,  $index1 - 3);

      $index1 = index ($line, ":", $index1 + 1);

      next if $index1 < 1;

      # digest

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Cisco $9$ - scrypt
    elsif ($mode == 9300)
    {
      next unless (substr ($line, 0, 3) eq '$9$');

      # get hash
      my $index1 = index ($line, "\$", 3);

      next if $index1 != 17;

      my $index2 = index ($line, "\$", $index1 + 1);

      # salt
      $salt = substr ($line, 3,  $index1 - 3);

      $index1 = index ($line, ":", $index1 + 1);

      next if $index1 < 1;

      # digest

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Office 2007
    elsif ($mode == 9400)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 8;

      next unless (shift @data eq '$office$');
      next unless (shift @data eq '2007');
      next unless (shift @data eq '20');

      my $aes_key_size = shift @data;

      next unless (($aes_key_size eq '128') || ($aes_key_size eq '256'));
      next unless (shift @data eq '16');

      next unless (length $data[0] == 32);
      next unless (length $data[1] == 32);
      next unless (length $data[2] == 40);

      $salt   = shift @data;
      $param  = shift @data;
      $param2 = $aes_key_size;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Office 2010
    elsif ($mode == 9500)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 8;

      next unless (shift @data eq '$office$');
      next unless (shift @data eq '2010');
      next unless (shift @data eq '100000');
      next unless (shift @data eq '128');
      next unless (shift @data eq '16');

      next unless (length $data[0] == 32);
      next unless (length $data[1] == 32);
      next unless (length $data[2] == 64);

      $salt  = shift @data;
      $param = shift @data;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Office 2013
    elsif ($mode == 9600)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 8;

      next unless (shift @data eq '$office$');
      next unless (shift @data eq '2013');
      next unless (shift @data eq '100000');
      next unless (shift @data eq '256');
      next unless (shift @data eq '16');

      next unless (length $data[0] == 32);
      next unless (length $data[1] == 32);
      next unless (length $data[2] == 64);

      $salt  = shift @data;
      $param = shift @data;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Office Old $1 $2
    elsif ($mode == 9700)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 4;

      my $signature = shift @data;

      next unless (($signature eq '$oldoffice$0') || ($signature eq '$oldoffice$1'));

      next unless (length $data[0] == 32);
      next unless (length $data[1] == 32);
      next unless (length $data[2] == 32);

      $salt  = shift @data;
      $param = shift @data;
      $param2 = substr ($signature, 11, 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Office Old $3 $4
    elsif ($mode == 9800)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 4;

      my $signature = shift @data;

      next unless (($signature eq '$oldoffice$3') || ($signature eq '$oldoffice$4'));

      next unless (length $data[0] == 32);
      next unless (length $data[1] == 32);
      next unless (length $data[2] == 40);

      $salt  = shift @data;
      $param = shift @data;
      $param2 = substr ($signature, 11, 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Django (PBKDF2-SHA256)
    elsif ($mode == 10000)
    {
      next unless (substr ($line, 0, 14) eq 'pbkdf2_sha256$');

      # get hash
      my $index1 = index ($line, "\$", 14);

      next if $index1 < 1;

      my $index2 = index ($line, "\$", $index1 + 1);

      # iter

      $iter = substr ($line, 14,  $index1 - 14);


      # salt
      $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

      # digest

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # SipHash
    elsif ($mode == 10100)
    {
      my $hash;

      ($hash, undef, undef, $salt, $word) = split ":", $line;

      next unless defined $hash;
      next unless defined $salt;
      next unless defined $word;

      next unless (length $hash == 16);
      next unless (length $salt == 32);

      my $hash_in = sprintf ("%s:2:4:%s", $hash, $salt);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Cram MD5
    elsif ($mode == 10200)
    {
      next unless (substr ($line, 0, 10) eq '$cram_md5$');

      # get hash
      my $index1 = index ($line, "\$", 10);

      next if $index1 < 1;

      # challenge

      my $challengeb64 = substr ($line, 10,  $index1 - 10);
      $salt = decode_base64 ($challengeb64);

      # response

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      my $responseb64 = substr ($line, $index1 + 1, $index2 - $index1 - 1);
      my $response = decode_base64 ($responseb64);

      $param = substr ($response, 0, length ($response) - 32 - 1); # -1 is for space

      $word = substr ($line, $index2 + 1);
      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # SAP CODVN H (PWDSALTEDHASH) iSSHA-1
    elsif ($mode == 10300)
    {
      next unless (substr ($line, 0, 10) eq '{x-issha, ');

      # get iterations

      my $index1 = index ($line, "}", 10);

      next if $index1 < 1;

      $iter = substr ($line, 10, $index1 - 10);

      $iter = int ($iter);

      # base64 substring

      my $base64_encoded = substr ($line, $index1 + 1);
      my $base64_decoded = decode_base64 ($base64_encoded);

      $salt = substr ($base64_decoded, 20);

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $word = substr ($line, $index2 + 1);
      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PDF 1.1 - 1.3 (Acrobat 2 - 4)
    elsif ($mode == 10400)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 11;

      next unless (shift @data eq '$pdf$1');
      next unless (shift @data eq '2');
      next unless (shift @data eq '40');
      my $P      = shift @data;
      next unless (shift @data eq '0');
      next unless (shift @data eq '16');
      my $id     = shift @data;
      next unless (shift @data eq '32');
      my $u      = shift @data;
      next unless (shift @data eq '32');
      my $o      = shift @data;

      $salt   = $id;
      $param  = $u;
      $param2 = $o;
      $param3 = $P;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PDF 1.4 - 1.6 (Acrobat 5 - 8)
    elsif ($mode == 10500)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data == 11;

      my $V      = shift @data; $V = substr ($V, 5, 1);
      my $R      = shift @data;
      next unless (shift @data eq '128');
      my $P      = shift @data;
      my $enc    = shift @data;
      next unless (shift @data eq '16');
      my $id     = shift @data;
      next unless (shift @data eq '32');
      my $u      = shift @data;
      next unless (shift @data eq '32');
      my $o      = shift @data;

      $salt   = $id;
      $param  = $u;
      $param2 = $o;
      $param3 = $P;
      $param4 = $V;
      $param5 = $R;
      $param6 = $enc;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PDF 1.7 Level 3 (Acrobat 9)
    elsif ($mode == 10600)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data >= 11;

      next unless (shift @data eq '$pdf$5');
      next unless (shift @data eq '5');
      next unless (shift @data eq '256');
      next unless (shift @data eq '-1028');
      next unless (shift @data eq '1');
      next unless (shift @data eq '16');
      my $id     = shift @data;
      my $rest   = join "*", @data;

      $salt   = $id;
      $param  = $rest;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PDF 1.7 Level 8 (Acrobat 10 - 11)
    elsif ($mode == 10700)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\*/, $hash_in;

      next unless scalar @data >= 11;

      next unless (shift @data eq '$pdf$5');
      next unless (shift @data eq '6');
      next unless (shift @data eq '256');
      next unless (shift @data eq '-1028');
      next unless (shift @data eq '1');
      next unless (shift @data eq '16');
      my $id     = shift @data;
      my $rest   = join "*", @data;

      $salt   = $id;
      $param  = $rest;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PBKDF2-HMAC-SHA256
    elsif ($mode == 10900)
    {
      next unless (substr ($line, 0, 7) eq 'sha256:');

      # iterations
      my $index1 = index ($line, ":", 7);

      next if $index1 < 1;

      $iter = substr ($line, 7, $index1 - 7);

      # salt

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

      $salt = decode_base64 ($salt);

      # end of digest

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      # additional param = output len of pbkdf2

      my $digest64_encoded = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      my $digest = decode_base64 ($digest64_encoded);

      $param = length ($digest);

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PostgreSQL MD5 Authentication
    elsif ($mode == 11100)
    {
      next unless (substr ($line, 0, 10) eq '$postgres$');

      my $index1 = index ($line, "*", 10);

      next if $index1 < 1;

      # the user name

      $param = substr ($line, 10, $index1 - 10);

      # get the 4 byte salt

      my $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 1;

      $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      # word / hash

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # MySQL MD5 Authentication
    elsif ($mode == 11200)
    {
      next unless (substr ($line, 0, 9) eq '$mysqlna$');

      my $index1 = index ($line, "*", 9);

      next if $index1 < 1;

      # salt

      $salt = substr ($line, 9, $index1 - 9);

      # word / hash

      $index1 = index ($line, ":", $index1 + 1);

      next if $index1 < 1;

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # WPA-EAPOL-PBKDF2
    elsif ($mode == 2500)
    {
      print "ERROR: verify currently not supported for WPA-EAPOL-PBKDF2 (because of hashcat's output format)\n";

      exit (1);
    }
    # Bitcoin/Litecoin wallet.dat
    elsif ($mode == 11300)
    {
      print "ERROR: verify currently not supported for Bitcoin/Litecoin wallet.dat because of unknown crypt data\n";

      exit (1);
    }
    # SIP digest authentication (MD5)
    elsif ($mode == 11400)
    {
      next unless (substr ($line, 0, 6) eq '$sip$*');

      # URI_server:

      my $index1 = index ($line, "*", 6);

      next if $index1 < 0;

      $param10 = substr ($line, 6, $index1 - 6);

      next if (length ($param10) > 32);

      # URI_client:

      my $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 0;

      $param11 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next if (length ($param11) > 32);

      # user:

      $index1 = index ($line, "*", $index2 + 1);

      next if $index1 < 0;

      $param = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      next if (length ($param) > 12);

      # realm:

      $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 0;

      $param2 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next if (length ($param2) > 20);

      # method:

      $index1 = index ($line, "*", $index2 + 1);

      next if $index1 < 0;

      $param6 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      next if (length ($param6) > 24);

      # URI_prefix:

      $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 0;

      $param7 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next if (length ($param7) > 10);

      # URI_resource:

      $index1 = index ($line, "*", $index2 + 1);

      next if $index1 < 0;

      $param8 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      next if (length ($param8) > 32);

      # URI_suffix:

      $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 0;

      $param9 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next if (length ($param9) > 32);

      # nonce:

      $index1 = index ($line, "*", $index2 + 1);

      next if $index1 < 0;

      $salt = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      next if (length ($salt) > 34);

      # nonce_client:

      $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 0;

      $param4 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next if (length ($param4) > 12);

      # nonce_count:

      $index1 = index ($line, "*", $index2 + 1);

      next if $index1 < 0;

      $param3 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      next if (length ($param3) > 10);

      # qop:

      $index2 = index ($line, "*", $index1 + 1);

      next if $index2 < 0;

      $param5 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next if (length ($param5) > 8);

      # directive:

      $index1 = index ($line, "*", $index2 + 1);

      next if $index1 < 0;

      my $directive = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      next unless ($directive eq "MD5");

      # hash_buf:

      $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 0;

      my $hex_digest = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      next unless (length ($hex_digest) == 32);

      $word = substr ($line, $index2 + 1);
      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # 7-Zip
    elsif ($mode == 11600)
    {
      next unless (substr ($line, 0, 4) eq '$7z$');

      # p

      my $index1 = index ($line, '$', 4);

      next if $index1 < 0;

      my $p = substr ($line, 4, $index1 - 4);

      next unless ($p eq "0");

      # num cycle power

      my $index2 = index ($line, '$', $index1 + 1);

      next if $index2 < 0;

      $iter = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      # seven zip salt length

      $index1 = index ($line, '$', $index2 + 1);

      next if $index1 < 0;

      $param = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      # seven zip salt

      $index2 = index ($line, '$', $index1 + 1);

      next if $index2 < 0;

      $param2 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      # salt len

      $index1 = index ($line, '$', $index2 + 1);

      next if $index1 < 0;

      $param3 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      # salt

      $index2 = index ($line, '$', $index1 + 1);

      next if $index2 < 0;

      $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      $salt = pack ("H*", $salt);

      # crc / hash

      $index1 = index ($line, '$', $index2 + 1);

      next if $index1 < 0;

      my $crc = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      # ignore this crc, we don't need to pass it to gen_hash ()

      # data len

      $index2 = index ($line, '$', $index1 + 1);

      next if $index2 < 0;

      $param4 = substr ($line, $index1 + 1, $index2 - $index1 - 1);

      # unpack size

      $index1 = index ($line, '$', $index2 + 1);

      next if $index1 < 0;

      $param5 = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      # data

      $index2 = index ($line, ':', $index1 + 1);

      next if $index2 < 0;

      $param6 = substr ($line, $index1 + 1, $index2 - $index1 - 1);
      $param6 = pack ("H*", $param6);

      $word = substr ($line, $index2 + 1);
      $hash_in = substr ($line, 0, $index2);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PBKDF2-HMAC-MD5
    elsif ($mode == 11900)
    {
      next unless (substr ($line, 0, 4) eq 'md5:');

      # iterations
      my $index1 = index ($line, ":", 4);

      next if $index1 < 1;

      $iter = substr ($line, 4, $index1 - 4);

      # salt

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

      $salt = decode_base64 ($salt);

      # end of digest

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      # additional param = output len of pbkdf2

      my $digest64_encoded = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      my $digest = decode_base64 ($digest64_encoded);

      $param = length ($digest);

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PBKDF2-HMAC-SHA1
    elsif ($mode == 12000)
    {
      next unless (substr ($line, 0, 5) eq 'sha1:');

      # iterations
      my $index1 = index ($line, ":", 5);

      next if $index1 < 1;

      $iter = substr ($line, 5, $index1 - 5);

      # salt

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

      $salt = decode_base64 ($salt);

      # end of digest

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      # additional param = output len of pbkdf2

      my $digest64_encoded = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      my $digest = decode_base64 ($digest64_encoded);

      $param = length ($digest);

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # PBKDF2-HMAC-SHA512
    elsif ($mode == 12100)
    {
      next unless (substr ($line, 0, 7) eq 'sha512:');

      # iterations
      my $index1 = index ($line, ":", 7);

      next if $index1 < 1;

      $iter = substr ($line, 7, $index1 - 7);

      # salt

      my $index2 = index ($line, ":", $index1 + 1);

      next if $index2 < 1;

      $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

      $salt = decode_base64 ($salt);

      # end of digest

      $index1 = index ($line, ":", $index2 + 1);

      next if $index1 < 1;

      # additional param = output len of pbkdf2

      my $digest64_encoded = substr ($line, $index2 + 1, $index1 - $index2 - 1);

      my $digest = decode_base64 ($digest64_encoded);

      $param = length ($digest);

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # ecryptfs
    elsif ($mode == 12200)
    {
      next unless (substr ($line, 0, 12) eq '$ecryptfs$0$');

      # check if default salt

      $param = 1;

      $param = 0 if (substr ($line, 12, 2) eq '1$');

      # salt

      $salt = "";

      my $index1 = 12;

      if ($param == 0) # we need to extract the salt
      {
        $index1 = index ($line, '$', $index1);

        next if $index1 < 1;

        my $index2 = index ($line, '$', $index1 + 1);

        next if $index2 < 1;

        $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

        $index1 = $index2;
      }

      $index1 = index ($line, ':', $index1 + 1);

      next if $index1 < 1;

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Oracle T: Type (Oracle 12+)
    elsif ($mode == 12300)
    {
      my $index1 = index ($line, ':');

      next if ($index1 != 160);

      # salt

      $salt = substr ($line, 128, 32);

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # BSDi Crypt, Extended DES
    elsif ($mode == 12400)
    {
      next unless (substr ($line, 0, 1) eq '_');

      my $index1 = index ($line, ':', 20);

      next if ($index1 != 20);

      # iter

      $iter = substr ($line, 1, 4);

      $iter = base64_to_int24 ($iter);

      # salt

      $salt = substr ($line, 5, 4);

      # word / hash

      $word = substr ($line, $index1 + 1);
      $hash_in = substr ($line, 0, $index1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Blockchain, My Wallet
    elsif ($mode == 12700)
    {
      my $index1 = index ($line, ':');

      next if ($index1 < 0);

      $hash_in = substr ($line, 0, $index1);
      $word = substr ($line, $index1 + 1);

      my (undef, $signature, $data_len, $data_buf) = split '\$', $hash_in;

      next unless ($signature eq "blockchain");

      next unless (($data_len * 2) == length $data_buf);

      $salt  = substr ($data_buf, 0, 32);
      $param = substr ($data_buf, 32);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 12800)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split /\,/, $hash_in;

      next unless scalar @data == 4;

      next unless (shift @data eq 'v1;PPH1_MD4');

      $salt = shift @data;
      $iter = shift @data;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 12900)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      next unless length $hash_in == 160;

      $param = substr ($hash_in, 0, 64);
      $salt  = substr ($hash_in, 128, 32);
      $iter  = 4096;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 13000)
    {
      my $hash_line;

      ($hash_line, $word) = split ":", $line;

      next unless defined $hash_line;
      next unless defined $word;

      my @data = split ('\$', $hash_line);

      next unless scalar @data == 8;

      shift @data;

      my $signature    = shift @data;
      my $salt_len     = shift @data;
      my $salt_buf     = shift @data;
      my $iterations   = shift @data;
      my $iv           = shift @data;
      my $pswcheck_len = shift @data;
      my $pswcheck     = shift @data;

      next unless ($signature eq "rar5");
      next unless ($salt_len == 16);
      next unless ($pswcheck_len == 8);

      $salt    = $salt_buf;
      $iter    = $iterations;
      $hash_in = $pswcheck;
      $param   = $iv;

      next unless (exists ($db->{$hash_line}) and (! defined ($db->{$hash_line})));
    }
    elsif ($mode == 13100)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 8;

      shift @data;

      my $signature = shift @data;
      my $algorithm = shift @data;
      my $user      = shift @data;
      $user         = substr ($user, 1);
      my $realm     = shift @data;
      my $spn       = shift @data;
      $spn          = substr ($spn, 0, length ($spn) - 1);
      my $checksum  = shift @data;
      my $edata2    = shift @data;

      next unless ($signature eq "krb5tgs");
      next unless (length ($checksum) == 32);
      next unless (length ($edata2) >= 64);

      $salt = $user . '$' . $realm . '$' . $spn . '$';

      $param  = $checksum;
      $param2 = $edata2;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 13200)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\*', $hash_in);

      next unless scalar @data == 5;

      my $signature = shift @data;
      my $version   = shift @data;
      my $iteration = shift @data;
      my $mysalt    = shift @data;
      my $digest    = shift @data;

      next unless ($signature eq '$axcrypt$');
      next unless (length ($mysalt) == 32);
      next unless (length ($digest) == 48);

      $salt  = $iteration . '*' . $mysalt;
      $param = $digest;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 13300)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 3;

      shift @data;

      my $signature = shift @data;
      my $digest    = shift @data;

      $param = length ($digest);

      next unless ($signature eq 'axcrypt_sha1');
      next unless (($param == 32) || ($param == 40));

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 13400)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\*', $hash_in);

      next unless (scalar @data == 9
                  || scalar @data == 11
                  || scalar @data == 12
                  || scalar @data == 14);

      my $signature = shift @data;
      next unless ($signature eq '$keepass$');

      my $version = shift @data;
      next unless ($version == 1 || $version == 2);

      my $iteration          = shift @data;

      my $algorithm          = shift @data;

      my $final_random_seed  = shift @data;

      if ($version == 1)
      {
        next unless (length ($final_random_seed) == 32);
      }
      elsif ($version == 2)
      {
        next unless (length ($final_random_seed) == 64);
      }

      my $transf_random_seed = shift @data;
      next unless (length ($transf_random_seed) == 64);

      my $enc_iv = shift @data;
      next unless (length ($enc_iv) == 32);

      if ($version == 1)
      {
        my $contents_hash  = shift @data;
        next unless (length ($contents_hash) == 64);

        my $inline_flags   = shift @data;
        next unless ($inline_flags == 1);

        my $contents_len   = shift @data;

        my $contents       = shift @data;
        next unless (length ($contents) == $contents_len * 2);
      }
      elsif ($version == 2)
      {
        my $expected_bytes = shift @data;
        next unless (length ($expected_bytes) == 64);

        my $contents_hash  = shift @data;
        next unless (length ($contents_hash) == 64);
      }

      if (scalar @data == 12 || scalar @data == 14)
      {
        my $inline_flags = shift @data;
        next unless ($inline_flags == 1);

        my $keyfile_len  = shift @data;
        next unless ($keyfile_len == 64);

        my $keyfile     = shift @data;
        next unless (length ($keyfile) == $keyfile_len);
      }

      $salt = substr ($hash_in, length ("*keepass*") + 1);
      $param = 1; # distinguish between encrypting vs decrypting

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 13600)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\*', $hash_in);

      next unless scalar @data == 10;

      my $tag_start     = shift @data;
      my $type          = shift @data;
      my $mode          = shift @data;
      my $magic         = shift @data;
      my $salt          = shift @data;
      my $verify_bytes  = shift @data;
      my $length        = shift @data;
      my $data          = shift @data;
      my $auth          = shift @data;
      my $tag_end       = shift @data;

      next unless ($tag_start eq '$zip2$');
      next unless ($tag_end   eq '$/zip2$');

      $param  = $type;
      $param2 = $mode;
      $param3 = $magic;
      $param4 = $salt;
      $param5 = $length;
      $param6 = $data;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # itunes backup 9/10
    elsif (($mode == 14700) || ($mode == 14800))
    {
      ($hash_in, $word) = split ":", $line;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      my $index1 = index ($hash_in, '*');

      next unless ($index1 == 15);

      # signature

      my $signature = substr ($hash_in, 0, $index1);

      next unless ($signature eq '$itunes_backup$');

      my $index2 = index ($hash_in, '*', $index1 + 1);

      next unless ($index2 >= 0);

      # version

      my $version = substr ($hash_in, $index1 + 1, $index2 - $index1 - 1);

      if ($mode == 14700)
      {
        next unless ($version eq "9");
      }
      else
      {
        next unless ($version eq "10");
      }

      $index1 = index ($hash_in, '*', $index2 + 1);

      next unless ($index1 >= 0);

      # wpky

      my $wpky = substr ($hash_in, $index2 + 1, $index1 - $index2 - 1);

      next unless (length ($wpky) == 80);

      $wpky = pack ("H*", $wpky);

      $param = $wpky;

      $index2 = index ($hash_in, '*', $index1 + 1);

      next unless ($index2 >= 0);

      # iterations

      $iter = substr ($hash_in, $index1 + 1, $index2 - $index1 - 1);
      $iter = int ($iter);

      next unless ($iter > 0);

      $index1 = index ($hash_in, '*', $index2 + 1);

      next unless ($index1 >= 0);

      # salt

      $salt = substr ($hash_in, $index2 + 1, $index1 - $index2 - 1);

      next unless (length ($salt) == 40);

      # dpic and dpsl

      if ($mode == 14700)
      {
        $index2 = index ($hash_in, '**', $index1 + 1);

        next unless ($index2 != $index1 + 1);
      }
      else
      {
        $index2 = index ($hash_in, '*', $index1 + 1);

        next unless ($index2 >= 0);

        # dpic

        my $dpic = substr ($hash_in, $index1 + 1, $index2 - $index1 - 1);

        $dpic = int ($dpic);

        next unless ($dpic > 0);

        $param2 = $dpic;

        # dpsl

        my $dpsl = substr ($hash_in, $index2 + 1);

        next unless (length ($dpsl) == 40);

        $dpsl = pack ("H*", $dpsl);

        $param3 = $dpsl;
      }
    }
    # base64 and salt embedded SSHA256, salt length = total length - 32
    elsif ($mode == 1411)
    {
      # split hash and plain
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));

      # remove signature
      my $plain_base64 = substr ($hash_in, 9);

      # base64 decode to extract salt
      my $decoded = decode_base64 ($plain_base64);

      $salt = substr ($decoded, 32);
    }
    # Atlassian (PBKDF2-HMAC-SHA1)
    elsif ($mode == 12001)
    {
      my $index = index ($line, ":");

      next if $index < 1;

      $hash_in = substr ($line, 0, $index);
      $word    = substr ($line, $index + 1);

      next unless (substr ($hash_in, 0, 9) eq '{PKCS5S2}');

      # base64 buf

      my $base64_buf = substr ($hash_in, 9);
      my $base64_buf_decoded = decode_base64 ($base64_buf);

      next if (length ($base64_buf_decoded) != (16 + 32));

      $salt = substr ($base64_buf_decoded, 0, 16);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 15100)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 5;

      shift @data;

      my $signature = shift @data;

      next unless ($signature eq 'sha1');

      $iter  = shift @data;
      $salt  = shift @data;
      $param = shift @data;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 15200)
    {
      my $index1 = index ($line, ':');

      next if ($index1 < 0);

      $hash_in = substr ($line, 0, $index1);
      $word = substr ($line, $index1 + 1);

      my (undef, $signature, $version, $iter_count, $data_len, $data_buf) = split '\$', $hash_in;

      next unless ($signature eq "blockchain");

      next unless ($version eq "v2");

      next unless (($data_len * 2) == length $data_buf);

      $iter  = $iter_count;
      $salt  = substr ($data_buf, 0, 32);
      $param = substr ($data_buf, 32);

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 15300 || $mode == 15900)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @tmp_data  = split ('\$', $hash_in);

      my $signature = $tmp_data[1];

      next unless ($signature eq 'DPAPImk');

      my @data = split ('\*', $tmp_data[2]);

      next unless (scalar @data == 9);

      my $version = shift @data;

      next unless ($version == 1 || $version == 2);

      my $context          = shift @data;

      my $SID              = shift @data;

      my $cipher_algorithm = shift @data;

      my $hash_algorithm   = shift @data;

      my $iteration        = shift @data;

      my $iv               = shift @data;

      my $cipher_len       = shift @data;

      my $cipher           = shift @data;

      next unless (length ($cipher) == $cipher_len);

      if ($version == 1)
      {
        next unless ($cipher_len == 208);
      }
      elsif ($version == 2)
      {
        next unless ($cipher_len == 288);
      }

      $salt   = substr ($hash_in, length ('$DPAPImk$'));

      $param = $cipher;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # chacha
    elsif ($mode == 15400)
    {
      my $index1 = index ($line, ':');

      next if ($index1 < 0);

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next if (length ($hash_in) < 11);

      next unless (substr ($hash_in, 0, 11) eq "\$chacha20\$\*");

      my @data = split ('\*', $hash_in);

      next unless (scalar (@data) == 6);

      $param  = $data[1]; # counter
      $param2 = $data[2]; # offset
      $param3 = $data[3]; # iv

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # jksprivk
    elsif ($mode == 15500)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\*', $hash_in);

      next unless scalar @data == 7;

      my $signature = shift @data;

      next unless ($signature eq '$jksprivk$');

      my $checksum  = shift @data;
      my $iv        = shift @data;
      my $enc_key   = shift @data;
      my $DER1      = shift @data;
      my $DER2      = shift @data;
      my $alias     = shift @data;

      $param  = $iv;
      $param2 = $enc_key;
      $param3 = $alias;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Ethereum - PBKDF2
    elsif ($mode == 15600)
    {
      my $index1 = index ($line, ':');

      next if ($index1 < 0);

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next if (length ($hash_in) < 12);

      next unless (substr ($hash_in, 0, 12) eq "\$ethereum\$p\*");

      my @data = split ('\*', $hash_in);

      next unless (scalar (@data) == 5);

      $iter = $data[1];

      $salt = pack ("H*", $data[2]);

      $param = pack ("H*", $data[3]); # ciphertext

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Ethereum - Scrypt
    elsif ($mode == 15700)
    {
      my $index1 = index ($line, ':');

      next if ($index1 < 0);

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next if (length ($hash_in) < 12);

      next unless (substr ($hash_in, 0, 12) eq "\$ethereum\$s\*");

      my @data = split ('\*', $hash_in);

      next unless (scalar (@data) == 7);

      $param  = $data[1];              # scrypt_N
      $param2 = $data[2];              # scrypt_r
      $param3 = $data[3];              # scrypt_p

      $salt   = pack ("H*", $data[4]);

      $param4 = pack ("H*", $data[5]); # ciphertext

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # tacacs-plus
    elsif ($mode == 16100)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 6;

      shift @data;

      my $signature = shift @data;

      next unless ($signature eq "tacacs-plus");

      my $auth_version = shift @data;

      next unless ($auth_version eq "0");

      my $session_id      = shift @data;
      my $encrypted_data  = shift @data;
      my $sequence        = shift @data;

      $param  = $session_id;
      $param2 = $encrypted_data;
      $param3 = $sequence;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # apple secure notes
    elsif ($mode == 16200)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\*', $hash_in);

      next unless scalar @data == 5;

      my $signature = shift @data;

      next unless ($signature eq '$ASN$');

      my ($Z_PK, $ZCRYPTOITERATIONCOUNT, $ZCRYPTOSALT, $ZCRYPTOWRAPPEDKEY) = @data;

      $salt = $ZCRYPTOSALT;
      $iter = $ZCRYPTOITERATIONCOUNT;

      $param  = $Z_PK;
      $param2 = $ZCRYPTOWRAPPEDKEY;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Ethereum Pre-Sale - PBKDF2
    elsif ($mode == 16300)
    {
      my $index1 = index ($line, ':');

      next if ($index1 < 0);

      $hash_in = substr ($line, 0, $index1);
      $word    = substr ($line, $index1 + 1);

      next if (length ($hash_in) < 12);

      next unless (substr ($hash_in, 0, 12) eq "\$ethereum\$w\*");

      my @data = split ('\*', $hash_in);

      next unless (scalar (@data) == 4);

      $param  = pack ("H*", $data[1]); # encseed

      $salt = $data[2];                # ethaddr

      $param2 = pack ("H*", $data[3]); # bpk (the iv + keccak digest)

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # JWT
    elsif ($mode == 16500)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split (/\./, $hash_in);

      next unless scalar @data == 3;

      my ($header, $payload, $signature) = @data;

      $salt = $header . "." . $payload;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Electrum Wallet (Salt-Type 1-3)
    elsif ($mode == 16600)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split (/\*/, $hash_in);

      next unless scalar @data == 3;

      my ($mode, $iv, $encrypted) = @data;

      my (undef, $signature, $salt_type) = split ('\$', $mode);

      next unless ($signature eq "electrum");

      $param  = $salt_type;
      $param2 = $iv;
      $param3 = $encrypted;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # FileVault 2
    elsif ($mode == 16700)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 7;

      shift @data;

      my $signature = shift @data;

      next unless ($signature eq 'fvde');

      my $Z_PK = shift @data;

      next unless ($Z_PK eq '1');

      my $salt_length = shift @data;

      next unless ($salt_length eq '16');

      my ($ZCRYPTOSALT, $ZCRYPTOITERATIONCOUNT, $ZCRYPTOWRAPPEDKEY) = @data;

      $salt = $ZCRYPTOSALT;
      $iter = $ZCRYPTOITERATIONCOUNT;

      $param  = $Z_PK;
      $param2 = $ZCRYPTOWRAPPEDKEY;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # WPA-PMKID-PMKDF2
    elsif ($mode == 16800)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split (/\*/, $hash_in);

      next unless scalar @data == 4;

      my ($pmkid, $macap, $macsta, $essid) = @data;

      $param  = $macap;
      $param2 = $macsta;
      $param3 = $essid;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # Ansible Vault
    elsif ($mode == 16900)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\*', $hash_in);

      next unless scalar @data == 5;

      my ($signature_tmp, $cipher, $salt, $ciphertext, $hmac) = @data;

      my ($signature, undef) = split ('\$', $signature_tmp);

      next unless ($signature eq "ansible");

      $param = $ciphertext;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 18200)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 8;

      shift @data;

      my $signature            = shift @data;
      my $algorithm            = shift @data;
      my $user_principal_name  = shift @data;
      my $checksum             = shift @data;
      my $edata2               = shift @data;

      next unless ($signature eq "krb5asrep");
      next unless (length ($checksum) == 32);
      next unless (length ($edata2) >= 64);

      $salt = $user_principal_name;

      $param  = $checksum;
      $param2 = $edata2;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    # FileVault 2
    elsif ($mode == 18300)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      my @data = split ('\$', $hash_in);

      next unless scalar @data == 7;

      shift @data;

      my $signature = shift @data;

      next unless ($signature eq 'fvde');

      my $Z_PK = shift @data;

      next unless ($Z_PK eq '2');

      my $salt_length = shift @data;

      next unless ($salt_length eq '16');

      my ($ZCRYPTOSALT, $ZCRYPTOITERATIONCOUNT, $ZCRYPTOWRAPPEDKEY) = @data;

      $salt = $ZCRYPTOSALT;
      $iter = $ZCRYPTOITERATIONCOUNT;

      $param  = $Z_PK;
      $param2 = $ZCRYPTOWRAPPEDKEY;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 18400)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      # tokenize
      my @data = split ('\*', $hash_in);

      next unless scalar @data == 12;

      my $signature   = shift @data;
      my $cipher_type = shift @data;
      my $cs_type     = shift @data;
      $iter           = shift @data;
      my $cs_len      = shift @data;
      my $cs          = shift @data;
      my $iv_len      = shift @data;
      my $iv          = shift @data;
      my $salt_len    = shift @data;
      $salt           = shift @data;
      my $unused      = shift @data;
      my $ciphertext  = shift @data;

      # validate
      next unless ($signature   eq '$odf$');
      next unless ($cipher_type eq '1');
      next unless ($cs_type     eq '1');
      next unless ($cs_len      eq '32');
      next unless ($iv_len      eq '16');
      next unless ($salt_len    eq '16');
      next unless ($unused      eq '0');
      next unless defined $ciphertext;

      # decrypt
      my $b_iv         = pack ("H*", $iv);
      my $b_salt       = pack ("H*", $salt);
      my $b_ciphertext = pack ("H*", $ciphertext);

      my $kdf = Crypt::PBKDF2->new
      (
        hash_class => 'HMACSHA1',
        iterations => $iter,
        output_len => 32
      );

      my $pass_hash   = sha256 ($word);
      my $derived_key = $kdf->PBKDF2 ($b_salt, $pass_hash);
      my $cbc         = Crypt::Mode::CBC->new ('AES', 0);
      my $b_plaintext = $cbc->decrypt ($b_ciphertext, $derived_key, $b_iv);

      my $plaintext   = unpack ("H*", $b_plaintext);

      $param  = $iv;
      $param2 = $plaintext;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    elsif ($mode == 18600)
    {
      ($hash_in, $word) = split ":", $line;

      next unless defined $hash_in;
      next unless defined $word;

      # tokenize
      my @data = split ('\*', $hash_in);

      next unless scalar @data == 12;

      my $signature   = shift @data;
      my $cipher_type = shift @data;
      my $cs_type     = shift @data;
      $iter           = shift @data;
      my $cs_len      = shift @data;
      my $cs          = shift @data;
      my $iv_len      = shift @data;
      my $iv          = shift @data;
      my $salt_len    = shift @data;
      $salt           = shift @data;
      my $unused      = shift @data;
      my $ciphertext  = shift @data;

      # validate
      next unless ($signature   eq '$odf$');
      next unless ($cipher_type eq '0');
      next unless ($cs_type     eq '0');
      next unless ($cs_len      eq '16');
      next unless ($iv_len      eq '8');
      next unless ($salt_len    eq '16');
      next unless ($unused      eq '0');
      next unless defined $ciphertext;

      # decrypt
      my $b_iv         = pack ("H*", $iv);
      my $b_salt       = pack ("H*", $salt);
      my $b_ciphertext = pack ("H*", $ciphertext);

      my $kdf = Crypt::PBKDF2->new
      (
        hash_class => 'HMACSHA1',
        iterations => $iter,
        output_len => 16
      );

      my $pass_hash   = sha1 ($word);
      my $derived_key = $kdf->PBKDF2 ($b_salt, $pass_hash);

      my $cfb = Crypt::GCrypt->new(
        type      => 'cipher',
        algorithm => 'blowfish',
        mode      => 'cfb'
      );

      $cfb->start  ('decrypting');
      $cfb->setkey ($derived_key);
      $cfb->setiv  ($b_iv);

      my $b_plaintext = $cfb->decrypt ($b_ciphertext);

      $cfb->finish ();

      my $plaintext = unpack ("H*", $b_plaintext);

      $param  = $iv;
      $param2 = $plaintext;

      next unless (exists ($db->{$hash_in}) and (! defined ($db->{$hash_in})));
    }
    ## STEP 2c: Add your custom hash parser branch here
    else
    {
      print "ERROR: hash mode is not supported\n";

      exit (1);
    }

    if ($word =~ m/^\$HEX\[[0-9a-fA-F]*\]$/)
    {
      $word = pack ("H*", substr ($word, 5, -1));
    }

    # finally generate the hash

    # special case:
    if ($mode == 6800)
    {
      # check both variations
      $hash_out = gen_hash ($mode, $word, $salt, $iter, 1);

      $len = length $hash_out; # == length $alternative

      if (substr ($line, 0, $len) ne $hash_out)
      {
        my $alternative = gen_hash ($mode, $word, $salt, $iter, 2);

        return unless (substr ($line, 0, $len) eq $alternative);
      }
    }
    elsif ($mode == 8700)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 8900)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 9100)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 3300)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 5100)
    {
      # check 3 variants (start, middle, end)

      my $idx = 0;

      $hash_out = gen_hash ($mode, $word, $salt, $iter, $idx++);

      $len = length $hash_out; # == length $alternative

      if (substr ($line, 0, $len) ne $hash_out)
      {
        my $alternative = gen_hash ($mode, $word, $salt, $iter, $idx++);

        if (substr ($line, 0, $len) ne $alternative)
        {
          my $alternative = gen_hash ($mode, $word, $salt, $iter, $idx++);

          return unless (substr ($line, 0, $len) eq $alternative);
        }
      }
    }
    elsif ($mode == 9400)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 50000, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 9500)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 100000, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 9600)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 100000, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 9700)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 9800)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 10200)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 10400)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 10500)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2, $param3, $param4, $param5, $param6);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 10600)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 10700)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 10900)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 11100)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 11400)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2, $param3, $param4, $param5, $param6, $param7, $param8, $param9, $param10, $param11);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 11600)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2, $param3, $param4, $param5, $param6);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 11900)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 12000)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 12100)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 12200)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 12700)
    {
      # this is very special, we can't call gen_hash () because the param part is not always the same
      # we only know that it should contain the letters "guid" at the beginning of the decryted string

      my $pbkdf2 = Crypt::PBKDF2->new (
        hash_class => 'HMACSHA1',
        iterations   => 10,
        output_len   => 32
      );

      my $salt_bin = pack ("H*", $salt);

      my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

      my $cipher = Crypt::CBC->new ({
        key         => $key,
        cipher      => "Crypt::Rijndael",
        iv          => $salt_bin,
        literal_key => 1,
        header      => "none",
        keysize     => 32
      });

      my $param_bin = pack ("H*", $param);

      my $decrypted = $cipher->decrypt ($param_bin);

      my $decrypted_part = substr ($decrypted, 1, 16);

      return unless ($decrypted_part =~ /"guid"/);

      $hash_out = $hash_in;
    }
    elsif ($mode == 12900)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 13000)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 13100)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 13200)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 13300)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 13400)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 13600)
    {
      $hash_out = gen_hash ($mode, $word, undef, undef, $param, $param2, $param3, $param4, $param5, $param6);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 14700)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 14800)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 15100)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 15200)
    {
      # this is very special, we can't call gen_hash () because the param part is not always the same
      # we only know that it should contain the letters "guid" at the beginning of the decryted string

      my $pbkdf2 = Crypt::PBKDF2->new (
        hash_class => 'HMACSHA1',
        iterations   => 5000,
        output_len   => 32
      );

      my $salt_bin = pack ("H*", $salt);

      my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

      my $cipher = Crypt::CBC->new ({
        key         => $key,
        cipher      => "Crypt::Rijndael",
        iv          => $salt_bin,
        literal_key => 1,
        header      => "none",
        keysize     => 32
      });

      my $param_bin = pack ("H*", $param);

      my $decrypted = $cipher->decrypt ($param_bin);

      my $decrypted_part = substr ($decrypted, 1, 16);

      return unless ($decrypted_part =~ /"guid"/);

      $hash_out = $hash_in;
    }
    elsif ($mode == 15300 || $mode == 15900)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 15400)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 15500)
    {
      $hash_out = gen_hash ($mode, $word, undef, undef, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 15600)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 15700)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2, $param3, $param4);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16100)
    {
      $hash_out = gen_hash ($mode, $word, undef, 0, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16200)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16300)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16600)
    {
      $hash_out = gen_hash ($mode, $word, undef, 0, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16700)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16800)
    {
      $hash_out = gen_hash ($mode, $word, undef, 0, $param, $param2, $param3);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 16900)
    {
      $hash_out = gen_hash ($mode, $word, $salt, 0, $param);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 18200)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 18300)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 18400)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    elsif ($mode == 18600)
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter, $param, $param2);

      $len = length $hash_out;

      return unless (substr ($line, 0, $len) eq $hash_out);
    }
    ## STEP 2c: Add your custom gen_hash call here
    else
    {
      $hash_out = gen_hash ($mode, $word, $salt, $iter);

      $len = length $hash_out;

      # special cases:
      if ($mode == 400)
      {
        # allow $P$ and $H$ for -m 400
        next unless (substr ($line, 3, $len - 3) eq substr ($hash_out, 3));
      }
      elsif ($mode == 5600)
      {
        # hashcat outputs the user name always upper-case, we need
        next unless (substr ($line, 0, $len) eq $hash_out);

        my $found = 0;

        my $hash_out_lower = lc ($hash_out);

        for my $key (keys %{$db})
        {
          if (lc ($key) eq $hash_out_lower)
          {
            $found = 1;

            last;
          }
        }

        next unless $found;
      }
      else
      {
        next unless (substr ($line, 0, $len) eq $hash_out);
      }
    }

    # do not forget "exists ($db->$hash_out)" should be done above!
    $db->{$hash_out} = $word;
    print OUT $line . "\n";
  }

  close (IN);
  close (OUT);
}

sub passthrough
{
  my $mode = shift || 0;

  while (my $word_buf = <>)
  {
    chomp ($word_buf);

    next if length ($word_buf) > 256;

    ##
    ## gen salt
    ##

    my @salt_arr;

    for (my $i = 0; $i < 256; $i++)
    {
      my $c = get_random_chr (0x30, 0x39);

      push (@salt_arr, $c);
    }

    my $salt_buf = join ("", @salt_arr);

    ##
    ## gen hash
    ##

    my $tmp_hash;

    # unsalted
    if (is_in_array ($mode, $COMMON_UNSALTED_MODES)
     || $mode == 2400 || $mode == 13300)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, "");
    }
    elsif (is_in_array ($mode, $COMMON_DEFAULT_SALTED_MODES)
        || $mode ==  1411 || $mode ==  1711 || $mode ==  3711 || $mode ==  3800
        || $mode ==  4900 || $mode ==  8900 || $mode == 10000 || $mode == 10200
        || $mode == 10900 || $mode == 11900 || $mode == 12000 || $mode == 12100)
    {
      my $salt_len = get_random_num (1, 15);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 11 || $mode == 12)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 21)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 2));
    }
    elsif ($mode == 22)
    {
      my $salt_len = get_random_num (1, 11);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode ==  111 || $mode ==   122 || $mode ==  131 || $mode ==  132
        || $mode ==  400 || $mode ==   500 || $mode == 1600 || $mode == 1722
        || $mode == 1731 || $mode ==  1800 || $mode == 6300 || $mode == 7900
        || $mode == 8100 || $mode == 11100)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 8));
    }
    elsif ($mode == 112)
    {
      next if length ($word_buf) > 30;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 20));
    }
    elsif ($mode == 121)
    {
      my $salt_len = get_random_num (1, 9);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 125)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 8));
    }
    elsif ($mode == 141 || $mode == 1441)
    {
      my $salt_len = get_random_num (1, 15);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 1100)
    {
      my $salt_len = get_random_num (1, 19);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 1500)
    {
      next if length ($word_buf) > 8;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 2));
    }
    elsif ($mode == 2100)
    {
      next if length ($word_buf) > 13;

      my $salt_len = get_random_num (1, 19);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 2410)
    {
      my $salt_len = get_random_num (1, 4);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 2500)
    {
      next if length ($word_buf) < 8;

      my $salt_len = get_random_num (0, 32);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 2611)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 3));
    }
    elsif ($mode == 2612)
    {
      my $salt_len = get_random_num (1, 22);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 2711)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 30));
    }
    elsif ($mode == 2811)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 5));
    }
    elsif ($mode == 3000)
    {
      next if length ($word_buf) > 7;

      $tmp_hash = gen_hash ($mode, $word_buf, "");
    }
    elsif ($mode == 3100)
    {
      next if length ($word_buf) > 30;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 10));
    }
    elsif ($mode == 3200 || $mode == 5800 || $mode == 6400 || $mode == 6500 || $mode == 6700 || $mode == 7400 || $mode == 3300 || $mode == 8000 || $mode == 9100 || $mode == 12001 || $mode == 12200 || $mode == 15600)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 16));
    }
    elsif ($mode == 3800 || $mode == 4900)
    {
      my $salt_len = get_random_num (1, 11);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 4520)
    {
      my $salt_len = get_random_num (1, 50);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 4521 || $mode == 15700)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 4522)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 12));
    }
    elsif ($mode == 4800)
    {
      $salt_buf = get_random_md5chap_salt (substr ($salt_buf, 0, 16));

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 5300 || $mode == 5400)
    {
      $salt_buf = get_random_ike_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 5500)
    {
      my $user_len   = get_random_num (0, 15);
      my $domain_len = get_random_num (0, 15);

      $salt_buf = get_random_netntlmv1_salt ($user_len, $domain_len);

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 5600)
    {
      my $user_len   = get_random_num (0, 15);
      my $domain_len = get_random_num (0, 15);

      $salt_buf = get_random_netntlmv2_salt ($user_len, $domain_len);

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 6600)
    {
      $salt_buf = get_random_agilekeychain_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 6800)
    {
      my $email_len = get_random_num (1, 15);

      my $email = "";

      for (my $i = 0; $i < $email_len; $i++)
      {
        $email .= get_random_chr (0x61, 0x7a);
      }

      $email .= '@trash-mail.com';

      $tmp_hash = gen_hash ($mode, $word_buf, $email);
    }
    elsif ($mode == 7000)
    {
      next if length ($word_buf) > 19;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 24));
    }
    elsif ($mode == 7100)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 64));
    }
    elsif ($mode == 7200)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 128));
    }
    elsif ($mode == 7300)
    {
      my $salt_len = get_random_num (32, 256);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 7500)
    {
      $salt_buf = get_random_kerberos5_salt (substr ($salt_buf, 0, 16));

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 7700 || $mode == 7701)
    {
      next if length ($word_buf) > 8;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 12));
    }
    elsif ($mode == 7800 || $mode == 7801)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 12));
    }
    elsif ($mode == 8200)
    {
      $salt_buf = get_random_cloudkeychain_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 8300)
    {
      $salt_buf = get_random_dnssec_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 8400 || $mode == 11200 || $mode == 16300)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 40));
    }
    elsif ($mode == 8500)
    {
      next if length ($word_buf) > 8;

      my $salt_len = get_random_num (1, 9);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 8600)
    {
      next if length ($word_buf) > 16;

      $tmp_hash = gen_hash ($mode, $word_buf, "");
    }
    elsif ($mode == 8700)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 5));
    }
    elsif ($mode == 9200 || $mode == 9300)
    {
      my $salt_len = 14;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 9400 || $mode == 9500 || $mode == 9600)
    {
      next if length ($word_buf) > 19;

      my $salt_len = 32;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 9700 || $mode == 9800)
    {
      next if length ($word_buf) > 15;

      my $salt_len = 32;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 10100)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 10300)
    {
      my $salt_len = get_random_num (4, 15);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 10400)
    {
      next if length ($word_buf) > 31;

      my $salt_len = 32;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 10500)
    {
      next if length ($word_buf) > 15;

      my $salt_len = 32;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 10600)
    {
      next if length ($word_buf) > 31;

      my $salt_len = 32;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 10700)
    {
      next if length ($word_buf) > 15;

      my $salt_len = 32;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 11000)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 56));
    }
    elsif ($mode == 11300)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 16));
    }
    elsif ($mode == 11400)
    {
      next if length ($word_buf) > 24;

      my $salt_len = get_random_num (1, 15);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 11600)
    {
      my $salt_len = get_random_num (0, 16);

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, $salt_len));
    }
    elsif ($mode == 12300)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 12400)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 4));
    }
    elsif ($mode == 12600 || $mode == 15000)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 64));
    }
    elsif ($mode == 12700)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 12800)
    {
      next if length ($word_buf) > 24;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 20));
    }
    elsif ($mode == 12900)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 13000)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 13100)
    {
      $salt_buf = get_random_kerberos5_tgs_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 13200)
    {
      $salt_buf = get_random_axcrypt_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 13400)
    {
      $salt_buf = get_random_keepass_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 13500)
    {
      $salt_buf = get_pstoken_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 13600)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 13800)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 256));
    }
    elsif ($mode == 13900)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 9));
    }
    elsif ($mode == 14000)
    {
      next if length ($word_buf) != 8;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 16));
    }
    elsif ($mode == 14100)
    {
      next if length ($word_buf) != 24;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 16));
    }
    elsif ($mode == 14400)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 20));
    }
    elsif (($mode == 14700) || ($mode == 14800))
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 40));
    }
    elsif ($mode == 14900)
    {
      next if length ($word_buf) != 10;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 8));
    }
    elsif ($mode == 15100)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 8));
    }
    elsif ($mode == 15200)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 15300 || $mode == 15900)
    {
      my $version = 2;

      if ($mode == 15300)
      {
        $version = 1;
      }

      $salt_buf = get_random_dpapimk_salt ($version);

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 15400)
    {
      next if length ($word_buf) != 32;

      $tmp_hash = gen_hash ($mode, $word_buf, "");
    }
    elsif ($mode == 15500)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 40));
    }
    elsif ($mode == 16000)
    {
      next if length ($word_buf) > 8;

      $tmp_hash = gen_hash ($mode, $word_buf, "");
    }
    elsif ($mode == 16100)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, undef);
    }
    elsif ($mode == 16200)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 16500)
    {
      $salt_buf = get_random_jwt_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 16600)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 16700)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 16800)
    {
      next if length ($word_buf) < 8;

      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 16900)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 64));
    }
    elsif ($mode == 18200)
    {
      $salt_buf = get_random_kerberos5_as_rep_salt ();

      $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);
    }
    elsif ($mode == 18300)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 18400)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    elsif ($mode == 18600)
    {
      $tmp_hash = gen_hash ($mode, $word_buf, substr ($salt_buf, 0, 32));
    }
    ## STEP 2c: Add your custom salt branch here
    else
    {
      print "ERROR: Unsupported hash type\n";

      exit (1);
    }

    print $tmp_hash, "\n";
  }
}

sub single
{
  my $mode = shift;

  if (defined $mode)
  {
    @{$MODES} = ($mode);
  }

  for (my $j = 0; $j < scalar @{$MODES}; $j++)
  {
    my $mode = $MODES->[$j];

    if (is_in_array ($mode, $COMMON_UNSALTED_MODES)
     || $mode == 5300 || $mode == 5400 || $mode ==  6600
     || $mode == 8200 || $mode == 8300 || $mode == 13300)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 0);
        }
        else
        {
          rnd ($mode, $i, 0);
        }
      }
    }
    elsif (is_in_array ($mode, $COMMON_DEFAULT_SALTED_MODES)
        || $mode ==   121 || $mode ==  1411 || $mode ==  1711 || $mode ==  3711
        || $mode ==  8900 || $mode == 10000 || $mode == 10200 || $mode == 10900
        || $mode == 11900 || $mode == 12000 || $mode == 12100 || $mode == 16500)
    {
      my $salt_len = get_random_num (1, 15);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 11 || $mode == 12)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 21 || $mode == 22)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 2);
        }
        else
        {
          rnd ($mode, $i, 2);
        }
      }
    }
    elsif ($mode ==  111 || $mode ==   122 || $mode ==  125 || $mode ==  131
        || $mode ==  132 || $mode ==   400 || $mode ==  500 || $mode == 1600
        || $mode == 1722 || $mode ==  1731 || $mode == 6300 || $mode == 7900
        || $mode == 8100 || $mode == 11100)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 8);
        }
        else
        {
          rnd ($mode, $i, 8);
        }
      }
    }
    elsif ($mode == 112)
    {
      for (my $i = 1; $i < 31; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 20);
        }
        else
        {
          rnd ($mode, $i, 20);
        }
      }
    }
    elsif ($mode ==   141 || $mode ==  3300 || $mode ==  1441 || $mode == 1800
        || $mode ==  3200 || $mode ==  4800 || $mode ==  6400 || $mode == 6500
        || $mode ==  6700 || $mode ==  7400 || $mode ==  8000 || $mode == 9100
        || $mode == 12001 || $mode == 12200 || $mode == 15600)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 1100)
    {
      my $salt_len = get_random_num (1, 19);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 1500)
    {
      for (my $i = 1; $i < 9; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 2);
        }
        else
        {
          rnd ($mode, $i, 2);
        }
      }
    }
    elsif ($mode == 2100)
    {
      my $salt_len = get_random_num (1, 19);

      for (my $i = 1; $i < 13; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 2400)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 0);
        }
        else
        {
          rnd ($mode, $i, 0);
        }
      }
    }
    elsif ($mode == 2410)
    {
      my $salt_len = get_random_num (3, 4);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 2500)
    {
      my $salt_len = get_random_num (0, 32);

      for (my $i = 8; $i < 16; $i++)
      {
        if ($len != 0)
        {
          if ($len < 8)
          {
            $len += 7;
          }

          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 2611)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 3);
        }
        else
        {
          rnd ($mode, $i, 3);
        }
      }
    }
    elsif ($mode == 2612)
    {
      my $salt_len = get_random_num (1, 22);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 2711)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 30);
        }
        else
        {
          rnd ($mode, $i, 30);
        }
      }
    }
    elsif ($mode == 2811)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 5);
        }
        else
        {
          rnd ($mode, $i, 5);
        }
      }
    }
    elsif ($mode == 3000)
    {
      for (my $i = 1; $i < 8; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 0);
        }
        else
        {
          rnd ($mode, $i, 0);
        }
      }
    }
    elsif ($mode == 3100)
    {
      for (my $i = 1; $i < 31; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 10);
        }
        else
        {
          rnd ($mode, $i, 10);
        }
      }
    }
    elsif ($mode == 3800 || $mode == 4900)
    {
      my $salt_len = get_random_num (1, 11);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 4520)
    {
      my $salt_len = get_random_num (1, 50);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 4521 || $mode == 15700)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 4522)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 12);
        }
        else
        {
          rnd ($mode, $i, 12);
        }
      }
    }
    elsif ($mode == 5500 || $mode == 5600)
    {
      my $salt_len;

      for (my $i = 1; $i < 27; $i++)
      {
        $salt_len = get_random_num (1, 15);

        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 5800)
    {
      for (my $i = 1; $i < 14; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 6800)
    {
      my $salt_len = get_random_num (8, 25);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 7000)
    {
      for (my $i = 1; $i < 19; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 24);
        }
        else
        {
          rnd ($mode, $i, 24);
        }
      }
    }
    elsif ($mode == 7100)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 64);
        }
        else
        {
          rnd ($mode, $i, 64);
        }
      }
    }
    elsif ($mode == 7200)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 128);
        }
        else
        {
          rnd ($mode, $i, 128);
        }
      }
    }
    elsif ($mode == 7300)
    {
      my $salt_len = get_random_num (32, 255);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 7500)
    {
      for (my $i = 1; $i < 27; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 7700 || $mode == 7701)
    {
      my $salt_len = get_random_num (1, 12);

      for (my $i = 1; $i < 9; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 7800 || $mode == 7801)
    {
      my $salt_len = get_random_num (1, 12);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 8400 || $mode == 11200 || $mode == 14700 || $mode == 14800 || $mode == 16300)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 40);
        }
        else
        {
          rnd ($mode, $i, 40);
        }
      }
    }
    elsif ($mode == 8500)
    {
      my $salt_len = get_random_num (1, 8);

      for (my $i = 1; $i < 9; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 8600)
    {
      for (my $i = 1; $i < 17; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 0);
        }
        else
        {
          rnd ($mode, $i, 0);
        }
      }
    }
    elsif ($mode == 8700)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 5);
        }
        else
        {
          rnd ($mode, $i, 5);
        }
      }
    }
    elsif ($mode == 9200 || $mode == 9300)
    {
      my $salt_len = 14;

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 9400 || $mode == 9500 || $mode == 9600)
    {
      my $salt_len = 32;

      for (my $i = 1; $i < 20; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 9700 || $mode == 9800)
    {
      my $salt_len = 32;

      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 10100)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 10300)
    {
      my $salt_len = get_random_num (4, 15);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 10400 || $mode == 10600)
    {
      my $salt_len = 32;

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 10500 || $mode == 10700)
    {
      my $salt_len = 32;

      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 11000)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 56);
        }
        else
        {
          rnd ($mode, $i, 56);
        }
      }
    }
    elsif ($mode == 11300)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 11400)
    {
      for (my $i = 1; $i < 24; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 11600)
    {
      my $salt_len = get_random_num (0, 16);

      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 12300)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 12400)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 4);
        }
        else
        {
          rnd ($mode, $i, 4);
        }
      }
    }
    elsif ($mode == 12600 || $mode == 15000)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 64);
        }
        else
        {
          rnd ($mode, $i, 64);
        }
      }
    }
    elsif ($mode == 12700)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 12800)
    {
      for (my $i = 1; $i < 25; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 20);
        }
        else
        {
          rnd ($mode, $i, 20);
        }
      }
    }
    elsif ($mode == 12900)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 13000)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 13100)
    {
      for (my $i = 1; $i < 27; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 13200)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 13400)
    {
      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 13500)
    {
      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 13600)
    {
      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 13800)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 256);
        }
        else
        {
          rnd ($mode, $i, 256);
        }
      }
    }
    elsif ($mode == 13900)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 9);
        }
        else
        {
          rnd ($mode, $i, 9);
        }
      }
    }
    elsif ($mode == 14000)
    {
      rnd ($mode,  8, 16);
    }
    elsif ($mode == 14100)
    {
      rnd ($mode, 24, 16);
    }
    elsif ($mode == 14400)
    {
      for (my $i = 1; $i < 24; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 20);
        }
        else
        {
          rnd ($mode, $i, 20);
        }
      }
    }
    elsif ($mode == 14900)
    {
      rnd ($mode, 10, 8);
    }
    elsif ($mode == 15100)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 8);
        }
        else
        {
          rnd ($mode, $i, 8);
        }
      }
    }
    elsif ($mode == 15200)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 15300 || $mode == 15900)
    {
      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 15400)
    {
      rnd ($mode, 32, 0);
    }
    elsif ($mode == 15500)
    {
      for (my $i = 1; $i < 16; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 40);
        }
        else
        {
          rnd ($mode, $i, 40);
        }
      }
    }
    elsif ($mode == 16000)
    {
      for (my $i = 1; $i < 9; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 0);
        }
        else
        {
          rnd ($mode, $i, 0);
        }
      }
    }
    elsif ($mode == 16100)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 0);
        }
        else
        {
          rnd ($mode, $i, 0);
        }
      }
    }
    elsif ($mode == 16200)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 16600)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 16700)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 16800)
    {
      my $salt_len = get_random_num (0, 32);

      for (my $i = 8; $i < 16; $i++)
      {
        if ($len != 0)
        {
          if ($len < 8)
          {
            $len += 7;
          }

          rnd ($mode, $len, $salt_len);
        }
        else
        {
          rnd ($mode, $i, $salt_len);
        }
      }
    }
    elsif ($mode == 16900)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 64);
        }
        else
        {
          rnd ($mode, $i, 64);
        }
      }
    }
    elsif ($mode == 18200)
    {
      for (my $i = 1; $i < 27; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 16);
        }
        else
        {
          rnd ($mode, $i, 16);
        }
      }
    }
    elsif ($mode == 18300)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 18400)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    elsif ($mode == 18600)
    {
      for (my $i = 1; $i < 32; $i++)
      {
        if ($len != 0)
        {
          rnd ($mode, $len, 32);
        }
        else
        {
          rnd ($mode, $i, 32);
        }
      }
    }
    ## STEP 2c: Add your custom salt branch here
  }
}

exit;

## STEP 3: Implement hash generation for your hash mode here.
#
# For an example of how to use python, see mode 11700.
# For an example of how to use PHP, see mode 11900.
#
# Don't forget to add the modules you depend on to the
# installation script.
#
##
sub gen_hash
{
  my $mode = shift;

  my $word_buf = shift;

  my $salt_buf = shift;

  my $iter = shift;

  my $additional_param = shift;

  my $additional_param2 = shift;

  my $additional_param3 = shift;

  my $additional_param4 = shift;

  my $additional_param5 = shift;

  my $additional_param6 = shift;

  my $additional_param7 = shift;

  my $additional_param8 = shift;

  my $additional_param9 = shift;

  my $additional_param10 = shift;

  my $additional_param11 = shift;

  ##
  ## gen hash
  ##

  my $tmp_hash;

  my $hash_buf;

  if ($mode == 0)
  {
    $hash_buf = md5_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 10)
  {
    $hash_buf = md5_hex ($word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 11)
  {
    $hash_buf = md5_hex ($word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 12)
  {
    $hash_buf = md5_hex ($word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 20)
  {
    $hash_buf = md5_hex ($salt_buf . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 21)
  {
    $hash_buf = md5_hex ($salt_buf . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 22)
  {
    my $itoa64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    my $salt_suffix = "Administration Tools";

    my $pass = sprintf ("%s:%s:%s", $salt_buf, $salt_suffix, $word_buf);

    $hash_buf = md5 ($pass);

    my $res = "";

    for (my $pos = 0; $pos < 16; $pos += 2)
    {
      my $octet1 = ord (substr ($hash_buf, $pos + 0, 1));
      my $octet2 = ord (substr ($hash_buf, $pos + 1, 1));

      my $num = ($octet1 <<8 & 0xff00) | ($octet2 & 0xff);

      my $idx1 = $num >> 12 & 0x0f;
      my $idx2 = $num >>  6 & 0x3f;
      my $idx3 = $num       & 0x3f;

      $res = $res . substr ($itoa64, $idx1, 1) . substr ($itoa64, $idx2, 1) . substr ($itoa64, $idx3, 1);
    }

    my $obfuscate_str = "nrcstn";
    my @obfuscate_pos = (0, 6, 12, 17, 23, 29);

    foreach my $pos (keys @obfuscate_pos)
    {
      my $idx = $obfuscate_pos[$pos];
      my $before = substr ($res, 0, $idx);
      my $char   = substr ($obfuscate_str, $pos, 1);
      my $after  = substr ($res, $idx);

      $res = sprintf ("%s%s%s", $before, $char, $after);
    }

    $tmp_hash = sprintf ("%s:%s", $res, $salt_buf);
  }
  elsif ($mode == 23)
  {
    $hash_buf = md5_hex ($salt_buf . "\nskyper\n" . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 30)
  {
    $hash_buf = md5_hex (encode ("UTF-16LE", $word_buf) . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 40)
  {
    $hash_buf = md5_hex ($salt_buf . encode ("UTF-16LE", $word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 50)
  {
    $hash_buf = hmac_hex ($salt_buf, $word_buf, \&md5, 64);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 60)
  {
    $hash_buf = hmac_hex ($word_buf, $salt_buf, \&md5, 64);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 100)
  {
    $hash_buf = sha1_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 101)
  {
    $hash_buf = sha1 ($word_buf);

    my $base64_buf = encode_base64 ($hash_buf, "");

    $tmp_hash = sprintf ("{SHA}%s", $base64_buf);
  }
  elsif ($mode == 110)
  {
    $hash_buf = sha1_hex ($word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 111)
  {
    $hash_buf = sha1 ($word_buf . $salt_buf);

    my $base64_buf = encode_base64 ($hash_buf . $salt_buf, "");

    $tmp_hash = sprintf ("{SSHA}%s", $base64_buf);
  }
  elsif ($mode == 112)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha1_hex ($word_buf . $salt_buf_bin);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 120)
  {
    $hash_buf = sha1_hex ($salt_buf . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 121)
  {
    $hash_buf = sha1_hex (lc ($salt_buf) . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 122)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha1_hex ($salt_buf_bin . $word_buf);

    $tmp_hash = sprintf ("%s%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 125)
  {
    my $signature = "01";

    my $salt_buf_bin = pack ("H*", $salt_buf . $signature);

    $hash_buf = sha1_hex ($salt_buf_bin . $word_buf);

    $tmp_hash = sprintf ("%s%s%s", $salt_buf, $signature, $hash_buf);
  }
  elsif ($mode == 130)
  {
    $hash_buf = sha1_hex (encode ("UTF-16LE", $word_buf) . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 131)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha1_hex (encode ("UTF-16LE", uc ($word_buf)) . $salt_buf_bin);

    $tmp_hash = sprintf ("0x0100%s%s%s", $salt_buf, "0" x 40, $hash_buf);
  }
  elsif ($mode == 132)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha1_hex (encode ("UTF-16LE", $word_buf) . $salt_buf_bin);

    $tmp_hash = sprintf ("0x0100%s%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 133)
  {
    $hash_buf = sha1 (encode ("UTF-16LE", $word_buf));

    $hash_buf = encode_base64 ($hash_buf, "");

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 140)
  {
    $hash_buf = sha1_hex ($salt_buf . encode ("UTF-16LE", $word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 141)
  {
    $hash_buf = sha1 ($salt_buf . encode ("UTF-16LE", $word_buf));

    my $base64_salt_buf = encode_base64 ($salt_buf, "");
    my $base64_hash_buf = encode_base64 ($hash_buf, "");

    $base64_hash_buf = substr ($base64_hash_buf, 0, 27);

    $tmp_hash = sprintf ("\$episerver\$*0*%s*%s", $base64_salt_buf, $base64_hash_buf);
  }
  elsif ($mode == 150)
  {
    $hash_buf = hmac_hex ($salt_buf, $word_buf, \&sha1, 64);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 160)
  {
    $hash_buf = hmac_hex ($word_buf, $salt_buf, \&sha1, 64);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 200)
  {
    my $ppr = Authen::Passphrase::MySQL323->new (passphrase => $word_buf);

    $hash_buf = $ppr->hash_hex;

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 300)
  {
    $hash_buf = substr (password41 ($word_buf), 1);

    $hash_buf = lc ($hash_buf); # useful for 'not matched' check only

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 400)
  {
    my $cost = 11;

    if (length ($iter))
    {
      $cost = $iter;
    }

    my $ppr = Authen::Passphrase::PHPass->new
    (
      cost => $cost,
      salt => $salt_buf,
      passphrase => $word_buf,
    );

    $hash_buf = $ppr->as_rfc2307;

    $tmp_hash = sprintf ("%s", substr ($hash_buf, 7));
  }
  elsif ($mode == 500)
  {
    my $iterations = 1000;

    if (defined ($iter))
    {
      if ($iter > 0)
      {
        $iterations = int ($iter);
      }
    }

    $hash_buf = md5_crypt ('$1$', $iterations, $word_buf, $salt_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 600)
  {
    $hash_buf = lc blake2b_hex ($word_buf);
    $tmp_hash = sprintf ("\$BLAKE2\$" . $hash_buf);
  }
  elsif ($mode == 900)
  {
    $hash_buf = md4_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1000)
  {
    $hash_buf = md4_hex (encode ("UTF-16LE", $word_buf));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1100)
  {
    $hash_buf = md4_hex (md4 (encode ("UTF-16LE", $word_buf)) . encode ("UTF-16LE", lc ($salt_buf)));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1300)
  {
    $hash_buf = sha224_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1400)
  {
    $hash_buf = sha256_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1410)
  {
    $hash_buf = sha256_hex ($word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1411)
  {
    $hash_buf = sha256_hex ($word_buf . $salt_buf);

    my $base64_buf = encode_base64 (pack ("H*", $hash_buf) . $salt_buf, "");

    $tmp_hash = sprintf ("{SSHA256}%s", $base64_buf);
  }
  elsif ($mode == 1420)
  {
    $hash_buf = sha256_hex ($salt_buf . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1430)
  {
    $hash_buf = sha256_hex (encode ("UTF-16LE", $word_buf) . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1440)
  {
    $hash_buf = sha256_hex ($salt_buf . encode ("UTF-16LE", $word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1441)
  {
    $hash_buf = sha256 ($salt_buf . encode ("UTF-16LE", $word_buf));

    my $base64_salt_buf = encode_base64 ($salt_buf, "");
    my $base64_hash_buf = encode_base64 ($hash_buf, "");

    $base64_hash_buf = substr ($base64_hash_buf, 0, 43);

    $tmp_hash = sprintf ("\$episerver\$*1*%s*%s", $base64_salt_buf, $base64_hash_buf);
  }
  elsif ($mode == 1450)
  {
    $hash_buf = hmac_hex ($salt_buf, $word_buf, \&sha256, 64);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1460)
  {
    $hash_buf = hmac_hex ($word_buf, $salt_buf, \&sha256, 64);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1500)
  {
    $hash_buf = crypt ($word_buf, $salt_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1600)
  {
    my $iterations = 1000;

    if (defined ($iter))
    {
      if ($iter > 0)
      {
        $iterations = int ($iter);
      }
    }

    $hash_buf = md5_crypt ('$apr1$', $iterations, $word_buf, $salt_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1700)
  {
    $hash_buf = sha512_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 1710 || $mode == 15000)
  {
    $hash_buf = sha512_hex ($word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1711)
  {
    $hash_buf = sha512_hex ($word_buf . $salt_buf);

    my $base64_buf = encode_base64 (pack ("H*", $hash_buf) . $salt_buf, "");

    $tmp_hash = sprintf ("{SSHA512}%s", $base64_buf);
  }
  elsif ($mode == 1720)
  {
    $hash_buf = sha512_hex ($salt_buf . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1730)
  {
    $hash_buf = sha512_hex (encode ("UTF-16LE", $word_buf) . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1740)
  {
    $hash_buf = sha512_hex ($salt_buf . encode ("UTF-16LE", $word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1722)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha512_hex ($salt_buf_bin . $word_buf);

    $tmp_hash = sprintf ("%s%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 1731)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha512_hex (encode ("UTF-16LE", $word_buf) . $salt_buf_bin);

    $tmp_hash = sprintf ("0x0200%s%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 1750)
  {
    $hash_buf = hmac_hex ($salt_buf, $word_buf, \&sha512, 128);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1760)
  {
    $hash_buf = hmac_hex ($word_buf, $salt_buf, \&sha512, 128);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 1800)
  {
    my $iterations = 5000;

    if (defined ($iter))
    {
      if ($iter > 0)
      {
        $iterations = int ($iter);
      }
    }

    $hash_buf = sha512_crypt ($iterations, $word_buf, $salt_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 2100)
  {
    my $iterations = 10240;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $salt = encode ("UTF-16LE", lc ($salt_buf));

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iterations,
      output_len => 16,
      salt_len   => length ($salt),
    );

    $hash_buf = unpack ("H*", $pbkdf2->PBKDF2 ($salt, md4 (md4 (encode ("UTF-16LE", $word_buf)) . $salt)));

    $tmp_hash = sprintf ("\$DCC2\$%i#%s#%s", $iterations, $salt_buf, $hash_buf);
  }
  elsif ($mode == 2400)
  {
    my $word_len = length ($word_buf);

    my $pad_len = ceil ($word_len / 16) * 16;

    my $hash_buf = Digest::MD5::md5 ($word_buf . "\0" x ($pad_len - $word_len));

    $tmp_hash = sprintf ("%s", pseudo_base64 ($hash_buf));
  }
  elsif ($mode == 2410)
  {
    my $word_salt_buf = $word_buf . $salt_buf;

    my $word_salt_len = length ($word_salt_buf);

    my $pad_len = ceil ($word_salt_len / 16) * 16;

    my $hash_buf = Digest::MD5::md5 ($word_buf . $salt_buf . "\0" x ($pad_len - $word_salt_len));

    $tmp_hash = sprintf ("%s:%s", pseudo_base64 ($hash_buf), $salt_buf);
  }
  elsif ($mode == 2500)
  {
    my ($bssid, $stmac, $snonce, $anonce, $eapol, $keyver, $eapol_len, $essid_len);

    if (! defined ($additional_param))
    {
      # random stuff

      $bssid  = randbytes (6);
      $stmac  = randbytes (6);
      $snonce = randbytes (32);
      $anonce = randbytes (32);

      $keyver = get_random_num (1, 4); # 1, 2 or 3

      # eapol:
      # should be "validly" generated, but in theory could be anything for us also:
      # $eapol = "\x00" x 121; # works too, but let's generate it correctly

      $eapol = gen_random_wpa_eapol ($keyver, $snonce);
    }
    else
    {
      $bssid  = $additional_param;
      $stmac  = $additional_param2;
      $snonce = $additional_param3;
      $anonce = $additional_param4;
      $keyver = $additional_param5;
      $eapol  = $additional_param6;
    }

    $eapol_len = length ($eapol);

    # constants

    my $iterations = 4096;

    #
    # START
    #

    # generate the Pairwise Master Key (PMK)

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iterations,
      output_len => 32,
    );

    my $pmk = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

    # Pairwise Transient Key (PTK) transformation

    my $ptk = wpa_prf_512 ($keyver, $pmk, $stmac, $bssid, $snonce, $anonce);

    # generate the Message Integrity Code (MIC)

    my $mic = "";

    if ($keyver == 1) # WPA1 => MD5
    {
      $mic = hmac ($eapol, $ptk, \&md5);
    }
    elsif ($keyver == 2) # WPA2 => SHA1
    {
      $mic = hmac ($eapol, $ptk, \&sha1);
    }
    elsif ($keyver == 3) # WPA2 => SHA256 + AES-CMAC
    {
      my $omac1 = Digest::CMAC->new ($ptk, 'Crypt::Rijndael');

      $omac1->add ($eapol);

      $mic = $omac1->digest;
    }

    $mic = substr ($mic, 0, 16);

    #
    # format the binary output
    #

    my $HCCAPX_VERSION = 4;

    # signature
    $hash_buf = "HCPX";

    # format version
    $hash_buf .= pack ("L<", $HCCAPX_VERSION);

    # authenticated
    $hash_buf .= pack ("C", 0);

    # essid length
    $essid_len = length ($salt_buf);
    $hash_buf .= pack ("C", $essid_len);

    # essid (NULL-padded up to the first 32 bytes)
    $hash_buf .= $salt_buf;
    $hash_buf .= "\x00" x (32 - $essid_len);

    # key version
    $hash_buf .= pack ("C", $keyver);

    # key mic
    $hash_buf .= $mic;

    # access point MAC
    $hash_buf .= $bssid;

    # access point nonce
    $hash_buf .= $snonce;

    # client MAC
    $hash_buf .= $stmac;

    # client nonce
    $hash_buf .= $anonce;

    # eapol length
    $hash_buf .= pack ("S<", $eapol_len);

    # eapol
    $hash_buf .= $eapol;
    $hash_buf .= "\x00" x (256 - $eapol_len);

    # base64 encode the output
    $tmp_hash = encode_base64 ($hash_buf, "");
  }
  elsif ($mode == 2600)
  {
    $hash_buf = md5_hex (md5_hex ($word_buf));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 2611)
  {
    $hash_buf = md5_hex (md5_hex ($word_buf) . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 2612)
  {
    my $salt_buf_hex = unpack ("H*", $salt_buf);

    $hash_buf = md5_hex (md5_hex ($word_buf) . $salt_buf);

    $tmp_hash = sprintf ("\$PHPS\$%s\$%s", $salt_buf_hex, $hash_buf);
  }
  elsif ($mode == 2711)
  {
    $hash_buf = md5_hex (md5_hex ($word_buf) . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 2811)
  {
    $hash_buf = md5_hex (md5_hex ($salt_buf) . md5_hex ($word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 3000)
  {
    my $ppr = Authen::Passphrase::LANManager->new ("passphrase" => $word_buf);

    $hash_buf = $ppr->hash_hex;

    $tmp_hash = sprintf ("%s", substr ($hash_buf, 0, 16));
  }
  elsif ($mode == 3100)
  {
    $hash_buf = oracle_hash ($salt_buf, $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 3200)
  {
    my $cost = "05";

    if (length ($iter))
    {
      $cost = $iter;
    }

    $tmp_hash = bcrypt ($word_buf, sprintf ('$2a$%s$%s$', $cost, en_base64 ($salt_buf)));
  }
  elsif ($mode == 3300)
  {
    my $iterations = 904;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $variant = "\$";

    if (defined ($additional_param))
    {
      $variant = $additional_param;
    }

    my $prefix = sprintf ("\$md5%srounds=%i\$%s", $variant, $iterations, $salt_buf);

    $iterations += 4096;

    $hash_buf = sun_md5 ($word_buf, $prefix, $iterations);

    $tmp_hash = sprintf ("%s\$%s", $prefix, $hash_buf);
  }
  elsif ($mode == 3500)
  {
    $hash_buf = md5_hex (md5_hex (md5_hex ($word_buf)));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 3610)
  {
    $hash_buf = md5_hex (md5_hex ($salt_buf) . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 3710)
  {
    $hash_buf = md5_hex ($salt_buf . md5_hex ($word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 3711)
  {
    $hash_buf = md5_hex ($salt_buf . "-" . md5_hex ($word_buf));

    $tmp_hash = sprintf ("\$B\$%s\$%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 3720)
  {
    $hash_buf = md5_hex ($word_buf . md5_hex ($salt_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 3800)
  {
    $hash_buf = md5_hex ($salt_buf . $word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 3910)
  {
    $hash_buf = md5_hex (md5_hex ($word_buf) . md5_hex ($salt_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 4010)
  {
    $hash_buf = md5_hex ($salt_buf . md5_hex ($salt_buf . $word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 4110)
  {
    $hash_buf = md5_hex ($salt_buf . md5_hex ($word_buf . $salt_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 4210)
  {
    $hash_buf = md5_hex ($salt_buf . "\x00" . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 4300)
  {
    $hash_buf = md5_hex (uc (md5_hex ($word_buf)));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 4400)
  {
    $hash_buf = md5_hex (sha1_hex ($word_buf));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 4500)
  {
    $hash_buf = sha1_hex (sha1_hex ($word_buf));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif (($mode == 4520) || ($mode == 4521) || ($mode == 4522))
  {
    $hash_buf = sha1_hex ($salt_buf . sha1_hex ($word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 4600)
  {
    $hash_buf = sha1_hex (sha1_hex (sha1_hex ($word_buf)));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 4700)
  {
    $hash_buf = sha1_hex (md5_hex ($word_buf));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 4800)
  {
    my $index = rindex ($salt_buf, ":");

    my $salt  = substr ($salt_buf, 0, $index);
    my $salt_bin  = pack ("H*", $salt);
    my $chap_sign = substr ($salt_buf, $index + 1);
    my $chap_sign_bin = pack ("H*", $chap_sign);

    $hash_buf = md5_hex ($chap_sign_bin . $word_buf . $salt_bin);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 4900)
  {
    $hash_buf = sha1_hex ($salt_buf . $word_buf . $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 5100)
  {
    my $pos;

    if (! defined ($additional_param))
    {
      $pos = 0;
    }
    else
    {
      $pos = $additional_param * 8 unless ($additional_param > 2);
    }

    $hash_buf = md5_hex ($word_buf);

    $tmp_hash = sprintf ("%s", substr ($hash_buf, $pos, 16));
  }
  elsif ($mode == 5300)
  {
    my @salt_arr = split (":", $salt_buf);

    my $msg_buf = pack ("H*", $salt_arr[0] . $salt_arr[1] . $salt_arr[2] . $salt_arr[3] . $salt_arr[4] . $salt_arr[5]);
    my $nr_buf  = pack ("H*", $salt_arr[6] . $salt_arr[7]);

    my $hash_buf = hmac  ($nr_buf , $word_buf, \&md5, 64);
    $hash_buf = hmac_hex ($msg_buf, $hash_buf, \&md5, 64);

    $tmp_hash = sprintf ("%s:%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 5400)
  {
    my @salt_arr = split (":", $salt_buf);

    my $msg_buf = pack ("H*", $salt_arr[0] . $salt_arr[1] . $salt_arr[2] . $salt_arr[3] . $salt_arr[4] . $salt_arr[5]);
    my $nr_buf  = pack ("H*", $salt_arr[6] . $salt_arr[7]);

    my $hash_buf = hmac  ($nr_buf , $word_buf, \&sha1, 64);
    $hash_buf = hmac_hex ($msg_buf, $hash_buf, \&sha1, 64);

    $tmp_hash = sprintf ("%s:%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 5500)
  {
    my $index1 = index  ($salt_buf, "::");
    my $user   = substr ($salt_buf, 0, $index1);

    my $index2 = index  ($salt_buf, ":", $index1 + 2);
    my $domain = substr ($salt_buf, $index1 + 2, $index2 - $index1 - 2);

    my $len = length (substr ($salt_buf, $index2 + 1));

    my $c_challenge_hex;

    if ($len > 32)
    {
      $c_challenge_hex = substr ($salt_buf, $index2 +  1, 48);
      $index2 += 32;
    }
    else
    {
      $c_challenge_hex  = substr ($salt_buf, $index2 +  1, 16);
      $c_challenge_hex .= 00 x 32;
    }

    my $c_challenge     = pack   ("H*", substr ($c_challenge_hex, 0, 16));
    my $s_challenge_hex = substr ($salt_buf, $index2 + 17, 16);
    my $s_challenge     = pack   ("H*", $s_challenge_hex);

    my $challenge = substr (md5 ($s_challenge . $c_challenge), 0, 8);

    my $ntresp;

    my $nthash = Authen::Passphrase::NTHash->new (passphrase => $word_buf)->hash . "\x00" x 5;

    $ntresp .= Crypt::ECB::encrypt (setup_des_key (substr ($nthash,  0, 7)), "DES", $challenge, "none");
    $ntresp .= Crypt::ECB::encrypt (setup_des_key (substr ($nthash,  7, 7)), "DES", $challenge, "none");
    $ntresp .= Crypt::ECB::encrypt (setup_des_key (substr ($nthash, 14, 7)), "DES", $challenge, "none");

    $tmp_hash = sprintf ("%s::%s:%s:%s:%s", $user, $domain, $c_challenge_hex, unpack ("H*", $ntresp), $s_challenge_hex);
  }
  elsif ($mode == 5600)
  {
    my $index1 = index  ($salt_buf, "::");
    my $user   = substr ($salt_buf, 0, $index1);

    my $index2 = index  ($salt_buf, ":", $index1 + 2);
    my $domain = substr ($salt_buf, $index1 + 2, $index2 - $index1 - 2);

    my $s_challenge_hex = substr ($salt_buf, $index2 + 1, 16);
    my $s_challenge     = pack   ("H*", $s_challenge_hex);

    my $temp_hex = substr ($salt_buf, $index2 + 17);
    my $temp     = pack   ("H*", $temp_hex);

    my $nthash   = Authen::Passphrase::NTHash->new (passphrase => $word_buf)->hash;
    my $identity = Encode::encode ("UTF-16LE", uc ($user) . $domain);

    $hash_buf = hmac_hex ($s_challenge . $temp, hmac ($identity, $nthash, \&md5, 64), \&md5, 64);

    $tmp_hash = sprintf ("%s::%s:%s:%s:%s", $user, $domain, $s_challenge_hex, $hash_buf, $temp_hex);
  }
  elsif ($mode == 5700)
  {
    $hash_buf = sha256 ($word_buf);

    my $base64_buf = encode_base64 ($hash_buf, "");

    $tmp_hash = "";

    for (my $i = 0; $i < 43; $i++)
    {
      $tmp_hash .= $CISCO_BASE64_MAPPING->{substr ($base64_buf, $i, 1)};
    }
  }
  elsif ($mode == 5800)
  {
    $hash_buf = androidpin_hash ($word_buf, $salt_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 6000)
  {
    $hash_buf = ripemd160_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 6100)
  {
    $hash_buf = whirlpool_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 6300)
  {
    my $iterations = 1000; # hard coded by the AIX format

    $hash_buf = md5_crypt ('', $iterations, $word_buf, $salt_buf);

    $tmp_hash = sprintf ("{smd5}%s", $hash_buf);
  }
  elsif ($mode == 6400)
  {
    my $iterations = 64;

    if (length ($iter))
    {
      $iterations = 1 << int ($iter);
    }

    $hash_buf = aix_ssha256_pbkdf2 ($word_buf, $salt_buf, $iterations);

    $tmp_hash = sprintf ("{ssha256}%02i\$%s\$%s", log ($iterations) / log (2), $salt_buf, $hash_buf);
  }
  elsif ($mode == 6500)
  {
    my $iterations = 64;

    if (length ($iter))
    {
      $iterations = 1 << int ($iter);
    }

    $hash_buf = aix_ssha512_pbkdf2 ($word_buf, $salt_buf, $iterations);

    $tmp_hash = sprintf ("{ssha512}%02i\$%s\$%s", log ($iterations) / log (2), $salt_buf, $hash_buf);
  }
  elsif ($mode == 6600)
  {
    my $iterations = 1000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $salt_hex = substr ($salt_buf, 0, 16);
    my $salt     = pack   ("H*", $salt_hex);

    my $prefix   = substr ($salt_buf, 16, 2016);

    my $iv_hex   = substr ($salt_buf, 2032);
    my $iv       = pack ("H*", $iv_hex);

    my $data = pack ("H*", "10101010101010101010101010101010");

    my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

    my $pbkdf2 = Crypt::PBKDF2->new (
      hasher       => $hasher,
      iterations   => $iterations,
      output_len   => 16
    );

    my $key = $pbkdf2->PBKDF2 ($salt, $word_buf);

    my $cipher = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $iv,
      literal_key => 1,
      header      => "none",
      keysize     => 16
    });

    my $encrypted = unpack ("H*", $cipher->encrypt ($data));

    $hash_buf  = substr ($encrypted, 0, 32);

    $tmp_hash = sprintf ("%i:%s:%s%s%s", $iterations, $salt_hex, $prefix, $iv_hex, $hash_buf);
  }
  elsif ($mode == 6700)
  {
    my $iterations = 64;

    if (length ($iter))
    {
      $iterations = 1 << int ($iter);
    }

    $hash_buf = aix_ssha1_pbkdf2 ($word_buf, $salt_buf, $iterations);

    $tmp_hash = sprintf ("{ssha1}%02i\$%s\$%s", log ($iterations) / log (2), $salt_buf, $hash_buf);
  }
  elsif ($mode == 6800)
  {
    my $variant = $additional_param;

    if (! defined ($variant))
    {
      $variant = int (rand (2));
    }

    my $iterations = 500;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256);

    my $pbkdf2 = Crypt::PBKDF2->new (
      hasher       => $hasher,
      iterations   => $iterations,
      output_len   => 32
    );

    my $key = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

    my $cipher = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $iv,
      literal_key => 1,
      header      => "none",
      keysize     => 32
    });

    if ($variant == 1)
    {
      my $encrypt = $cipher->encrypt (substr ($salt_buf, 0, 16));

      $hash_buf = substr (unpack ("H*", $encrypt), 0, 32);
    }
    else
    {
      my $verifier = "lastpass rocks\x02\x02";

      $hash_buf = unpack ("H*", substr ($cipher->encrypt ($verifier), 0, 16));
    }

    $tmp_hash = sprintf ("%s:%i:%s", $hash_buf, $iterations, $salt_buf);
  }
  elsif ($mode == 6900)
  {
    $hash_buf = gost_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 7000)
  {
    my $FORTIGATE_SIGNATURE = "AK1";
    my $FORTIGATE_MAGIC     = pack ("H*", "a388ba2e424cb04a537930c13107cc3fa1329029a9815b70");

    my $salt_bin = pack ("H*", $salt_buf);

    my $hash = sha1 ($salt_bin . $word_buf . $FORTIGATE_MAGIC);

    $hash = encode_base64 ($salt_bin . $hash, "");

    $tmp_hash = sprintf ("%s%s", $FORTIGATE_SIGNATURE, $hash);
  }
  elsif ($mode == 7100)
  {
    my $iterations = 1024;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
      iterations => $iterations
    );

    $hash_buf = unpack ("H*", $pbkdf2->PBKDF2 (pack ("H*", $salt_buf), $word_buf));

    $tmp_hash = sprintf ("\$ml\$%i\$%s\$%0128s", $iterations, $salt_buf, $hash_buf);
  }
  elsif ($mode == 7200)
  {
    my $iterations = 1024;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $pbkdf2 = Crypt::PBKDF2->new (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
      iterations => $iterations
    );

    $hash_buf = unpack ("H*", $pbkdf2->PBKDF2 (pack ("H*", $salt_buf), $word_buf));

    $tmp_hash = sprintf ("grub.pbkdf2.sha512.%i.%s.%0128s", $iterations, $salt_buf, $hash_buf);
  }
  elsif ($mode == 7300)
  {
    $hash_buf = hmac_hex ($salt_buf, $word_buf, \&sha1);

    $tmp_hash = sprintf ("%s:%s", unpack ("H*", $salt_buf), $hash_buf);
  }
  elsif ($mode == 7400)
  {
    my $iterations = 5000;

    if (defined ($iter))
    {
      if ($iter > 0)
      {
        $iterations = int ($iter);
      }
    }

    $hash_buf = sha256_crypt ($iterations, $word_buf, $salt_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 7500)
  {
    my @salt_arr = split ("\\\$", $salt_buf);

    my $user = $salt_arr[0];

    my $realm = $salt_arr[1];

    my $salt = $salt_arr[2];

    my $hmac_salt = $salt_arr[3];
    my $hmac_salt_bin = pack ("H*", $hmac_salt);

    my $clear_data = $salt_arr[4];

    my $k = md4 (encode ("UTF-16LE", $word_buf));

    my $k1 = hmac_md5 ("\x01\x00\x00\x00", $k);

    my $k3 = hmac_md5 ($hmac_salt_bin, $k1);

    if (length ($clear_data) > 1)
    {
      my $clear_data_bin = pack ("H*", $clear_data);

      $hash_buf = RC4 ($k3, $clear_data_bin);
    }
    else
    {
      my $hash = $salt_arr[5];

      my $hash_bin = pack ("H*", $hash);

      my $clear_data = RC4 ($k3, $hash_bin);

      my $timestamp = substr ($clear_data, 14, 14);

      my $is_numeric = 1;

      if ($timestamp !~ /^[[:digit:]]{14}$/)
      {
        $is_numeric = 0;
      }

      if (! $is_numeric)
      {
        $hash_buf = "\x00" x 36;

        if ($hash_buf eq $hash_bin)
        {
          $hash_buf = "\x01" x 36;
        }
      }
      else
      {
        $hash_buf = $hash_bin;
      }
    }

    $tmp_hash = sprintf ("\$krb5pa\$23\$%s\$%s\$%s\$%s%s", $user, $realm, $salt, unpack ("H*", $hash_buf), $hmac_salt);
  }
  elsif ($mode == 7700 || $mode == 7701)
  {
    $word_buf = uc $word_buf;
    $salt_buf = uc $salt_buf;

    my $word_buf_t = sapb_transcode ($word_buf);
    my $salt_buf_t = sapb_transcode ($salt_buf);

    my $digest1 = md5 ($word_buf_t . $salt_buf_t);

    my $data = sapb_waldorf ($digest1, $word_buf_t, $salt_buf_t);

    my $digest2 = md5 ($data);

    my ($a, $b, $c, $d) = unpack ("N4", $digest2);

    $a ^= $c;
    $b ^= $d;

    if ($mode == 7700)
    {
      $tmp_hash = sprintf ("%s\$%08X%08X", $salt_buf, $a, $b);
    }
    else
    {
      $tmp_hash = sprintf ("%s\$%08X%08X", $salt_buf, $a, 0);
    }
  }
  elsif ($mode == 7800 || $mode == 7801)
  {
    my $theMagicArray_s =
      "\x91\xac\x51\x14\x9f\x67\x54\x43\x24\xe7\x3b\xe0\x28\x74\x7b\xc2" .
      "\x86\x33\x13\xeb\x5a\x4f\xcb\x5c\x08\x0a\x73\x37\x0e\x5d\x1c\x2f" .
      "\x33\x8f\xe6\xe5\xf8\x9b\xae\xdd\x16\xf2\x4b\x8d\x2c\xe1\xd4\xdc" .
      "\xb0\xcb\xdf\x9d\xd4\x70\x6d\x17\xf9\x4d\x42\x3f\x9b\x1b\x11\x94" .
      "\x9f\x5b\xc1\x9b\x06\x05\x9d\x03\x9d\x5e\x13\x8a\x1e\x9a\x6a\xe8" .
      "\xd9\x7c\x14\x17\x58\xc7\x2a\xf6\xa1\x99\x63\x0a\xd7\xfd\x70\xc3" .
      "\xf6\x5e\x74\x13\x03\xc9\x0b\x04\x26\x98\xf7\x26\x8a\x92\x93\x25" .
      "\xb0\xa2\x0d\x23\xed\x63\x79\x6d\x13\x32\xfa\x3c\x35\x02\x9a\xa3" .
      "\xb3\xdd\x8e\x0a\x24\xbf\x51\xc3\x7c\xcd\x55\x9f\x37\xaf\x94\x4c" .
      "\x29\x08\x52\x82\xb2\x3b\x4e\x37\x9f\x17\x07\x91\x11\x3b\xfd\xcd";

    $salt_buf = uc $salt_buf;

    my $digest = sha1 ($word_buf . $salt_buf);

    my ($a, $b, $c, $d, $e) = unpack ("I*", $digest);

    my $lengthMagicArray = 0x20;
    my $offsetMagicArray = 0;

    $lengthMagicArray += (($a >>  0) & 0xff) % 6;
    $lengthMagicArray += (($a >>  8) & 0xff) % 6;
    $lengthMagicArray += (($a >> 16) & 0xff) % 6;
    $lengthMagicArray += (($a >> 24) & 0xff) % 6;
    $lengthMagicArray += (($b >>  0) & 0xff) % 6;
    $lengthMagicArray += (($b >>  8) & 0xff) % 6;
    $lengthMagicArray += (($b >> 16) & 0xff) % 6;
    $lengthMagicArray += (($b >> 24) & 0xff) % 6;
    $lengthMagicArray += (($c >>  0) & 0xff) % 6;
    $lengthMagicArray += (($c >>  8) & 0xff) % 6;
    $offsetMagicArray += (($c >> 16) & 0xff) % 8;
    $offsetMagicArray += (($c >> 24) & 0xff) % 8;
    $offsetMagicArray += (($d >>  0) & 0xff) % 8;
    $offsetMagicArray += (($d >>  8) & 0xff) % 8;
    $offsetMagicArray += (($d >> 16) & 0xff) % 8;
    $offsetMagicArray += (($d >> 24) & 0xff) % 8;
    $offsetMagicArray += (($e >>  0) & 0xff) % 8;
    $offsetMagicArray += (($e >>  8) & 0xff) % 8;
    $offsetMagicArray += (($e >> 16) & 0xff) % 8;
    $offsetMagicArray += (($e >> 24) & 0xff) % 8;

    my $hash_buf = sha1_hex ($word_buf . substr ($theMagicArray_s, $offsetMagicArray, $lengthMagicArray) . $salt_buf);

    if ($mode == 7800)
    {
      $tmp_hash = sprintf ("%s\$%s", $salt_buf, uc $hash_buf);
    }
    else
    {
      $tmp_hash = sprintf("%s\$%.20s%020X", $salt_buf, uc $hash_buf, 0);
    }
  }
  elsif ($mode == 7900)
  {
    my $cost = 14;

    if (length ($iter))
    {
      $cost = $iter;
    }

    my $phpass_it = 1 << $cost;

    $hash_buf = sha512 ($salt_buf . $word_buf);

    for (my $i = 0; $i < $phpass_it; $i++)
    {
      $hash_buf = sha512 ($hash_buf . $word_buf);
    }

    my $base64_buf = substr (Authen::Passphrase::PHPass::_en_base64 ($hash_buf), 0, 43);

    my $base64_digits = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    my $cost_str = substr ($base64_digits , $cost, 1);

    $tmp_hash = sprintf ('$S$%s%s%s', $cost_str, $salt_buf, $base64_buf);
  }
  elsif ($mode == 8000)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $word_buf_utf = encode ("UTF-16BE", $word_buf);

    $hash_buf = sha256_hex ($word_buf_utf . "\x00" x (510 - (length ($word_buf) * 2)) . $salt_buf_bin);

    $tmp_hash = sprintf ("0xc007%s%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 8100)
  {
    $hash_buf = sha1_hex ($salt_buf . $word_buf . "\x00");

    $tmp_hash = sprintf ("1%s%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 8200)
  {
    my $iterations = 40000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $salt_hex = substr ($salt_buf, 0, 32);
    my $salt     = pack   ("H*", $salt_hex);

    my $data_hex = substr ($salt_buf, 32);
    my $data     = pack   ("H*", $data_hex);

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
      iterations => int $iterations
    );

    my $key = $pbkdf2->PBKDF2 ($salt, $word_buf);

    $hash_buf = hmac_hex ($data, substr ($key, 32, 32), \&sha256, 64);

    $tmp_hash = sprintf ("%s:%s:%d:%s", $hash_buf, $salt_hex, $iterations, $data_hex);
  }
  elsif ($mode == 8300)
  {
    my ($domain, $salt_hex) = split (":", $salt_buf);

    my $hashalg = Net::DNS::SEC->digtype ("SHA1");

    my $salt = pack ("H*", $salt_hex);

    my $iterations = 1;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $name = lc ($word_buf . $domain);

    my $hash_buf = Net::DNS::RR::NSEC3::name2hash ($hashalg, $name, $iterations, $salt);

    $tmp_hash = sprintf ("%s:%s:%s:%d", $hash_buf, $domain, $salt_hex, $iterations);
  }
  elsif ($mode == 8400 || $mode == 13900)
  {
    $hash_buf = sha1_hex ($salt_buf . sha1_hex ($salt_buf . sha1_hex ($word_buf)));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 8500)
  {
    $hash_buf = racf_hash (uc $salt_buf, $word_buf);

    $tmp_hash = sprintf ('$racf$*%s*%s', uc $salt_buf, uc $hash_buf);
  }
  elsif ($mode == 8600)
  {
    my @saved_key = map { ord $_; } split "", $word_buf;

    my $len = scalar @saved_key;

    my @state = domino_big_md (\@saved_key, $len);

    $tmp_hash = sprintf ('%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x',
      $state[ 0],
      $state[ 1],
      $state[ 2],
      $state[ 3],
      $state[ 4],
      $state[ 5],
      $state[ 6],
      $state[ 7],
      $state[ 8],
      $state[ 9],
      $state[10],
      $state[11],
      $state[12],
      $state[13],
      $state[14],
      $state[15],
    );
  }
  elsif ($mode == 8700)
  {
    my $domino_char = undef;

    if (defined ($additional_param))
    {
      $domino_char = $additional_param;
    }

    my @saved_key = map { ord $_; } split "", $word_buf;

    my $len = scalar @saved_key;

    my @state = domino_big_md (\@saved_key, $len);

    my $str = "(" . unpack ("H*", join ("", (map { chr $_; } @state))) . ")";

    @saved_key = map { ord $_; } split "", $salt_buf . uc $str;

    @state = domino_big_md (\@saved_key, 34);

    $hash_buf = join ("", (map { chr $_; } @state));

    $tmp_hash = sprintf ('(G%s)', domino_encode ($salt_buf . $hash_buf, $domino_char));
  }
  elsif ($mode == 8900)
  {
    my $N = 1024;
    my $r = 1;
    my $p = 1;

    if (defined ($additional_param))
    {
      $N = $additional_param;
      $r = $additional_param2;
      $p = $additional_param3;
    }

    $hash_buf = scrypt_hash ($word_buf, $salt_buf, $N, $r, $p, 32);

    $tmp_hash = sprintf ('%s', $hash_buf);
  }
  elsif ($mode == 9100)
  {
    my $iterations = 5000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $domino_char = undef;

    # domino 5 hash - SEC_pwddigest_V1 - -m 8600

    my @saved_key = map { ord $_; } split "", $word_buf;

    my $len = scalar @saved_key;

    my @state = domino_big_md (\@saved_key, $len);


    # domino 6 hash - SEC_pwddigest_V2 - -m 8700

    my $salt_part = substr ($salt_buf, 0, 5);

    my $str = "(" . unpack ("H*", join ("", (map { chr $_; } @state))) . ")";

    @saved_key = map { ord $_; } split "", $salt_part . uc $str;

    @state = domino_big_md (\@saved_key, 34);

    $hash_buf = join ("", (map { chr $_; } @state));

    $tmp_hash = sprintf ('(G%s)', domino_encode ($salt_part . $hash_buf, $domino_char));


    # domino 8(.5.x) hash - SEC_pwddigest_V3 - -m 9100

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iterations,
      output_len =>  8,
      salt_len   => 16,
    );

    my $chars = "02";

    if (defined ($additional_param))
    {
      $chars = $additional_param;
    }

    my $digest_new = $pbkdf2->PBKDF2 ($salt_buf, $tmp_hash);

    for (my $i = length ($iterations); $i < 10; $i++)
    {
      $iterations = "0" . $iterations;
    }

    $tmp_hash = sprintf ('(H%s)', domino_85x_encode ($salt_buf . $iterations . $chars . $digest_new, $domino_char));
  }
  elsif ($mode == 9200)
  {
    my $iterations = 20000;

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations
    );

    $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt_buf, $word_buf), "");

    $tmp_hash = "";

    for (my $i = 0; $i < 43; $i++)
    {
      $tmp_hash .= $CISCO_BASE64_MAPPING->{substr ($hash_buf, $i, 1)};
    }

    $tmp_hash = sprintf ("\$8\$%s\$%s", $salt_buf, $tmp_hash);
  }
  elsif ($mode == 9300)
  {
    my $N = 16384;
    my $r = 1;
    my $p = 1;

    $hash_buf = scrypt_b64 ($word_buf, $salt_buf, $N, $r, $p, 32);

    $tmp_hash = "";

    for (my $i = 0; $i < 43; $i++)
    {
      $tmp_hash .= $CISCO_BASE64_MAPPING->{substr ($hash_buf, $i, 1)};
    }

    $tmp_hash = sprintf ('$9$%s$%s', $salt_buf, $tmp_hash);
  }
  elsif ($mode == 9400)
  {
    my $iterations = 50000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $aes_key_size = 128; # or 256

    if (defined ($additional_param2))
    {
      $aes_key_size = $additional_param2;
    }

    $salt_buf = pack ("H*", $salt_buf);

    my $tmp = sha1 ($salt_buf . encode ("UTF-16LE", $word_buf));

    for (my $i = 0; $i < $iterations; $i++)
    {
      my $num32 = pack ("L", $i);

      $tmp = sha1 ($num32 . $tmp);
    }

    my $zero32    = pack ("L", 0x00);

    my $derivation_array1 = pack ("C", 0x36) x 64;
    my $derivation_array2 = pack ("C", 0x5C) x 64;

    $tmp = sha1 ($tmp . $zero32);

    my $tmp2 = sha1 ($derivation_array1 ^ $tmp);
    my $tmp3 = sha1 ($derivation_array2 ^ $tmp);

    my $key = substr ($tmp2 . $tmp3, 0, $aes_key_size / 8);

    my $m = Crypt::Mode::ECB->new ('AES', 0);

    my $encdata;

    if (defined $additional_param)
    {
      $encdata = $m->decrypt (pack ("H*", $additional_param), $key);
    }
    else
    {
      $encdata = "A" x 16; ## can be anything
    }

    my $data1_buf = $encdata;
    my $data2_buf = sha1 (substr ($data1_buf, 0, 16));

    $data1_buf = substr ($data1_buf . ("\x00" x 16), 0, 16);
    $data2_buf = substr ($data2_buf . ("\x00" x 16), 0, 32);

    my $encrypted1 = unpack ("H*", $m->encrypt ($data1_buf, $key));
    my $encrypted2 = unpack ("H*", $m->encrypt ($data2_buf, $key));

    $encrypted1 = substr ($encrypted1, 0, 32);
    $encrypted2 = substr ($encrypted2, 0, 40);

    $tmp_hash = sprintf ("\$office\$*%d*%d*%d*%d*%s*%s*%s", 2007, 20, $aes_key_size, 16, unpack ("H*", $salt_buf), $encrypted1, $encrypted2);
  }
  elsif ($mode == 9500)
  {
    my $iterations = 100000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    $salt_buf = pack ("H*", $salt_buf);

    my $tmp = sha1 ($salt_buf . encode ("UTF-16LE", $word_buf));

    for (my $i = 0; $i < $iterations; $i++)
    {
      my $num32 = pack ("L", $i);

      $tmp = sha1 ($num32 . $tmp);
    }

    my $encryptedVerifierHashInputBlockKey = "\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79";
    my $encryptedVerifierHashValueBlockKey = "\xd7\xaa\x0f\x6d\x30\x61\x34\x4e";

    my $final1 = sha1 ($tmp . $encryptedVerifierHashInputBlockKey);
    my $final2 = sha1 ($tmp . $encryptedVerifierHashValueBlockKey);

    my $key1 = substr ($final1, 0, 16);
    my $key2 = substr ($final2, 0, 16);

    my $cipher1 = Crypt::CBC->new ({
      key         => $key1,
      cipher      => "Crypt::Rijndael",
      iv          => $salt_buf,
      literal_key => 1,
      header      => "none",
      keysize     => 16,
      padding     => "null",
    });

    my $cipher2 = Crypt::CBC->new ({
      key         => $key2,
      cipher      => "Crypt::Rijndael",
      iv          => $salt_buf,
      literal_key => 1,
      header      => "none",
      keysize     => 16,
      padding     => "null",
    });

    my $encdata;

    if (defined $additional_param)
    {
      $encdata = $cipher1->decrypt (pack ("H*", $additional_param));
    }
    else
    {
      $encdata = "A" x 16; ## can be anything
    }

    my $data1_buf = $encdata;
    my $data2_buf = sha1 (substr ($data1_buf, 0, 16));

    my $encrypted1 = unpack ("H*", $cipher1->encrypt ($data1_buf));
    my $encrypted2 = unpack ("H*", $cipher2->encrypt ($data2_buf));

    $encrypted2 = substr ($encrypted2, 0, 64);

    $tmp_hash = sprintf ("\$office\$*%d*%d*%d*%d*%s*%s*%s", 2010, 100000, 128, 16, unpack ("H*", $salt_buf), $encrypted1, $encrypted2);
  }
  elsif ($mode == 9600)
  {
    my $iterations = 100000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    $salt_buf = pack ("H*", $salt_buf);

    my $tmp = sha512 ($salt_buf . encode ("UTF-16LE", $word_buf));

    for (my $i = 0; $i < $iterations; $i++)
    {
      my $num32 = pack ("L", $i);

      $tmp = sha512 ($num32 . $tmp);
    }

    my $encryptedVerifierHashInputBlockKey = "\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79";
    my $encryptedVerifierHashValueBlockKey = "\xd7\xaa\x0f\x6d\x30\x61\x34\x4e";

    my $final1 = sha512 ($tmp . $encryptedVerifierHashInputBlockKey);
    my $final2 = sha512 ($tmp . $encryptedVerifierHashValueBlockKey);

    my $key1 = substr ($final1, 0, 32);
    my $key2 = substr ($final2, 0, 32);

    my $cipher1 = Crypt::CBC->new ({
      key         => $key1,
      cipher      => "Crypt::Rijndael",
      iv          => $salt_buf,
      literal_key => 1,
      header      => "none",
      keysize     => 32,
      padding     => "null",
    });

    my $cipher2 = Crypt::CBC->new ({
      key         => $key2,
      cipher      => "Crypt::Rijndael",
      iv          => $salt_buf,
      literal_key => 1,
      header      => "none",
      keysize     => 32,
      padding     => "null",
    });

    my $encdata;

    if (defined $additional_param)
    {
      $encdata = $cipher1->decrypt (pack ("H*", $additional_param));
    }
    else
    {
      $encdata = "A" x 16; ## can be anything
    }

    my $data1_buf = $encdata;
    my $data2_buf = sha512 (substr ($data1_buf, 0, 16));

    my $encrypted1 = unpack ("H*", $cipher1->encrypt ($data1_buf));
    my $encrypted2 = unpack ("H*", $cipher2->encrypt ($data2_buf));

    $encrypted2 = substr ($encrypted2, 0, 64);

    $tmp_hash = sprintf ("\$office\$*%d*%d*%d*%d*%s*%s*%s", 2013, 100000, 256, 16, unpack ("H*", $salt_buf), $encrypted1, $encrypted2);
  }
  elsif ($mode == 9700)
  {
    $salt_buf = pack ("H*", $salt_buf);

    my $tmp = md5 (encode ("UTF-16LE", $word_buf));

    $tmp = substr ($tmp, 0, 5);

    my $data;

    for (my $i = 0; $i < 16; $i++)
    {
      $data .= $tmp;
      $data .= $salt_buf;
    }

    $tmp = md5 ($data);

    $tmp = substr ($tmp, 0, 5);

    my $version;

    if (defined $additional_param2)
    {
      $version = $additional_param2;
    }
    else
    {
      $version = (unpack ("L", $tmp) & 1) ? 0 : 1;
    }

    my $rc4_key = md5 ($tmp . "\x00\x00\x00\x00");

    my $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

    my $encdata;

    if (defined $additional_param)
    {
      $encdata = $m->RC4 (pack ("H*", $additional_param));
    }
    else
    {
      $encdata = "A" x 16; ## can be anything
    }

    my $data1_buf = $encdata;
    my $data2_buf = md5 (substr ($data1_buf, 0, 16));

    $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

    my $encrypted1 = $m->RC4 ($data1_buf);
    my $encrypted2 = $m->RC4 ($data2_buf);

    $tmp_hash = sprintf ("\$oldoffice\$%d*%s*%s*%s", $version, unpack ("H*", $salt_buf), unpack ("H*", $encrypted1), unpack ("H*", $encrypted2));
  }
  elsif ($mode == 9800)
  {
    $salt_buf = pack ("H*", $salt_buf);

    my $tmp = sha1 ($salt_buf. encode ("UTF-16LE", $word_buf));

    my $version;

    if (defined $additional_param2)
    {
      $version = $additional_param2;
    }
    else
    {
      $version = (unpack ("L", $tmp) & 1) ? 3 : 4;
    }

    my $rc4_key = sha1 ($tmp . "\x00\x00\x00\x00");

    if ($version == 3)
    {
      $rc4_key = substr ($rc4_key, 0, 5) . "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    }

    my $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

    my $encdata;

    if (defined $additional_param)
    {
      $encdata = $m->RC4 (pack ("H*", $additional_param));
    }
    else
    {
      $encdata = "A" x 16; ## can be anything
    }

    my $data1_buf = $encdata;
    my $data2_buf = sha1 (substr ($data1_buf, 0, 16));

    $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

    my $encrypted1 = $m->RC4 ($data1_buf);
    my $encrypted2 = $m->RC4 ($data2_buf);

    $tmp_hash = sprintf ("\$oldoffice\$%d*%s*%s*%s", $version, unpack ("H*", $salt_buf), unpack ("H*", $encrypted1), unpack ("H*", $encrypted2));
  }
  elsif ($mode == 9900)
  {
    $tmp_hash = sprintf ("%s", md5_hex ($word_buf . "\0" x (100 - length ($word_buf))));
  }
  elsif ($mode == 10000)
  {
    my $iterations = 10000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations
    );

    $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt_buf, $word_buf), "");

    $tmp_hash = sprintf ("pbkdf2_sha256\$%i\$%s\$%s", $iterations, $salt_buf, $hash_buf);
  }
  elsif ($mode == 10100)
  {
    my $seed = pack ("H*", $salt_buf);

    my ($hi, $lo) = siphash ($word_buf, $seed);

    my $hi_s = sprintf ("%08x", $hi);
    my $lo_s = sprintf ("%08x", $lo);

    $hi_s =~ s/^(..)(..)(..)(..)$/$4$3$2$1/;
    $lo_s =~ s/^(..)(..)(..)(..)$/$4$3$2$1/;

    $tmp_hash = sprintf ("%s%s:2:4:%s", $hi_s, $lo_s, $salt_buf);
  }
  elsif ($mode == 10200)
  {
    my $challengeb64 = encode_base64 ($salt_buf, "");

    my $username;

    if (defined $additional_param)
    {
      $username = $additional_param;
    }
    else
    {
      $username = "user";
    }

    $hash_buf = hmac_hex ($salt_buf, $word_buf, \&md5);

    my $responseb64 = encode_base64 ($username . " " . $hash_buf, "");

    $tmp_hash = sprintf ('$cram_md5$%s$%s', $challengeb64, $responseb64);
  }
  elsif ($mode == 10300)
  {
    my $iterations = 1024;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $hash_buf = $salt_buf;

    for (my $pos = 0; $pos < $iterations; $pos++)
    {
      $hash_buf = sha1 ($word_buf . $hash_buf);
    }

    $hash_buf = encode_base64 ($hash_buf . $salt_buf, "");

    $tmp_hash = sprintf ("{x-issha, %i}%s", $iterations, $hash_buf);
  }
  elsif ($mode == 10400)
  {
    my $id  = $salt_buf;
    my $u   = $additional_param;
    my $o   = $additional_param2;
    my $P   = $additional_param3;

    if (defined $u == 0)
    {
      $u = "0" x 64;
    }

    if (defined $o == 0)
    {
      $o = "0" x 64;
    }

    if (defined $P == 0)
    {
      $P = -1;
    }

    my $padding;

    for (my $i = 0; $i < 32; $i++)
    {
      $padding .= pack ("C", $PDF_PADDING->[$i]);
    }

    my $res = pdf_compute_encryption_key ($word_buf, $padding, $id, $u, $o, $P, 1, 2, 0);

    my $m = Crypt::RC4->new (substr ($res, 0, 5));

    $u = $m->RC4 ($padding);

    $tmp_hash = sprintf ('$pdf$%d*%d*40*%d*%d*16*%s*32*%s*32*%s', 1, 2, $P, 0, $id, unpack ("H*", $u), $o);
  }
  elsif ($mode == 10500)
  {
    my $id  = $salt_buf;
    my $u   = $additional_param;
    my $o   = $additional_param2;
    my $P   = $additional_param3;
    my $V   = $additional_param4;
    my $R   = $additional_param5;
    my $enc = $additional_param6;

    if (defined $u == 0)
    {
      $u = "0" x 64;
    }

    my $u_save = $u;

    if (defined $o == 0)
    {
      $o = "0" x 64;
    }

    if (defined $R == 0)
    {
      $R = get_random_num (3, 5);
    }

    if (defined $V == 0)
    {
      $V = ($R == 3) ? 2 : 4;
    }

    if (defined $P == 0)
    {
      $P = ($R == 3) ? -4 : -1028;
    }

    if (defined $enc == 0)
    {
      $enc = ($R == 3) ? 1 : get_random_num (0, 2);
    }

    my $padding;

    for (my $i = 0; $i < 32; $i++)
    {
      $padding .= pack ("C", $PDF_PADDING->[$i]);
    }

    my $res = pdf_compute_encryption_key ($word_buf, $padding, $id, $u, $o, $P, $V, $R, $enc);

    my $digest = md5 ($padding . pack ("H*", $id));

    my $m = Crypt::RC4->new ($res);

    $u = $m->RC4 ($digest);

    my @ress = split "", $res;

    for (my $x = 1; $x <= 19; $x++)
    {
      my @xor;

      for (my $i = 0; $i < 16; $i++)
      {
        $xor[$i] = chr (ord ($ress[$i]) ^ $x);
      }

      my $s = join ("", @xor);

      my $m2 = Crypt::RC4->new ($s);

      $u = $m2->RC4 ($u);
    }

    $u .= substr (pack ("H*", $u_save), 16, 16);

    $tmp_hash = sprintf ('$pdf$%d*%d*128*%d*%d*16*%s*32*%s*32*%s', $V, $R, $P, $enc, $id, unpack ("H*", $u), $o);
  }
  elsif ($mode == 10600)
  {
    my $id   = $salt_buf;
    my $rest = $additional_param;

    if (defined $id == 0)
    {
      $id = "0" x 32;
    }

    if (defined $rest == 0)
    {
      $rest = "127*";
      $rest .= "0" x 64;
      $rest .= $id;
      $rest .= "0" x 158;
      $rest .= "*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";
    }

    my @data = split /\*/, $rest;

    my $u = pack ("H*", $data[1]);

    my $h = sha256 ($word_buf . substr ($u, 32, 8));

    $data[1] = unpack ("H*", $h . substr ($u, 32));

    $rest = join ("*", @data);

    $tmp_hash = sprintf ('$pdf$5*5*256*-1028*1*16*%s*%s', $id, $rest);
  }
  elsif ($mode == 10700)
  {
    my $id   = $salt_buf;
    my $rest = $additional_param;

    if (defined $id == 0)
    {
      $id = "0" x 32;
    }

    if (defined $rest == 0)
    {
      $rest = "127*";
      $rest .= "0" x 64;
      $rest .= $id;
      $rest .= "0" x 158;
      $rest .= "*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";
    }

    my @datax = split /\*/, $rest;

    my $u = pack ("H*", $datax[1]);

    my $block = sha256 ($word_buf . substr ($u, 32, 8));

    my $block_size = 32;

    my $data = 0x00 x 64;

    my $data_len = 1;

    my $data63 = 0;

    for (my $i = 0; $i < 64 || $i < $data63 + 32; $i++)
    {
      $data = $word_buf . $block;

      $data_len = length ($data);

      for (my $k = 1; $k < 64; $k++)
      {
        $data .= $word_buf . $block;
      }

      my $aes = Crypt::CBC->new ({
        key         => substr ($block,  0, 16),
        cipher      => "Crypt::Rijndael",
        iv          => substr ($block, 16, 16),
        literal_key => 1,
        header      => "none",
        keysize     => 16,
        padding     => "null",
      });

      my $data = $aes->encrypt ($data);

      my $sum = 0;

      for (my $j = 0; $j < 16; $j++)
      {
        $sum += ord (substr ($data, $j, 1));
      }

      $block_size = 32 + ($sum % 3) * 16;

      if ($block_size == 32)
      {
        $block = sha256 (substr ($data, 0, $data_len * 64));
      }
      elsif ($block_size == 48)
      {
        $block = sha384 (substr ($data, 0, $data_len * 64));
      }
      elsif ($block_size == 64)
      {
        $block = sha512 (substr ($data, 0, $data_len * 64));
      }

      $data63 = ord (substr ($data, $data_len * 64 - 1, 1));
    }

    $datax[1] = unpack ("H*", substr ($block, 0, 32) . substr ($u, 32));

    $rest = join ("*", @datax);

    $tmp_hash = sprintf ('$pdf$5*6*256*-1028*1*16*%s*%s', $id, $rest);
  }
  elsif ($mode == 10800)
  {
    $hash_buf = sha384_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 10900)
  {
    my $iterations = 1000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $out_len = 24;

    if (defined $additional_param)
    {
      $out_len = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => $out_len
    );

    $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt_buf, $word_buf), "");

    my $base64_salt_buf = encode_base64 ($salt_buf, "");

    $tmp_hash = sprintf ("sha256:%i:%s:%s", $iterations, $base64_salt_buf, $hash_buf);
  }
  elsif ($mode == 16900)
  {
    my $iterations = 10000;

    my $salt_hex = substr ($salt_buf, 0, 64);
    my $salt     = pack   ("H*", $salt_hex);

    my $ciphertext = randbytes(32);

    if (defined $additional_param)
    {
      my $ciphertext_hex = $additional_param;
      $ciphertext       = pack ("H*", $ciphertext_hex);
    }

    # actually 80 but the last 16 bytes are the IV which we don't need
    my $out_len = 64;

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => $out_len
    );

    my $derived_key = $pbkdf2->PBKDF2 ($salt, $word_buf);

    $hash_buf = hmac_hex ($ciphertext, substr ($derived_key, 32, 32), \&sha256);

    $tmp_hash = sprintf ('$ansible$0*0*%s*%s*%s', unpack ("H*", $salt), unpack ("H*", $ciphertext), $hash_buf);
  }
  elsif ($mode == 11000)
  {
    $hash_buf = md5_hex ($salt_buf . $word_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 11100)
  {
    my $user = "postgres";

    if (defined $additional_param)
    {
      $user = $additional_param;
    }

    $hash_buf = md5_hex (md5_hex ($word_buf . $user) . pack ("H*", $salt_buf));

    $tmp_hash = sprintf ("\$postgres\$%s*%s*%s", $user, $salt_buf, $hash_buf);
  }
  elsif ($mode == 11200)
  {
    my $sha1_pass   = sha1 ($word_buf);
    my $double_sha1 = sha1 ($sha1_pass);

    my $xor_part1 = $sha1_pass;
    my $xor_part2 = sha1 (pack ("H*", $salt_buf) . $double_sha1);

    my $hash_buf = "";

    for (my $i = 0; $i < 20; $i++)
    {
      my $first_byte  = substr ($xor_part1, $i, 1);
      my $second_byte = substr ($xor_part2, $i, 1);

      my $xor_result = $first_byte ^ $second_byte;

      $hash_buf .= unpack ("H*", $xor_result);
    }

    $tmp_hash = sprintf ("\$mysqlna\$%s*%s", $salt_buf, $hash_buf);
  }
  elsif ($mode == 11300)
  {
    my $ckey_buf = get_random_string (96);

    if (length ($additional_param))
    {
      $ckey_buf = $additional_param;
    }

    my $public_key_buf = get_random_string (66);

    if (length ($additional_param2))
    {
      $public_key_buf = $additional_param2;
    }

    my $salt_iter = get_random_num (150000, 250000);

    if (length ($iter))
    {
      $salt_iter = int ($iter);
    }

    my $hash_buf = sha512 ($word_buf . pack ("H*", $salt_buf));

    for (my $i = 1; $i < $salt_iter; $i++)
    {
      $hash_buf = sha512 ($hash_buf);
    }

    my $data = get_random_string (32);

    my $aes = Crypt::CBC->new ({
      key         => substr ($hash_buf,  0, 32),
      cipher      => "Crypt::Rijndael",
      iv          => substr ($hash_buf, 32, 16),
      literal_key => 1,
      header      => "none",
      keysize     => 32,
      padding     => "standard",
    });

    my $cry_master_buf = (unpack ("H*", $aes->encrypt ($data)));

    $tmp_hash = sprintf ('$bitcoin$%d$%s$%d$%s$%d$%d$%s$%d$%s',
      length ($cry_master_buf),
      $cry_master_buf,
      length ($salt_buf),
      $salt_buf,
      $salt_iter,
      length ($ckey_buf),
      $ckey_buf,
      length ($public_key_buf),
      $public_key_buf);
  }
  elsif ($mode == 11400)
  {
    my ($directive, $URI_server, $URI_client, $user, $realm, $nonce, $nonce_count, $nonce_client, $qop, $method, $URI, $URI_prefix, $URI_resource, $URI_suffix);

    $directive = "MD5"; # only directive currently supported

    if (defined ($additional_param))
    {
      $user   = $additional_param;
      $realm  = $additional_param2;
      $nonce  = $salt_buf;
      $nonce_count  = $additional_param3;
      $nonce_client = $additional_param4;
      $qop = $additional_param5;
      $method = $additional_param6;

      $URI_prefix   = $additional_param7;
      $URI_resource = $additional_param8;
      $URI_suffix   = $additional_param9;

      # not needed information

      $URI_server = $additional_param10;
      $URI_client = $additional_param11;
    }
    else
    {
      $user   = get_random_string (get_random_num (0, 12 + 1));

      # special limit: (user_len + 1 + realm_len + 1 + word_buf_len) < 56
      my $realm_max_len = 55 - length ($user) - 1 - length ($word_buf) - 1;

      if ($realm_max_len < 1) # should never happen
      {
        $realm_max_len = 1;
      }

      $realm_max_len = min (20, $realm_max_len);

      $realm  = get_random_string (get_random_num (0, $realm_max_len + 1));

      $nonce  = $salt_buf;

      if (get_random_num (0, 1 + 1) == 1)
      {
        $qop = "auth";

        $nonce_count  = get_random_string (get_random_num (0, 10 + 1));
        $nonce_client = get_random_string (get_random_num (0, 12 + 1));
      }
      else
      {
        $qop = "";

        $nonce_count  = "";
        $nonce_client = "";
      }

      $method = get_random_string (get_random_num (0, 24 + 1));

      $URI_prefix   = get_random_string (get_random_num (0, 10 + 1));
      $URI_resource = get_random_string (get_random_num (1, 32 + 1));
      $URI_suffix   = get_random_string (get_random_num (0, 32 + 1));

      # not needed information

      $URI_server = get_random_string (get_random_num (0, 32 + 1));
      $URI_client = $URI_resource; # simplification
    }

    # start

    $URI = "";

    if (length ($URI_prefix) > 0)
    {
      $URI = $URI_prefix . ":";
    }

    $URI .= $URI_resource;

    if (length ($URI_suffix) > 0)
    {
      $URI .= ":" . $URI_suffix;
    }

    my $HA2 = md5_hex ($method . ":" . $URI);

    my $HA1 = md5_hex ($user . ":" . $realm . ":" . $word_buf);

    my $tmp_buf;

    if (($qop eq "auth") || ($qop eq "auth-int"))
    {
      $tmp_buf = $nonce . ":" . $nonce_count . ":" . $nonce_client . ":" . $qop;
    }
    else
    {
      $tmp_buf = $nonce;
    }

    my $hash_buf = md5_hex ($HA1 . ":" . $tmp_buf . ":" . $HA2);

    $tmp_hash = sprintf ("\$sip\$*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s", $URI_server, $URI_resource, $user, $realm, $method, $URI_prefix, $URI_resource, $URI_suffix, $nonce, $nonce_client, $nonce_count, $qop, $directive, $hash_buf);
  }
  elsif ($mode == 11500)
  {
    $hash_buf = crc32 ($word_buf);

    $tmp_hash = sprintf ("%08x:00000000", $hash_buf);
  }
  elsif ($mode == 11600)
  {
    my ($p, $num_cycle_power, $seven_zip_salt_len, $seven_zip_salt_buf, $salt_len, $data_len, $unpack_size, $data_buf);

    $p = 0; # is fixed

    my $validation_only = 0;

    $validation_only = 1 if (defined ($additional_param));

    if ($validation_only == 1)
    {
      $num_cycle_power = int ($iter);
      $seven_zip_salt_len = $additional_param;
      $seven_zip_salt_buf = $additional_param2;
      $salt_len = $additional_param3;
      # $salt_buf set in parser
      # $hash_buf (resulting crc)
      $data_len = $additional_param4;
      $unpack_size = $additional_param5;
      $data_buf = $additional_param6;
    }
    else
    {
      $num_cycle_power = 14; # by default it is 19
      $seven_zip_salt_len = 0;
      $seven_zip_salt_buf = "";
      $salt_len = length ($salt_buf);
      # $salt_buf set automatically
      # $hash_buf (resulting crc)
      # $data_len will be set when encrypting
      $unpack_size = get_random_num (1, 32 + 1);
      $data_buf = get_random_string ($unpack_size);
    }

    #
    # 2 ^ NumCyclesPower "iterations" of SHA256 (only one final SHA256)
    #

    $word_buf = encode ("UTF-16LE", $word_buf);

    my $rounds = 1 << $num_cycle_power;

    my $pass_buf = "";

    for (my $i = 0; $i < $rounds; $i++)
    {
      my $num_buf = "";

      $num_buf .= pack ("V", $i);
      $num_buf .= "\x00" x 4;

      # this would be better but only works on 64-bit systems:
      # $num_buf = pack ("q", $i);

      $pass_buf .= sprintf ("%s%s", $word_buf, $num_buf);
    }

    my $key = sha256 ($pass_buf);

    # the salt_buf is our IV for AES CBC
    # pad the salt_buf

    my $salt_buf_len = length ($salt_buf);
    my $salt_padding_len = 0;

    if ($salt_buf_len < 16)
    {
      $salt_padding_len = 16 - $salt_buf_len;
    }

    $salt_buf .= "\x00" x $salt_padding_len;

    my $aes = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      key         => $key,
      keysize     => 32,
      literal_key => 1,
      iv          => $salt_buf,
      header      => "none",
    });

    if ($validation_only == 1)
    {
      # decrypt

      my $decrypted_data = $aes->decrypt ($data_buf);

      $decrypted_data = substr ($decrypted_data, 0, $unpack_size);

      $hash_buf = crc32 ($decrypted_data);
    }
    else
    {
      # encrypt

      $hash_buf = crc32 ($data_buf);

      $data_buf = $aes->encrypt ($data_buf);

      $data_len = length ($data_buf);
    }

    $tmp_hash = sprintf ("\$7z\$%i\$%i\$%i\$%s\$%i\$%08s\$%u\$%u\$%u\$%s", $p, $num_cycle_power, $seven_zip_salt_len, $seven_zip_salt_buf, $salt_len, unpack ("H*", $salt_buf), $hash_buf, $data_len, $unpack_size, unpack ("H*", $data_buf));
  }
  elsif ($mode == 11700)
  {
    # PyGOST outputs digests in little-endian order, while the kernels
    # expect them in big-endian; hence the digest[::-1] mirroring.
    # Using sys.stdout.write instead of print to disable \n character.
    my $python_code = <<"END_CODE";

import binascii
import sys
from pygost import gost34112012256
digest = gost34112012256.new(b"$word_buf").digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

    $tmp_hash = `python2 -c '$python_code'`;
  }
  elsif ($mode == 11750)
  {
    my $python_code = <<"END_CODE";

import binascii
import hmac
import sys
from pygost import gost34112012256
key    = b"$word_buf"
msg    = b"$salt_buf"
digest = hmac.new(key, msg, gost34112012256).digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

    $hash_buf = `python2 -c '$python_code'`;
    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 11760)
  {
    my $python_code = <<"END_CODE";

import binascii
import hmac
import sys
from pygost import gost34112012256
key    = b"$salt_buf"
msg    = b"$word_buf"
digest = hmac.new(key, msg, gost34112012256).digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

    $hash_buf = `python2 -c '$python_code'`;
    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 11800)
  {
    my $python_code = <<"END_CODE";

import binascii
import sys
from pygost import gost34112012512
digest = gost34112012512.new(b"$word_buf").digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

    $tmp_hash = `python2 -c '$python_code'`;
  }
  elsif ($mode == 11850)
  {
    my $python_code = <<"END_CODE";

import binascii
import hmac
import sys
from pygost import gost34112012512
key    = b"$word_buf"
msg    = b"$salt_buf"
digest = hmac.new(key, msg, gost34112012512).digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

    $hash_buf = `python2 -c '$python_code'`;
    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 11860)
  {
    my $python_code = <<"END_CODE";

import binascii
import hmac
import sys
from pygost import gost34112012512
key    = b"$salt_buf"
msg    = b"$word_buf"
digest = hmac.new(key, msg, gost34112012512).digest()
sys.stdout.write(binascii.hexlify(digest[::-1]))

END_CODE

    $hash_buf = `python2 -c '$python_code'`;
    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 11900)
  {
    my $iterations = 1000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $out_len = 32;

    if (defined $additional_param)
    {
      $out_len = $additional_param;
    }

    #
    # call PHP here - WTF
    #

    # sanitize $word_buf and $salt_buf:

    my $word_buf_base64 = encode_base64 ($word_buf, "");
    my $salt_buf_base64 = encode_base64 ($salt_buf, "");

    # sanitize lenghs

    $out_len = int ($out_len);

    # output is in hex encoding, otherwise it could be screwed (but shouldn't)

    my $php_code = <<'END_CODE';

    function pbkdf2 ($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $algorithm = strtolower ($algorithm);

        if (! in_array ($algorithm, hash_algos (), true))
        {
          trigger_error ("PBKDF2 ERROR: Invalid hash algorithm.", E_USER_ERROR);
        }

        if ($count <= 0 || $key_length <= 0)
        {
          trigger_error ("PBKDF2 ERROR: Invalid parameters.", E_USER_ERROR);
        }

        if (function_exists ("hash_pbkdf2"))
        {
          if (!$raw_output)
          {
              $key_length = $key_length * 2;
          }

          return hash_pbkdf2 ($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }

        $hash_length = strlen (hash ($algorithm, "", true));
        $block_count = ceil ($key_length / $hash_length);

        $output = "";

        for ($i = 1; $i <= $block_count; $i++)
        {
          $last = $salt . pack ("N", $i);

          $last = $xorsum = hash_hmac ($algorithm, $last, $password, true);

          for ($j = 1; $j < $count; $j++)
          {
            $xorsum ^= ($last = hash_hmac ($algorithm, $last, $password, true));
          }

          $output .= $xorsum;
        }

        if ($raw_output)
        {
          return substr ($output, 0, $key_length);
        }
        else
        {
          return bin2hex (substr ($output, 0, $key_length));
        }
    }

    print pbkdf2 ("md5", base64_decode ("$word_buf_base64"), base64_decode ("$salt_buf_base64"), $iterations, $out_len, False);

END_CODE

    # replace with these command line arguments

    $php_code =~ s/\$word_buf_base64/$word_buf_base64/;
    $php_code =~ s/\$salt_buf_base64/$salt_buf_base64/;
    $php_code =~ s/\$iterations/$iterations/;
    $php_code =~ s/\$out_len/$out_len/;

    my $php_output = `php -r '$php_code'`;

    $hash_buf = pack ("H*", $php_output);

    $hash_buf = encode_base64 ($hash_buf, "");

    my $base64_salt_buf = encode_base64 ($salt_buf, "");

    $tmp_hash = sprintf ("md5:%i:%s:%s", $iterations, $base64_salt_buf, $hash_buf);
  }
  elsif ($mode == 12000)
  {
    my $iterations = 1000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $out_len = 16;

    if (defined $additional_param)
    {
      $out_len = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
      iterations => $iterations,
      output_len => $out_len
    );

    $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt_buf, $word_buf), "");

    my $base64_salt_buf = encode_base64 ($salt_buf, "");

    $tmp_hash = sprintf ("sha1:%i:%s:%s", $iterations, $base64_salt_buf, $hash_buf);
  }
  elsif ($mode == 12001)
  {
    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
      iterations => 10000,
      output_len => 32
    );

    my $base64_buf = encode_base64 ($salt_buf . $pbkdf2->PBKDF2 ($salt_buf, $word_buf), "");

    $tmp_hash = sprintf ("{PKCS5S2}%s", $base64_buf);
  }
  elsif ($mode == 12100)
  {
    my $iterations = 1000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $out_len = 16;

    if (defined $additional_param)
    {
      $out_len = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
      iterations => $iterations,
      output_len => $out_len
    );

    $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt_buf, $word_buf), "");

    my $base64_salt_buf = encode_base64 ($salt_buf, "");

    $tmp_hash = sprintf ("sha512:%i:%s:%s", $iterations, $base64_salt_buf, $hash_buf);
  }
  elsif ($mode == 12200)
  {
    my $iterations = 65536;

    my $default_salt = 0;

    if (defined $additional_param)
    {
      $default_salt = int ($additional_param);
    }

    if ($default_salt == 1)
    {
      $salt_buf = "0011223344556677";
    }

    $hash_buf = sha512 (pack ("H*", $salt_buf) . $word_buf);

    for (my $i = 0; $i < $iterations; $i++)
    {
      $hash_buf = sha512 ($hash_buf);
    }

    $hash_buf = unpack ("H*", $hash_buf);
    $hash_buf = substr ($hash_buf, 0, 16);

    if ($default_salt == 0)
    {
      $tmp_hash = sprintf ("\$ecryptfs\$0\$1\$%s\$%s", $salt_buf, $hash_buf);
    }
    else
    {
      $tmp_hash = sprintf ("\$ecryptfs\$0\$%s", $hash_buf);
    }
  }
  elsif ($mode == 12300)
  {
    my $iterations = 4096;

    my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512);

    my $pbkdf2 = Crypt::PBKDF2->new (
      hasher       => $hasher,
      iterations   => $iterations,
      output_len   => 64
    );

    my $salt_bin = pack ("H*", $salt_buf);

    my $key = $pbkdf2->PBKDF2 ($salt_bin. "AUTH_PBKDF2_SPEEDY_KEY", $word_buf);

    $hash_buf = sha512_hex ($key . $salt_bin);

    $tmp_hash = sprintf ("%s%s", uc ($hash_buf), uc ($salt_buf));
  }
  elsif ($mode == 12400)
  {
    my $iterations;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }
    else
    {
      $iterations = get_random_num (1, 5001 + 1);
    }

    my $key_value  = fold_password ($word_buf);

    my $data = "\x00\x00\x00\x00\x00\x00\x00\x00";
    my $salt_value = base64_to_int24 ($salt_buf);

    $hash_buf = crypt_rounds ($key_value, $iterations, $salt_value, $data);

    $tmp_hash = sprintf ("_%s%s%s", int24_to_base64 ($iterations), $salt_buf, block_to_base64 ($hash_buf));
  }
  elsif ($mode == 12600)
  {
    $hash_buf = sha1_hex ($word_buf);

    $hash_buf = sha256_hex ($salt_buf . uc $hash_buf);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 12700)
  {
    my $iterations = 10;

    my $data = qq|{
  "guid" : "00000000-0000-0000-0000-000000000000",
  "sharedKey" : "00000000-0000-0000-0000-000000000000",
  "options" : {"pbkdf2_iterations":10,"fee_policy":0,"html5_notifications":false,"logout_time":600000,"tx_display":0,"always_keep_local_backup":false}|;

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

    my $pbkdf2 = Crypt::PBKDF2->new (
      hasher       => $hasher,
      iterations   => $iterations,
      output_len   => 32
    );

    my $key = $pbkdf2->PBKDF2 ($salt_buf_bin, $word_buf);

    my $cipher = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $salt_buf_bin,
      literal_key => 1,
      header      => "none",
      keysize     => 32
    });

    my $encrypted = unpack ("H*", $cipher->encrypt ($data));

    $tmp_hash = sprintf ("\$blockchain\$%s\$%s", length ($salt_buf . $encrypted) / 2, $salt_buf . $encrypted);
  }
  elsif ($mode == 12800)
  {
    my $iterations = 100;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $nt = md4_hex (encode ("UTF-16LE", $word_buf));

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => 32
    );

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $hash = $pbkdf2->PBKDF2 ($salt_buf_bin, uc (encode ("UTF-16LE", $nt)));

    $tmp_hash = sprintf ("v1;PPH1_MD4,%s,%d,%s", $salt_buf, $iterations, unpack ("H*", $hash));
  }
  elsif ($mode == 12900)
  {
    my $iterations = 4096;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $salt2 = $salt_buf . $salt_buf;

    if (defined $additional_param)
    {
      $salt2 = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => 32
    );

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $hash = $pbkdf2->PBKDF2 ($salt_buf_bin, $word_buf);

    my $salt2_bin = pack ("H*", $salt2);

    my $hash_hmac = hmac_hex ($salt2_bin, $hash, \&sha256, 64);

    $tmp_hash = sprintf ("%s%s%s", $salt2, $hash_hmac, $salt_buf);
  }
  elsif ($mode == 13000)
  {
    my $iterations = 15;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $iv = "0" x 32;

    if (defined $additional_param)
    {
      $iv = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => (1 << $iterations) + 32,
      output_len => 32
    );

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $hash = $pbkdf2->PBKDF2 ($salt_buf_bin, $word_buf);

    my $hash_final = substr ($hash,  0, 8)
                   ^ substr ($hash,  8, 8)
                   ^ substr ($hash, 16, 8)
                   ^ substr ($hash, 24, 8);

    $tmp_hash = sprintf ('$rar5$16$%s$%d$%s$8$%s', $salt_buf, $iterations, $iv, unpack ("H*", $hash_final));
  }
  elsif ($mode == 13100)
  {
    my @salt_arr = split ('\$', $salt_buf);

    my $user  = $salt_arr[0];

    my $realm = $salt_arr[1];

    my $spn   = $salt_arr[2];

    my $k = md4 (encode ("UTF-16LE", $word_buf));

    my $k1 = hmac_md5 ("\x02\x00\x00\x00", $k);

    my $cleartext_ticket = '6381b03081ada00703050050a00000a11b3019a003020117a1'.
      '12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5'.
      '44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201'.
      '01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353'.
      '134343735305aa711180f32303136303231363030343735305aa811180f32303136303232'.
      '323134343735305a';

    my $checksum = "";

    if (defined $additional_param)
    {
      $checksum = pack ("H*", $additional_param);
    }
    else
    {
      my $nonce = $salt_arr[3];

      $cleartext_ticket = $nonce . $cleartext_ticket;

      $checksum = hmac_md5 (pack ("H*", $cleartext_ticket), $k1);
    }

    my $k3 = hmac_md5 ($checksum, $k1);

    my $edata2 = "";

    if (defined $additional_param2)
    {
      $edata2 = $additional_param2;

      my $cipher_decrypt = Crypt::RC4->new ($k3);

      my $ticket_decrypt = unpack ("H*", $cipher_decrypt->RC4 (pack ("H*", $edata2)));

      my $check_correct  = ((substr ($ticket_decrypt, 16, 4) eq "6381" && substr ($ticket_decrypt, 22, 2) eq "30") ||
                            (substr ($ticket_decrypt, 16, 4) eq "6382")) &&
                           ((substr ($ticket_decrypt, 32, 6) eq "030500") ||
                            (substr ($ticket_decrypt, 32, 8) eq "050307A0"));

      if ($check_correct == 1)
      {
        $cleartext_ticket = $ticket_decrypt;
      }
      else # validation failed
      {
        # fake/wrong ticket (otherwise if we just decrypt/encrypt we end up with false positives all the time)
        $cleartext_ticket = "0" x (length ($cleartext_ticket) + 16);
      }
    }

    my $cipher = Crypt::RC4->new ($k3);

    $edata2 = $cipher->RC4 (pack ("H*", $cleartext_ticket));

    $tmp_hash = sprintf ('$krb5tgs$23$*%s$%s$%s*$%s$%s', $user, $realm, $spn, unpack ("H*", $checksum), unpack ("H*", $edata2));
  }
  elsif ($mode == 13200)
  {
    my @salt_arr = split ('\*', $salt_buf);

    my $iteration = $salt_arr[0];

    my $mysalt = $salt_arr[1];

    $mysalt = pack ("H*", $mysalt);

    my $iv = "a6a6a6a6a6a6a6a6";

    my $KEK = sha1 ($word_buf);

    $KEK = substr ($KEK ^ $mysalt, 0, 16);

    my $aes = Crypt::Mode::ECB->new ('AES');

    my $B;

    my $A;

    my @R = ();

    if (defined $additional_param)
    {
      $additional_param = pack ("H*", $additional_param);

      $A = substr ($additional_param,  0, 8);
      $B = 0x00 x 8;

      $R[1] = substr ($additional_param,  8, 8);
      $R[2] = substr ($additional_param, 16, 8);

      for (my $j = $iteration - 1; $j >= 0; $j--)
      {
        $A = substr ($A, 0, 8) ^ pack ("l", (2 * $j + 2));

        $B = $R[2];

        $A = $aes->decrypt ($A . $B . "\x00" x 16, $KEK);

        $R[2] = substr ($A, 8, 16);

        $A = substr ($A, 0, 8) ^ pack ("l", (2 * $j + 1));

        $B = $R[1];

        $A = $aes->decrypt ($A . $B . "\x00" x 16, $KEK);

        $R[1] = substr ($A, 8, 16);
      }

      # check if valid
      if (index ($A, "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6") != 0)
      {
        # fake wrong @R and $A values

        @R = ('', "\x00" x 8, "\x00" x 8);

        $A = "\x00" x 16;
      }
    }
    else
    {
      my $DEK = randbytes (16);

      @R = ('', substr (pack ("H*", $DEK), 0, 8), substr (pack ("H*", $DEK), 8, 16));

      $A = pack ("H*", $iv);
    }

    for (my $j = 0; $j < $iteration; $j++)
    {
      $B = $aes->encrypt ($A . $R[1], $KEK);

      $A = substr ($B, 0, 8) ^ pack ("q", (2 * $j + 1));

      $R[1] = substr ($B, 8, 16);

      $B = $aes->encrypt ($A . $R[2], $KEK);

      $A = substr ($B, 0, 8) ^ pack ("q", (2 * $j + 2));

      $R[2] = substr ($B, 8, 16);
    }

    my $wrapped_key = unpack ("H*", $A . substr ($R[1], 0 ,8) . substr ($R[2], 0 ,8));

    $mysalt = unpack ("H*", $mysalt);

    $tmp_hash = sprintf ('$axcrypt$*1*%s*%s*%s', $iteration, $mysalt, $wrapped_key);
  }
  elsif ($mode == 13300)
  {
    my $length = 32;

    if ($additional_param)
    {
      $length = $additional_param;
    }

    $hash_buf = sha1_hex ($word_buf);

    $tmp_hash = sprintf ('$axcrypt_sha1$%s', substr ($hash_buf, 0, $length));
  }
  elsif ($mode == 13400)
  {
    my @salt_arr = split ('\*', $salt_buf);

    my $version   = $salt_arr[0];

    my $iteration = $salt_arr[1];

    my $algorithm = $salt_arr[2];

    my $final_random_seed  = $salt_arr[3];

    my $transf_random_seed = $salt_arr[4];

    my $enc_iv = $salt_arr[5];

    my $contents_hash;

    # specific to version 1
    my $inline_flag;
    my $contents_len;
    my $contents;

    # specific to version 2
    my $expected_bytes;

    # specific to keyfile handling
    my $inline_keyfile_flag;
    my $keyfile_len;
    my $keyfile_content;
    my $keyfile_attributes = "";

    $final_random_seed  = pack ("H*", $final_random_seed);

    $transf_random_seed = pack ("H*", $transf_random_seed);

    $enc_iv = pack ("H*", $enc_iv);

    my $intermediate_hash = sha256 ($word_buf);

    if ($version == 1)
    {
      $contents_hash = $salt_arr[6];

      $contents_hash = pack ("H*", $contents_hash);

      $inline_flag   = $salt_arr[7];


      $contents_len  = $salt_arr[8];


      $contents      = $salt_arr[9];

      $contents      = pack ("H*", $contents);

      # keyfile handling
      if (scalar @salt_arr == 13)
      {
        $inline_keyfile_flag = $salt_arr[10];

        $keyfile_len         = $salt_arr[11];

        $keyfile_content     = $salt_arr[12];

        $keyfile_attributes = $keyfile_attributes
                            . "*" . $inline_keyfile_flag
                            . "*" . $keyfile_len
                            . "*" . $keyfile_content;

        $intermediate_hash = $intermediate_hash . pack ("H*", $keyfile_content);

        $intermediate_hash = sha256 ($intermediate_hash);
      }
    }
    elsif ($version == 2)
    {
      # keyfile handling
      if (scalar @salt_arr == 11)
      {
        $inline_keyfile_flag = $salt_arr[8];

        $keyfile_len         = $salt_arr[9];

        $keyfile_content     = $salt_arr[10];

        $intermediate_hash = $intermediate_hash . pack ("H*", $keyfile_content);

        $keyfile_attributes = $keyfile_attributes
                    . "*" . $inline_keyfile_flag
                    . "*" . $keyfile_len
                    . "*" . $keyfile_content;

      }

      $intermediate_hash = sha256 ($intermediate_hash);
    }

    my $aes = Crypt::Mode::ECB->new ('AES', 1);

    for (my $j = 0; $j < $iteration; $j++)
    {
      $intermediate_hash = $aes->encrypt ($intermediate_hash, $transf_random_seed);

      $intermediate_hash = substr ($intermediate_hash, 0, 32);
    }

    $intermediate_hash = sha256 ($intermediate_hash);

    my $final_key = sha256 ($final_random_seed . $intermediate_hash);

    my $final_algorithm;

    if ($version == 1 && $algorithm == 1)
    {
      $final_algorithm = "Crypt::Twofish";
    }
    else
    {
      $final_algorithm = "Crypt::Rijndael";
    }

    my $cipher = Crypt::CBC->new ({
                   key         => $final_key,
                   cipher      => $final_algorithm,
                   iv          => $enc_iv,
                   literal_key => 1,
                   header      => "none",
                   keysize     => 32
                 });

    if ($version == 1)
    {
      if (defined $additional_param)
      {
        # if we try to verify the crack, we need to decrypt the contents instead of only encrypting it:

        $contents = $cipher->decrypt ($contents);

        # and check the output

        my $contents_hash_old = $contents_hash;

        $contents_hash = sha256 ($contents);

        if ($contents_hash_old ne $contents_hash)
        {
          # fake content
          $contents = "\x00" x length ($contents);
        }
      }
      else
      {
        $contents_hash = sha256 ($contents);
      }

      $contents = $cipher->encrypt ($contents);

      $tmp_hash = sprintf ('$keepass$*%d*%d*%d*%s*%s*%s*%s*%d*%d*%s%s',
            $version,
            $iteration,
            $algorithm,
            unpack ("H*", $final_random_seed),
            unpack ("H*", $transf_random_seed),
            unpack ("H*", $enc_iv),
            unpack ("H*", $contents_hash),
            $inline_flag,
            $contents_len,
            unpack ("H*", $contents),
            $keyfile_attributes);
    }
    if ($version == 2)
    {
      $expected_bytes = $salt_arr[6];

      $contents_hash = $salt_arr[7];
      $contents_hash = pack ("H*", $contents_hash);

      $expected_bytes = $cipher->decrypt ($contents_hash);

      $tmp_hash = sprintf ('$keepass$*%d*%d*%d*%s*%s*%s*%s*%s%s',
            $version,
            $iteration,
            $algorithm,
            unpack ("H*", $final_random_seed),
            unpack ("H*", $transf_random_seed),
            unpack ("H*", $enc_iv),
            unpack ("H*", $expected_bytes),
            unpack ("H*", $contents_hash),
            $keyfile_attributes);
    }
  }
  elsif ($mode == 13500)
  {
    $hash_buf = sha1_hex (pack ("H*", $salt_buf) . encode ("UTF-16LE", $word_buf));

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 13600)
  {
    my $iterations = 1000;

    my $type = 0;

    if (defined $additional_param)
    {
      $type = $additional_param;
    }

    my $mode = 1 + int rand (3);

    if (defined $additional_param2)
    {
      $mode = $additional_param2;
    }

    my $magic = 0;

    if (defined $additional_param3)
    {
      $magic = $additional_param3;
    }

    if (defined $additional_param4)
    {
      $salt_buf = $additional_param4;
    }

    $salt_buf = substr ($salt_buf, 0, 8 + ($mode * 8));

    my $compress_length = 0;

    if (defined $additional_param5)
    {
      $compress_length = $additional_param5;
    }

    my $data = "";

    if (defined $additional_param6)
    {
      $data = $additional_param6;
    }

    my $key_len = (8 * ($mode & 3) + 8) * 2;

    my $out_len = $key_len + 2;

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher      => $hasher,
      iterations  => $iterations,
      output_len  => $out_len
    );

    my $key = $pbkdf2->PBKDF2_hex ($salt_buf_bin, $word_buf);

    my $verify_bytes = substr ($key, -4); $verify_bytes =~ s/^0+//; #lol

    $key = substr ($key, $key_len, $key_len);

    my $key_bin = pack ("H*", $key);

    my $auth = hmac_hex ($data, $key_bin, \&sha1, 64);

    $tmp_hash = sprintf ('$zip2$*%u*%u*%u*%s*%s*%u*%s*%s*$/zip2$', $type, $mode, $magic, $salt_buf, $verify_bytes, $compress_length, $data, substr ($auth, 0, 20));
  }
  elsif ($mode == 13800)
  {
    my $word_buf_utf16le = encode ("UTF-16LE", $word_buf);

    my $salt_buf_bin = pack ("H*", $salt_buf);

    $hash_buf = sha256_hex ($word_buf_utf16le . $salt_buf_bin);

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 14000)
  {
    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $cipher = new Crypt::DES $word_buf;

    my $hash_buf = $cipher->encrypt ($salt_buf_bin);

    $tmp_hash = sprintf ("%s:%s", unpack ("H*", $hash_buf), $salt_buf);
  }
  elsif ($mode == 14100)
  {
    my $word_buf1 = substr ($word_buf,  0, 8);
    my $word_buf2 = substr ($word_buf,  8, 8);
    my $word_buf3 = substr ($word_buf, 16, 8);

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $cipher1 = new Crypt::DES $word_buf1;

    my $hash_buf1 = $cipher1->encrypt ($salt_buf_bin);

    my $cipher2 = new Crypt::DES $word_buf2;

    my $hash_buf2 = $cipher2->decrypt ($hash_buf1);

    my $cipher3 = new Crypt::DES $word_buf3;

    my $hash_buf3 = $cipher3->encrypt ($hash_buf2);

    $tmp_hash = sprintf ("%s:%s", unpack ("H*", $hash_buf3), $salt_buf);
  }
  elsif ($mode == 14400)
  {
    my $begin = "--" . $salt_buf . "--";
    my $end   = "--" . $word_buf . "----";

    my $hash_buf = sha1_hex ($begin . $end);

    for (my $round = 1; $round < 10; $round++)
    {
      $hash_buf = sha1_hex ($begin . $hash_buf . $end);
    }

    $tmp_hash = sprintf ("%s:%s", $hash_buf, $salt_buf);
  }
  elsif ($mode == 14700)
  {
    my $iterations = 10000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
      iterations => $iterations,
      output_len => 32
    );

    $salt_buf = pack ("H*", $salt_buf);

    my $key = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

    my $ITUNES_BACKUP_KEY = 12008468691120727718;

    my $WPKY = "\x00" x 40;

    if (defined $additional_param)
    {
      my ($A, $R) = itunes_aes_unwrap ($key, $additional_param);

      if ($A == $ITUNES_BACKUP_KEY)
      {
        $WPKY = itunes_aes_wrap ($key, $A, $R);
      }
    }
    else
    {
      my $max_number = 18446744073709551615; # 0xffffffffffffffff

      my @R;

      for (my $i = 0; $i < 4; $i++)
      {
        $R[$i] = get_random_num (0, $max_number);
      }

      $WPKY = itunes_aes_wrap ($key, $ITUNES_BACKUP_KEY, \@R);
    }

    $tmp_hash = sprintf ("\$itunes_backup\$*9*%s*%i*%s**", unpack ("H*", $WPKY), $iterations, unpack ("H*", $salt_buf));
  }
  elsif ($mode == 14800)
  {
    my $iterations = 10000;

    if (length ($iter))
    {
      $iterations = int ($iter);
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
      iterations => $iterations,
      output_len => 32
    );

    $salt_buf = pack ("H*", $salt_buf);

    my $ITUNES_BACKUP_KEY = 12008468691120727718;

    my $DPIC;
    my $DPSL;

    if (defined $additional_param)
    {
      $DPIC = $additional_param2;
      $DPSL = $additional_param3;
    }
    else
    {
      #$DPIC = 10000000; it's too much for the tests
      $DPIC = 1000;
      $DPSL = randbytes (20);
    }

    my $WPKY = "\x00" x 40;

    my $pbkdf2x = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2'),
      iterations => $DPIC,
      output_len => 32
    );

    my $key_dpsl = $pbkdf2x->PBKDF2 ($DPSL, $word_buf);

    my $key = $pbkdf2->PBKDF2 ($salt_buf, $key_dpsl);

    if (defined $additional_param)
    {
      my ($A, $R) = itunes_aes_unwrap ($key, $additional_param);

      if ($A == $ITUNES_BACKUP_KEY)
      {
        $WPKY = itunes_aes_wrap ($key, $A, $R);
      }
    }
    else
    {
      my $max_number = 18446744073709551615; # 0xffffffffffffffff

      my @R;

      for (my $i = 0; $i < 4; $i++)
      {
        $R[$i] = get_random_num (0, $max_number);
      }

      $WPKY = itunes_aes_wrap ($key, $ITUNES_BACKUP_KEY, \@R);
    }

    $tmp_hash = sprintf ("\$itunes_backup\$*10*%s*%i*%s*%i*%s", unpack ("H*", $WPKY), $iterations, unpack ("H*", $salt_buf), $DPIC, unpack ("H*", $DPSL));
  }
  elsif ($mode == 14900)
  {
    my $salt_bin = pack ("H*", $salt_buf);

    my $skip32 = Crypt::Skip32->new ($word_buf);

    my $hash = $skip32->encrypt ($salt_bin);

    $tmp_hash = sprintf ("%08x:%s", unpack ("N*", $hash), $salt_buf);
  }
  elsif ($mode == 15100)
  {
    my $iterations = 20000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $pbkdf1_salt_buf = sprintf ('%s$sha1$%u', $salt_buf, $iterations);

    my $tmp = hmac ($pbkdf1_salt_buf, $word_buf, \&sha1, 64);

    for (my $r = 1; $r < $iterations; $r++)
    {
      $tmp = hmac ($tmp, $word_buf, \&sha1, 64);
    }

    my $hash_buf = "";

    $hash_buf .= to64 ((int (ord (substr ($tmp,  0, 1))) << 16) | (int (ord (substr ($tmp,  1, 1))) << 8) | (int (ord (substr ($tmp,  2, 1)))), 4);
    $hash_buf .= to64 ((int (ord (substr ($tmp,  3, 1))) << 16) | (int (ord (substr ($tmp,  4, 1))) << 8) | (int (ord (substr ($tmp,  5, 1)))), 4);
    $hash_buf .= to64 ((int (ord (substr ($tmp,  6, 1))) << 16) | (int (ord (substr ($tmp,  7, 1))) << 8) | (int (ord (substr ($tmp,  8, 1)))), 4);
    $hash_buf .= to64 ((int (ord (substr ($tmp,  9, 1))) << 16) | (int (ord (substr ($tmp, 10, 1))) << 8) | (int (ord (substr ($tmp, 11, 1)))), 4);
    $hash_buf .= to64 ((int (ord (substr ($tmp, 12, 1))) << 16) | (int (ord (substr ($tmp, 13, 1))) << 8) | (int (ord (substr ($tmp, 14, 1)))), 4);
    $hash_buf .= to64 ((int (ord (substr ($tmp, 15, 1))) << 16) | (int (ord (substr ($tmp, 16, 1))) << 8) | (int (ord (substr ($tmp, 17, 1)))), 4);
    $hash_buf .= to64 ((int (ord (substr ($tmp, 18, 1))) << 16) | (int (ord (substr ($tmp, 19, 1))) << 8) | 0                                 , 4);

    ## super hackish, but we have no other choice, as this byte is kind of a random byte added to the digest when the hash was created

    if (defined $additional_param)
    {
      $hash_buf = substr ($hash_buf, 0, 24) . substr ($additional_param, 24, 4);
    }

    $tmp_hash = sprintf ("\$sha1\$%d\$%s\$%s", $iterations, $salt_buf, $hash_buf);
  }
  elsif ($mode == 15200)
  {
    my $iterations = 5000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $data = qq|{
  "guid" : "00000000-0000-0000-0000-000000000000",
  "sharedKey" : "00000000-0000-0000-0000-000000000000",
  "options" : {"pbkdf2_iterations":$iterations,"fee_policy":0,"html5_notifications":false,"logout_time":600000,"tx_display":0,"always_keep_local_backup":false}|;

    my $salt_buf_bin = pack ("H*", $salt_buf);

    my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

    my $pbkdf2 = Crypt::PBKDF2->new (
      hasher       => $hasher,
      iterations   => $iterations,
      output_len   => 32
    );

    my $key = $pbkdf2->PBKDF2 ($salt_buf_bin, $word_buf);

    my $cipher = Crypt::CBC->new ({
      key         => $key,
      cipher      => "Crypt::Rijndael",
      iv          => $salt_buf_bin,
      literal_key => 1,
      header      => "none",
      keysize     => 32
    });

    my $encrypted = unpack ("H*", $cipher->encrypt ($data));

    $tmp_hash = sprintf ("\$blockchain\$v2\$%d\$%s\$%s", $iterations, length ($salt_buf . $encrypted) / 2, $salt_buf . $encrypted);
  }
  elsif ($mode == 15300 || $mode == 15900)
  {
    my @salt_arr = split ('\*', $salt_buf);

    my $version          = $salt_arr[0];

    my $context          = $salt_arr[1];

    my $SID              = $salt_arr[2];

    my $cipher_algorithm = $salt_arr[3];

    my $hash_algorithm   = $salt_arr[4];

    my $iterations       = $salt_arr[5];

    my $salt             = pack ("H*", $salt_arr[6]);

    my $cipher_len       = $salt_arr[7];

    my $cipher;

    # intermediate values

    my $user_hash;
    my $user_derivationKey;
    my $encKey;
    my $expected_hmac;
    my $cleartext;

    if ($context == 1)
    {
       $user_hash = sha1 (encode ("UTF-16LE", $word_buf));
    }
    elsif ($context == 2)
    {
       $user_hash = md4 (encode ("UTF-16LE", $word_buf));
    }

    $user_derivationKey = hmac_sha1 (encode ("UTF-16LE", $SID . "\x00"), $user_hash);

    my $hmacSalt = randbytes (16);
    my $last_key = randbytes (64);

    if ($version == 1)
    {
      $encKey        = hmac_sha1 ($hmacSalt, $user_derivationKey);
      $expected_hmac = hmac_sha1 ($last_key, $encKey);

      # need padding because keyLen is 24 and hashLen 20
      $expected_hmac = $expected_hmac . randbytes (4);
    }
    elsif ($version == 2)
    {
      $encKey        = hmac_sha512 ($hmacSalt, $user_derivationKey);
      $expected_hmac = hmac_sha512 ($last_key, $encKey);
    }

    $cleartext = $hmacSalt . $expected_hmac . $last_key;

    my $derived_key;
    my $key;
    my $iv;

    my $pbkdf2;

    if ($version == 1)
    {
      $derived_key = dpapi_pbkdf2 ($user_derivationKey, $salt, $iterations, 32, \&hmac_sha1);
    }
    elsif ($version == 2)
    {
      $derived_key = dpapi_pbkdf2 ($user_derivationKey, $salt, $iterations, 48, \&hmac_sha512);
    }

    if (defined $additional_param)
    {
      $cipher = pack ("H*", $additional_param);
      my $computed_hmac = "";

      if ($version == 1)
      {
        $key = substr ($derived_key,   0, 24);
        $iv  = substr ($derived_key,  24,  8);

        my $p1 = Crypt::ECB->new ({
          key         => substr ($key, 0, 8),
          cipher      => "DES",
          literal_key => 1,
          header      => "none",
          keysize     => 8,
          padding     => "null",
        });

        my $p2 = Crypt::ECB->new ({
          key         => substr ($key, 8, 8),
          cipher      => "DES",
          literal_key => 1,
          header      => "none",
          keysize     => 8,
          padding     => "null",
        });

        my $p3 = Crypt::ECB->new ({
          key         => substr ($key, 16, 8),
          cipher      => "DES",
          literal_key => 1,
          header      => "none",
          keysize     => 8,
          padding     => "null",
        });

        # let's compute a 3DES-EDE-CBC decryption

        my $out1;
        my $out2;
        my $out3;
        my $expected_cleartext = "";

        # size of cipherlen is 104 bytes
        for (my $k = 0; $k < 13; $k++)
        {
          $out1 = $p3->decrypt (substr ($cipher, $k * 8, 8));
          $out2 = $p2->encrypt ($out1);
          $out3 = $p1->decrypt ($out2);

          $expected_cleartext .= substr ($out3, 0, 8) ^ $iv;

          $iv = substr ($cipher, $k * 8, 8);
        }

        $last_key      = substr ($expected_cleartext,  length ($expected_cleartext) - 64, 64);
        $hmacSalt      = substr ($expected_cleartext, 0, 16);
        $expected_hmac = substr ($expected_cleartext, 16, 20);

        $encKey        = hmac_sha1 ($hmacSalt, $user_derivationKey);
        $computed_hmac = hmac_sha1 ($last_key, $encKey);

        $cleartext = $expected_cleartext;

        if (unpack ("H*", $expected_hmac) ne unpack ("H*", $computed_hmac))
        {
          $cleartext = "0" x 104;
        }
      }
      elsif ($version == 2)
      {
        $key = substr ($derived_key,  0, 32);
        $iv  = substr ($derived_key, 32, 16);

        my $aes = Crypt::CBC->new ({
          key         => $key,
          cipher      => "Crypt::Rijndael",
          iv          => $iv,
          literal_key => 1,
          header      => "none",
          keysize     => 32,
          padding     => "null",
        });

        my $expected_cleartext = $aes->decrypt ($cipher);

        $last_key      = substr ($expected_cleartext,  length ($expected_cleartext) - 64, 64);
        $hmacSalt      = substr ($expected_cleartext, 0, 16);
        $expected_hmac = substr ($expected_cleartext, 16, 64);

        $encKey        = hmac_sha512 ($hmacSalt, $user_derivationKey);
        $computed_hmac = hmac_sha512 ($last_key, $encKey);

        $cleartext = $expected_cleartext;

        if (unpack ("H*", $expected_hmac) ne unpack ("H*", $computed_hmac))
        {
          $cleartext = "0" x 144;
        }
      }
    }

    if ($version == 1)
    {
      $key = substr ($derived_key,   0, 24);
      $iv  = substr ($derived_key,  24,  8);

      my $p1 = Crypt::ECB->new ({
        key         => substr ($key, 0, 8),
        cipher      => "DES",
        literal_key => 1,
        header      => "none",
        keysize     => 8,
        padding     => "null",
      });

      my $p2 = Crypt::ECB->new ({
        key         => substr ($key, 8, 8),
        cipher      => "DES",
        literal_key => 1,
        header      => "none",
        keysize     => 8,
        padding     => "null",
      });

      my $p3 = Crypt::ECB->new ({
        key         => substr ($key, 16, 8),
        cipher      => "DES",
        literal_key => 1,
        header      => "none",
        keysize     => 8,
        padding     => "null",
      });

      # let's compute a 3DES-EDE-CBC encryption

      # compute first block
      my $out1 = $p1->encrypt (substr ($cleartext, 0, 8) ^ $iv);
      my $out2 = $p2->decrypt ($out1);
      my $out3 = $p3->encrypt ($out2);

      $cipher = substr ($out3, 0, 8);

      # size of cipherlen is 104 bytes
      for (my $k = 1; $k < 13; $k++)
      {
        $iv = $out3;

        $out1 = $p1->encrypt (substr ($cleartext, $k * 8, 8) ^ $iv);
        $out2 = $p2->decrypt ($out1);
        $out3 = $p3->encrypt ($out2);

        $cipher .= substr ($out3, 0, 8);
      }
    }
    else
    {
      $key = substr ($derived_key,  0, 32);
      $iv  = substr ($derived_key, 32, 16);

      my $aes = Crypt::CBC->new ({
        key         => $key,
        cipher      => "Crypt::Rijndael",
        iv          => $iv,
        literal_key => 1,
        header      => "none",
        keysize     => 32,
        padding     => "null",
      });

      $cipher = $aes->encrypt ($cleartext);
    }

    $tmp_hash = sprintf ('$DPAPImk$%d*%d*%s*%s*%s*%d*%s*%d*%s',
                 $version,
                 $context,
                 $SID,
                 $cipher_algorithm,
                 $hash_algorithm,
                 $iterations,
                 unpack ("H*", $salt),
                 $cipher_len,
                 unpack ("H*", $cipher));
  }
  elsif ($mode == 15400)
  {
    my $counter;
    my $offset;
    my $iv;

    if (defined $additional_param)
    {
      $counter = $additional_param;
      $offset  = $additional_param2;
      $iv      = $additional_param3;
    }
    else
    {
      $counter = "0400000000000003";
      $offset  = int (rand (63));
      $iv      = "0200000000000001";
    }

    my $plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0a2b4c6d8e";
    my $eight_byte_iv = pack ("H*", $iv);
    my $eight_byte_counter = pack ("H*", $counter);
    my $pad_len = 32 - length ($word_buf);
    my $key = $word_buf . "\0" x $pad_len;

    my $cipher = Crypt::OpenSSH::ChachaPoly->new ($key);

    $cipher->ivsetup ($eight_byte_iv, $eight_byte_counter);

    my $enc = $cipher->encrypt ($plaintext);

    my $enc_offset = substr ($enc, $offset, 8);

    $hash_buf = $enc_offset;

    $tmp_hash = sprintf ("\$chacha20\$\*%s\*%d\*%s\*%s\*%s", $counter, $offset, $iv, unpack ("H*", substr ($plaintext, $offset, 8)), unpack ("H*", $enc_offset));
  }
  elsif ($mode == 15500)
  {
    my $iv = pack ("H*", $salt_buf);

    if (length $additional_param)
    {
      $iv = pack ("H*", $additional_param);
    }

    my $enc_key = randbytes (get_random_num (1, 1500));

    if (length $additional_param2)
    {
      $enc_key = pack ("H*", $additional_param2);
    }

    my $alias = "test";

    if (length $additional_param3)
    {
      $alias = $additional_param3;
    }

    my $word_buf_utf16be = encode ("UTF-16BE", $word_buf);

    my $hash_buf = sha1 ($word_buf_utf16be . $iv);

    my $DER1 = substr ($hash_buf, 0, 1);
    my $DER2 = substr ($hash_buf, 6, 14);

    my @enc_key_data = split "", $enc_key;

    my $enc_key_data_length = scalar @enc_key_data;

    my @key_data = ();

    for (my $i = 0; $i < scalar $enc_key_data_length; $i += 20)
    {
      my @hash_buf_data = split "", $hash_buf;

      for (my $j = 0; $j < 20; $j++)
      {
        last if (($i + $j) >= $enc_key_data_length);

        $key_data[$i + $j] = $enc_key_data[$i + $j] ^ $hash_buf_data[$j];
      }

      $hash_buf = sha1 ($word_buf_utf16be . $hash_buf);
    }

    my $key = join "", @key_data;

    $hash_buf = sha1 ($word_buf_utf16be . $key);

    $tmp_hash = sprintf ("\$jksprivk\$*%s*%s*%s*%s*%s*%s", uc unpack ("H*", $hash_buf), uc unpack ("H*", $iv), uc unpack ("H*", $enc_key), uc unpack ("H*", $DER1), uc unpack ("H*", $DER2), $alias);
  }
  elsif ($mode == 15600)
  {
    my $iterations;
    my $ciphertext;

    if (defined $additional_param)
    {
      $iterations = $iter;
      $ciphertext = $additional_param;
    }
    else
    {
      $iterations = 1024; # 262144 originally
      $ciphertext = randbytes (32);
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      out_len    => 32
    );

    my $derived_key = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

    my $derived_key_cropped = substr ($derived_key, 16, 16);

    $hash_buf = keccak_256_hex ($derived_key_cropped . $ciphertext);

    $tmp_hash = sprintf ("\$ethereum\$p*%i*%s*%s*%s", $iterations, unpack ("H*", $salt_buf), unpack ("H*", $ciphertext), $hash_buf);
  }
  elsif ($mode == 15700)
  {
    my $scrypt_N;
    my $scrypt_r;
    my $scrypt_p;

    my $ciphertext;

    if (defined $additional_param)
    {
      $scrypt_N = $additional_param;
      $scrypt_r = $additional_param2;
      $scrypt_p = $additional_param3;
      $ciphertext = $additional_param4;
    }
    else
    {
      $scrypt_N = 1024; # 262144 originally
      $scrypt_r = 1;    # 8 originally
      $scrypt_p = 1;
      $ciphertext = randbytes (32);
    }

    my $derived_key = scrypt_raw ($word_buf, $salt_buf, $scrypt_N, $scrypt_r, $scrypt_p, 32);

    my $derived_key_cropped = substr ($derived_key, 16, 16);

    $hash_buf = keccak_256_hex ($derived_key_cropped . $ciphertext);

    $tmp_hash = sprintf ("\$ethereum\$s*%i*%i*%i*%s*%s*%s", $scrypt_N, $scrypt_r, $scrypt_p, unpack ("H*", $salt_buf), unpack ("H*", $ciphertext), $hash_buf);
  }
  elsif ($mode == 16000)
  {
    my $converter = Text::Iconv->new ("utf-8", "shift-jis");

    $word_buf = $converter->convert ($word_buf);

    $salt_buf = substr ($word_buf . '..', 1, 2);

    $salt_buf =~ s/[^\.-z]/\./go;

    $salt_buf =~ tr/:;<=>?@[\\]^_`/A-Ga-f/;

    $hash_buf = crypt ($word_buf, $salt_buf);

    $hash_buf = substr ($hash_buf, -10);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 16100)
  {
    my $session_id;
    my $encrypted_data;
    my $sequence;

    if (defined $additional_param)
    {
      $session_id = pack ("H*", $additional_param);
    }
    else
    {
      $session_id = pack ("H*", randbytes (8));
    }

    if (defined $additional_param2)
    {
      $encrypted_data = pack ("H*", $additional_param2);
    }

    if (defined $additional_param3)
    {
      $sequence = pack ("H*", $additional_param3);
    }
    else
    {
      $sequence = pack ("H*", "c006");
    }

    my $key = md5 ($session_id . $word_buf . $sequence);

    if (defined $encrypted_data)
    {
      ## verify case

      my $encrypted_data_len = length $encrypted_data;

      my $plain_data = substr ($encrypted_data, 0, 6) ^ substr ($key, 0, 6);

      my ($status, $flags, $server_msg_len, $data_len) = unpack ("CCnn", $plain_data);

      if ((($status >= 0x01 && $status <= 0x07) || $status == 0x21)
       &&  ($flags  == 0x01 || $flags  == 0x00)
       &&  (6 + $server_msg_len + $data_len == $encrypted_data_len))
      {
        ## ok
      }
      else
      {
        $encrypted_data = ""; # some invalid data
      }
    }
    else
    {
      my $plain_data = "\x01\x00\x00\x00\x00\x00";

      my $plain_data_len = length $plain_data;

      my $shortest = ($plain_data_len > 16) ? 16 : $plain_data_len;

      $encrypted_data = substr ($plain_data, 0, $shortest) ^ substr ($key, 0, $shortest);
    }

    $tmp_hash = sprintf ('$tacacs-plus$0$%s$%s$%s', unpack ("H*", $session_id), unpack ("H*", $encrypted_data), unpack ("H*", $sequence));
  }
  elsif ($mode == 16200)
  {
    my $salt_bin = pack ("H*", $salt_buf);

    my $iterations = 20000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $Z_PK = 1;

    if (defined $additional_param)
    {
      $Z_PK = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => 16,
    );

    my $KEK = $pbkdf2->PBKDF2 ($salt_bin, $word_buf);

    my $aes = Crypt::Mode::ECB->new ('AES', 0);

    my $blob_bin;

    my $A;
    my $B;
    my $P1;
    my $P2;

    if (defined $additional_param2)
    {
      $blob_bin = pack ("H*", $additional_param2);

      $A  = substr ($blob_bin,  0, 8);
      $P1 = substr ($blob_bin,  8, 8);
      $P2 = substr ($blob_bin, 16, 8);

      for (my $j = 5; $j >= 0; $j--)
      {
        # N = 2

        $B  = $A;
        $B ^= pack ("Q>", (2 * $j + 2));
        $B .= $P2;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P2 = substr ($B, 8, 8);

        # N = 1

        $B  = $A;
        $B ^= pack ("Q>", (2 * $j + 1));
        $B .= $P1;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P1 = substr ($B, 8, 8);
      }

      if ($A eq "\xa6" x 8)
      {
        for (my $j = 0; $j <= 5; $j++)
        {
          # N = 1

          $B  = $A;
          $B .= $P1;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (2 * $j + 1));
          $P1 = substr ($B, 8, 8);

          # N = 2

          $B  = $A;
          $B .= $P2;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (2 * $j + 2));
          $P2 = substr ($B, 8, 8);
        }

        $blob_bin = $A . $P1 . $P2;
      }
      else
      {
        $blob_bin = "\xff" x 24;
      }
    }
    else
    {
      $A  = "\xa6" x 8;
      $P1 = "\xff" x 8;
      $P2 = "\xff" x 8;

      for (my $j = 0; $j <= 5; $j++)
      {
        # N = 1

        $B  = $A;
        $B .= $P1;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (2 * $j + 1));
        $P1 = substr ($B, 8, 8);

        # N = 2

        $B  = $A;
        $B .= $P2;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (2 * $j + 2));
        $P2 = substr ($B, 8, 8);
      }

      $blob_bin = $A . $P1 . $P2;
    }

    $tmp_hash = sprintf ('$ASN$*%d*%d*%s*%s', $Z_PK, $iterations, unpack ("H*", $salt_bin), unpack ("H*", $blob_bin));
  }
  elsif ($mode == 16300)
  {
    my $ethaddr = $salt_buf;

    my $iv      = "";
    my $seed    = "";
    my $encseed = "";

    # setup pbkdf2 params:

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => 2000,
      output_len => 16
    );

    my $key = $pbkdf2->PBKDF2 ($word_buf, $word_buf);

    if (defined $additional_param)
    {
      $iv      = substr ($additional_param, 0, 16);
      $encseed = substr ($additional_param, 16);

      # AES-128-CBC decrypt:

      my $aes_cbc = Crypt::CBC->new ({
        key         => $key,
        cipher      => "Crypt::Rijndael",
        iv          => $iv,
        literal_key => 1,
        header      => "none",
        keysize     => 16
      });

      $seed = $aes_cbc->decrypt ($encseed);
    }
    else
    {
      $iv   = randbytes (16);
      $seed = randbytes (592);

      # AES-128-CBC encrypt:

      my $aes_cbc = Crypt::CBC->new ({
        key         => $key,
        cipher      => "Crypt::Rijndael",
        iv          => $iv,
        literal_key => 1,
        header      => "none",
        keysize     => 16
      });

      $encseed = $aes_cbc->encrypt ($seed);
    }

    $hash_buf = keccak_256_hex ($seed . "\x02");

    $tmp_hash = sprintf ("\$ethereum\$w*%s*%s*%s", unpack ("H*", $iv . $encseed), $ethaddr, substr ($hash_buf, 0, 32));
  }
  elsif ($mode == 16400)
  {
    my $md5 = Digest::Perl::MD5->new;
    my $length = length($word_buf);

    $md5->{_data} = $word_buf ^ ("\x5c" x $length);
    $md5->{_data} .= "\x5c" x (64 - $length);
    $md5->add();

    $hash_buf = unpack("H*", pack('V4', @{$md5->{_state}}));
    $tmp_hash = sprintf ("{CRAM-MD5}%s00000000000000000000000000000000", $hash_buf);
  }
  elsif ($mode == 16500)
  {
    my ($header_base64) = split (/\./, $salt_buf);

    my $header_jwt = decode_base64url ($header_base64);

    my $header = decode_json ($header_jwt);

    my $alg = $header->{"alg"};

    if ($alg eq "HS256")
    {
      $hash_buf = hmac ($salt_buf, $word_buf, \&sha256, 64);
    }
    elsif ($alg eq "HS384")
    {
      $hash_buf = hmac ($salt_buf, $word_buf, \&sha384, 128);
    }
    elsif ($alg eq "HS512")
    {
      $hash_buf = hmac ($salt_buf, $word_buf, \&sha512, 128);
    }
    else
    {
      die "not supported hash\n";
    }

    $tmp_hash = sprintf ("%s.%s", $salt_buf, encode_base64url ($hash_buf, ""));
  }
  elsif ($mode == 16600)
  {
    my $key_bin = sha256 (sha256 ($word_buf));

    my $salt_type;

    if (defined $additional_param)
    {
      $salt_type = $additional_param;

      if ($salt_type ne "1") { die "currently only salt_type 1 supported\n"; }
    }
    else
    {
      $salt_type = 1;
    }

    my $iv;

    if (defined $additional_param2)
    {
      $iv = $additional_param2;
    }
    else
    {
      $iv = substr ($salt_buf, 0, 32);
    }

    my $iv_bin = pack ("H*", $iv);

    my $cipher = Crypt::CBC->new ({
      key         => $key_bin,
      cipher      => "Crypt::Rijndael",
      iv          => $iv_bin,
      literal_key => 1,
      header      => "none",
      keysize     => 32,
      padding     => "null",
    });

    my $plain_bin;

    if (defined $additional_param3)
    {
      my $encrypted_bin = pack ("H*", $additional_param3);

      my $test = $cipher->decrypt ($encrypted_bin);

      if ($test =~ /^[0-9a-f]+$/)
      {
        $plain_bin = $test;
      }
      else
      {
        $plain_bin = "\xff" x 16;
      }
    }
    else
    {
      my $plain = "30313233343536373839616263646566";

      $plain_bin = pack ("H*", $plain);
    }

    my $encrypted_bin = $cipher->encrypt ($plain_bin);

    my $encrypted = unpack ("H*", $encrypted_bin);

    $tmp_hash = sprintf ("\$electrum\$%d*%s*%s", $salt_type, $iv, $encrypted);
  }
  elsif ($mode == 16700)
  {
    my $salt_bin = pack ("H*", $salt_buf);

    my $iterations = 20000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $Z_PK = 1;

    if (defined $additional_param)
    {
      $Z_PK = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => 16,
    );

    my $KEK = $pbkdf2->PBKDF2 ($salt_bin, $word_buf);

    my $aes = Crypt::Mode::ECB->new ('AES', 0);

    my $blob_bin;

    my $A;
    my $B;
    my $P1;
    my $P2;

    if (defined $additional_param2)
    {
      $blob_bin = pack ("H*", $additional_param2);

      $A  = substr ($blob_bin,  0, 8);
      $P1 = substr ($blob_bin,  8, 8);
      $P2 = substr ($blob_bin, 16, 8);

      for (my $j = 5; $j >= 0; $j--)
      {
        # N = 2

        $B  = $A;
        $B ^= pack ("Q>", (2 * $j + 2));
        $B .= $P2;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P2 = substr ($B, 8, 8);

        # N = 1

        $B  = $A;
        $B ^= pack ("Q>", (2 * $j + 1));
        $B .= $P1;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P1 = substr ($B, 8, 8);
      }

      if ($A eq "\xa6" x 8)
      {
        for (my $j = 0; $j <= 5; $j++)
        {
          # N = 1

          $B  = $A;
          $B .= $P1;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (2 * $j + 1));
          $P1 = substr ($B, 8, 8);

          # N = 2

          $B  = $A;
          $B .= $P2;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (2 * $j + 2));
          $P2 = substr ($B, 8, 8);
        }

        $blob_bin = $A . $P1 . $P2;
      }
      else
      {
        $blob_bin = "\xff" x 24;
      }
    }
    else
    {
      $A  = "\xa6" x 8;
      $P1 = "\xff" x 8;
      $P2 = "\xff" x 8;

      for (my $j = 0; $j <= 5; $j++)
      {
        # N = 1

        $B  = $A;
        $B .= $P1;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (2 * $j + 1));
        $P1 = substr ($B, 8, 8);

        # N = 2

        $B  = $A;
        $B .= $P2;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (2 * $j + 2));
        $P2 = substr ($B, 8, 8);
      }

      $blob_bin = $A . $P1 . $P2;
    }

    $tmp_hash = sprintf ('$fvde$%d$%d$%s$%d$%s', $Z_PK, length ($salt_bin), unpack ("H*", $salt_bin), $iterations, unpack ("H*", $blob_bin));
  }
  elsif ($mode == 16800)
  {
    my $macap;
    my $macsta;
    my $essid;

    if (!defined ($additional_param))
    {
      $macap = unpack ("H*", randbytes (6));
    }
    else
    {
      $macap = $additional_param;
    }

    if (!defined ($additional_param2))
    {
      $macsta = unpack ("H*", randbytes (6));
    }
    else
    {
      $macsta = $additional_param2;
    }

    if (!defined ($additional_param3))
    {
      $essid = unpack ("H*", randbytes (get_random_num (8, 32) & 0x1e));
    }
    else
    {
      $essid = $additional_param3;
    }

    # generate the Pairwise Master Key (PMK)

    my $iterations = 4096;

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iterations,
      output_len => 32,
    );

    my $essid_bin = pack ("H*", $essid);

    my $pmk = $pbkdf2->PBKDF2 ($essid_bin, $word_buf);

    my $macap_bin  = pack ("H*", $macap);
    my $macsta_bin = pack ("H*", $macsta);

    my $data = "PMK Name" . $macap_bin . $macsta_bin;

    my $pmkid = hmac_hex ($data, $pmk, \&sha1);

    $tmp_hash = sprintf ("%s*%s*%s*%s", substr ($pmkid, 0, 32), $macap, $macsta, $essid);
  }
  elsif ($mode == 17300)
  {
    $hash_buf = sha3_224_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 17400)
  {
    $hash_buf = sha3_256_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 17500)
  {
    $hash_buf = sha3_384_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 17600)
  {
    $hash_buf = sha3_512_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 17700)
  {
    $hash_buf = keccak_224_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 17800)
  {
    $hash_buf = keccak_256_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 17900)
  {
    $hash_buf = keccak_384_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 18000)
  {
    $hash_buf = keccak_512_hex ($word_buf);

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 18100)
  {
    my $paddedTime = sprintf ("%016x", int (int ($salt_buf) / 30));
    my $data = pack ('H*', $paddedTime);
    my $key = $word_buf;

    $hash_buf = hmac_hex ($data, $key, \&sha1, 64);

    my $offset = hex (substr ($hash_buf, -8)) & 0xf;
    $offset *= 2;
    my $token = hex (substr ($hash_buf, $offset, 8));
    $token &= 0x7fffffff;
    $token %= 1000000;

    ## token must be leading zero padded, and salt leading zero stripped
    $tmp_hash = sprintf ("%06d:%d", $token, int ($salt_buf));
  }
  elsif ($mode == 18200)
  {
    my @salt_arr = split (':', $salt_buf);

    my $user_principal_name = $salt_arr[0];

    my $k = md4 (encode ("UTF-16LE", $word_buf));

    my $k1 = hmac_md5 ("\x08\x00\x00\x00", $k);

    my $cleartext_ticket = '7981df3081dca01b3019a003020117a112041071e026814da2' .
    '3f129f0e67a01b73f79aa11c301a3018a003020100a111180f32303138313033303039353' .
    '831365aa206020460fdc6caa311180f32303337303931343032343830355aa40703050050' .
    'c10000a511180f32303138313033303039353831365aa611180f323031383130333030393' .
    '53831365aa711180f32303138313033303139353831365aa811180f323031383130333131' .
    '30303433385aa90d1b0b545952454c4c2e434f5250aa20301ea003020101a11730151b066' .
    'b72627467741b0b545952454c4c2e434f5250';
    my $checksum = "";

    if (defined $additional_param)
    {
      $checksum = pack ("H*", $additional_param);
    }
    else
    {
      my $nonce = $salt_arr[1];

      $cleartext_ticket = $nonce . $cleartext_ticket;

      $checksum = hmac_md5 (pack ("H*", $cleartext_ticket), $k1);
    }

    my $k3 = hmac_md5 ($checksum, $k1);

    my $edata2 = "";

    if (defined $additional_param2)
    {
      $edata2 = $additional_param2;

      my $cipher_decrypt = Crypt::RC4->new ($k3);

      my $ticket_decrypt = unpack ("H*", $cipher_decrypt->RC4 (pack ("H*", $edata2)));

      my $check_correct  = ((substr ($ticket_decrypt, 16, 4) eq "7981" && substr ($ticket_decrypt, 22, 2) eq "30")) ||
                           ((substr ($ticket_decrypt, 16, 2) eq "79") && (substr ($ticket_decrypt, 20, 2) eq "30")) ||
                           ((substr ($ticket_decrypt, 16, 4) eq "7982")  && (substr ($ticket_decrypt, 24, 2) eq "30"));

      if ($check_correct == 1)
      {
        $cleartext_ticket = $ticket_decrypt;
      }
      else # validation failed
      {
        # fake/wrong ticket (otherwise if we just decrypt/encrypt we end up with false positives all the time)
        $cleartext_ticket = "0" x (length ($cleartext_ticket) + 16);
      }
    }

    my $cipher = Crypt::RC4->new ($k3);

    $edata2 = $cipher->RC4 (pack ("H*", $cleartext_ticket));

    $tmp_hash = sprintf ('$krb5asrep$23$%s:%s$%s', $user_principal_name, unpack ("H*", $checksum), unpack ("H*", $edata2));
  }
  elsif ($mode == 18300)
  {
    my $salt_bin = pack ("H*", $salt_buf);

    my $iterations = 20000;

    if (defined ($iter))
    {
      $iterations = $iter;
    }

    my $Z_PK = 2;

    if (defined $additional_param)
    {
      $Z_PK = $additional_param;
    }

    my $pbkdf2 = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iterations,
      output_len => 32,
    );

    my $KEK = $pbkdf2->PBKDF2 ($salt_bin, $word_buf);

    my $aes = Crypt::Mode::ECB->new ('AES', 0);

    my $blob_bin;

    my $A;
    my $B;
    my $P1;
    my $P2;
    my $P3;
    my $P4;

    if (defined $additional_param2)
    {
      $blob_bin = pack ("H*", $additional_param2);

      $A  = substr ($blob_bin,  0, 8);
      $P1 = substr ($blob_bin,  8, 8);
      $P2 = substr ($blob_bin, 16, 8);
      $P3 = substr ($blob_bin, 24, 8);
      $P4 = substr ($blob_bin, 32, 8);

      for (my $j = 5; $j >= 0; $j--)
      {
        # N = 4

        $B  = $A;
        $B ^= pack ("Q>", (4 * $j + 4));
        $B .= $P4;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P4 = substr ($B, 8, 8);

        # N = 3

        $B  = $A;
        $B ^= pack ("Q>", (4 * $j + 3));
        $B .= $P3;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P3 = substr ($B, 8, 8);

        # N = 2

        $B  = $A;
        $B ^= pack ("Q>", (4 * $j + 2));
        $B .= $P2;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P2 = substr ($B, 8, 8);

        # N = 1

        $B  = $A;
        $B ^= pack ("Q>", (4 * $j + 1));
        $B .= $P1;
        $B  = $aes->decrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $P1 = substr ($B, 8, 8);
      }

      if ($A eq "\xa6" x 8)
      {
        for (my $j = 0; $j <= 5; $j++)
        {
          # N = 1

          $B  = $A;
          $B .= $P1;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (4 * $j + 1));
          $P1 = substr ($B, 8, 8);

          # N = 2

          $B  = $A;
          $B .= $P2;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (4 * $j + 2));
          $P2 = substr ($B, 8, 8);

          # N = 3

          $B  = $A;
          $B .= $P3;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (4 * $j + 3));
          $P3 = substr ($B, 8, 8);

          # N = 4

          $B  = $A;
          $B .= $P4;
          $B  = $aes->encrypt ($B, $KEK);
          $A  = substr ($B, 0, 8);
          $A ^= pack ("Q>", (4 * $j + 4));
          $P4 = substr ($B, 8, 8);
        }

        $blob_bin = $A . $P1 . $P2 . $P3 . $P4;
      }
      else
      {
        $blob_bin = "\xff" x 40;
      }
    }
    else
    {
      $A  = "\xa6" x 8;
      $P1 = "\xff" x 8;
      $P2 = "\xff" x 8;
      $P3 = "\xff" x 8;
      $P4 = "\xff" x 8;

      for (my $j = 0; $j <= 5; $j++)
      {
        # N = 1

        $B  = $A;
        $B .= $P1;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 1));
        $P1 = substr ($B, 8, 8);

        # N = 2

        $B  = $A;
        $B .= $P2;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 2));
        $P2 = substr ($B, 8, 8);

        # N = 3

        $B  = $A;
        $B .= $P3;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 3));
        $P3 = substr ($B, 8, 8);

        # N = 4

        $B  = $A;
        $B .= $P4;
        $B  = $aes->encrypt ($B, $KEK);
        $A  = substr ($B, 0, 8);
        $A ^= pack ("Q>", (4 * $j + 4));
        $P4 = substr ($B, 8, 8);
      }

      $blob_bin = $A . $P1 . $P2 . $P3 . $P4;
    }

    $tmp_hash = sprintf ('$fvde$%d$%d$%s$%d$%s', $Z_PK, length ($salt_bin), unpack ("H*", $salt_bin), $iterations, unpack ("H*", $blob_bin));
  }
  elsif ($mode == 18400)
  {
    # defaults for single mode
    my $iterations = 100000;
    my $iv         = "aa" x 16;
    my $plaintext  = "bb" x 1024;

    # parameters for verify mode
    if (defined $iter)
    {
      $iterations = $iter;
    }

    if (defined $additional_param)
    {
      $iv = $additional_param;
    }

    if (defined $additional_param2)
    {
      $plaintext = $additional_param2;
    }

    # binary buffers
    my $b_iv        = pack ("H*", $iv);
    my $b_salt      = pack ("H*", $salt_buf);
    my $b_plaintext = pack ("H*", $plaintext);

    my $kdf = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iterations,
      output_len => 32
    );

    my $checksum     = sha256_hex ($b_plaintext);

    my $pass_hash    = sha256 ($word_buf);
    my $derived_key  = $kdf->PBKDF2 ($b_salt, $pass_hash);
    my $cbc          = Crypt::Mode::CBC->new ('AES', 0);
    my $b_ciphertext = $cbc->encrypt ($b_plaintext, $derived_key, $b_iv);

    my $ciphertext   = unpack ("H*", $b_ciphertext);

    $tmp_hash = '$odf$'."*1*1*$iterations*32*$checksum*16*$iv*16*$salt_buf*0*$ciphertext";
  }
  elsif ($mode == 18500)
  {
    $hash_buf = sha1_hex (md5_hex (md5_hex ($word_buf)));

    $tmp_hash = sprintf ("%s", $hash_buf);
  }
  elsif ($mode == 18600)
  {
    # defaults for single mode
    my $iterations = 1024;
    my $iv         = "aa" x 8;
    my $plaintext  = "bb" x 1024;

    # parameters for verify mode
    if (defined $iter)
    {
      $iterations = $iter;
    }

    if (defined $additional_param)
    {
      $iv = $additional_param;
    }

    if (defined $additional_param2)
    {
      $plaintext = $additional_param2;
    }

    # binary buffers
    my $b_iv        = pack ("H*", $iv);
    my $b_salt      = pack ("H*", $salt_buf);
    my $b_plaintext = pack ("H*", $plaintext);

    my $kdf = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iterations,
      output_len => 16
    );

    my $checksum    = sha1_hex ($b_plaintext);
    my $pass_hash   = sha1 ($word_buf);
    my $derived_key = $kdf->PBKDF2 ($b_salt, $pass_hash);

    my $cfb = Crypt::GCrypt->new(
      type      => 'cipher',
      algorithm => 'blowfish',
      mode      => 'cfb',
    );

    $cfb->start  ('encrypting');
    $cfb->setkey ($derived_key);
    $cfb->setiv  ($b_iv);

    my $b_ciphertext = $cfb->encrypt ($b_plaintext);

    $cfb->finish ();

    my $ciphertext = unpack ("H*", $b_ciphertext);

    $tmp_hash = '$odf$'."*0*0*$iterations*16*$checksum*8*$iv*16*$salt_buf*0*$ciphertext";
  }
  elsif ($mode == 99999)
  {
    $tmp_hash = sprintf ("%s", $word_buf);
  }

  return ($tmp_hash);
}

#Thanks to Jochen Hoenicke <hoenicke@gmail.com>
# (one of the authors of Palm Keyring)
# for these next two subs.
sub dpapi_pbkdf2
{
    my ($password, $salt, $iter, $keylen, $prf) = @_;
    my ($k, $t, $u, $ui, $i);
    $t = "";
    for ($k = 1; length ($t) <  $keylen; $k++)
    {
      $u = $ui = &$prf ($salt.pack ('N', $k), $password);
      for ($i = 1; $i < $iter; $i++)
      {
        # modification to fit Microsoft
        # weird pbkdf2 implementation...
        $ui = &$prf ($u, $password);
        $u ^= $ui;
      }
      $t .= $u;
    }
    return substr ($t, 0, $keylen);
}

## STEP 4: Add custom traits here (optional).
sub rnd
{
  my $mode = shift;

  my $word_len = shift;

  my $salt_len = shift;

  my $max = $MAX_LEN;

  if ($mode == 2410)
  {
    $salt_len = min ($salt_len, 4);
  }

  if (is_in_array ($mode, $IS_UTF16LE))
  {
    if (is_in_array ($mode, $ALLOW_LONG_SALT))
    {
      $word_len = min ($word_len, int ($max / 2));
    }
    else
    {
      $word_len = min ($word_len, int ($max / 2) - $salt_len);
    }
  }
  elsif (is_in_array ($mode, $LESS_FIFTEEN))
  {
    $word_len = min ($word_len, 15);
  }
  else
  {
    if (! is_in_array ($mode, $ALLOW_LONG_SALT))
    {
      $word_len = min ($word_len, $max - $salt_len);
    }
  }

  if ($word_len < 1)
  {
    $word_len = 1;
  }

  ##
  ## gen salt
  ##

  my $salt_buf;

  if ($mode == 4800)
  {
    my @salt_arr;

    for (my $i = 0; $i < $salt_len; $i++)
    {
      my $c = get_random_chr (0x30, 0x39);

      push (@salt_arr, $c);
    }

    $salt_buf = join ("", @salt_arr);

    $salt_buf = get_random_md5chap_salt ($salt_buf);
  }
  elsif ($mode == 5300 || $mode == 5400)
  {
    $salt_buf = get_random_ike_salt ();
  }
  elsif ($mode == 5500)
  {
    $salt_buf = get_random_netntlmv1_salt ($salt_len, $salt_len);
  }
  elsif ($mode == 5600)
  {
    $salt_buf = get_random_netntlmv2_salt ($salt_len, $salt_len);
  }
  elsif ($mode == 6600)
  {
    $salt_buf = get_random_agilekeychain_salt ();
  }
  elsif ($mode == 8200)
  {
    $salt_buf = get_random_cloudkeychain_salt ();
  }
  elsif ($mode == 8300)
  {
    $salt_buf = get_random_dnssec_salt ();
  }
  elsif ($mode == 13100)
  {
    $salt_buf = get_random_kerberos5_tgs_salt ();
  }
  elsif ($mode == 13200)
  {
    $salt_buf = get_random_axcrypt_salt ();
  }
  elsif ($mode == 13400)
  {
    $salt_buf = get_random_keepass_salt ();
  }
  elsif ($mode == 13500)
  {
    $salt_buf = get_pstoken_salt ();
  }
  elsif ($mode == 15300 || $mode == 15900)
  {
    my $version = 2;

    if ($mode == 15300)
    {
      $version = 1;
    }

    $salt_buf = get_random_dpapimk_salt ($version);
  }
  elsif ($mode == 16500)
  {
    $salt_buf = get_random_jwt_salt ();
  }
  elsif ($mode == 18200)
  {
    $salt_buf = get_random_kerberos5_as_rep_salt ();
  }
  else
  {
    my @salt_arr;

    for (my $i = 0; $i < $salt_len; $i++)
    {
      my $c = get_random_chr (0x30, 0x39);

      push (@salt_arr, $c);
    }

    $salt_buf = join ("", @salt_arr);

    if ($mode == 7500)
    {
      $salt_buf = get_random_kerberos5_salt ($salt_buf);
    }
  }

  ##
  ## gen plain
  ##

  my @word_arr;

  for (my $i = 0; $i < $word_len; $i++)
  {
    my $c = get_random_chr (0x30, 0x39);

    if (($mode == 14000) || ($mode == 14100))
    {
      $c &= 0xfe;
    }

    push (@word_arr, $c);
  }

  my $word_buf = join ("", @word_arr);

  ##
  ## gen hash
  ##

  my $tmp_hash = gen_hash ($mode, $word_buf, $salt_buf);

  ##
  ## run
  ##

  my @cmd =
  (
    $hashcat,
    "-a 0 -m", $mode,
    $tmp_hash
  );

  print sprintf ("echo -n %-20s | %s \${OPTS} %s %4d '%s'\n", $word_buf, @cmd);
}

##
## subs
##

sub min
{
  $_[$_[0] > $_[1]];
}

sub get_random_string
{
  my $len = shift;

  my @arr;

  for (my $i = 0; $i < $len; $i++)
  {
    my $c = get_random_chr (0x30, 0x39);

    push (@arr, $c);
  }

  my $buf = join ("", @arr);

  return $buf;
}

sub get_random_num
{
  my $min = shift;
  my $max = shift;

  return int ((rand ($max - $min)) + $min);
}

sub get_random_chr
{
  return chr get_random_num (@_);
}

sub domino_decode
{
  my $str = shift;

  my $decoded  = "";

  for (my $i = 0; $i < length ($str); $i += 4)
  {
    my $num = domino_base64_decode (substr ($str, $i, 4), 4);

    $decoded .= chr (($num >> 16) & 0xff) . chr (($num >> 8) & 0xff) . chr ($num & 0xff);
  }

  my $salt;
  my $digest;
  my $char;

  $salt   = substr ($decoded,  0, 5);

  my $byte10 = (ord (substr ($salt, 3, 1)) - 4);

  if ($byte10 < 0)
  {
    $byte10 = 256 + $byte10;
  }

  substr ($salt, 3, 1) = chr ($byte10);

  $digest = substr ($decoded,  5, 9);
  $char   = substr ($str,     18, 1);

  return ($digest, $salt, $char);
}

sub domino_85x_decode
{
  my $str = shift;

  my $decoded  = "";

  for (my $i = 0; $i < length ($str); $i += 4)
  {
    my $num = domino_base64_decode (substr ($str, $i, 4), 4);

    $decoded .= chr (($num >> 16) & 0xff) . chr (($num >> 8) & 0xff) . chr ($num & 0xff);
  }

  my $digest;
  my $salt;
  my $iterations = -1;
  my $chars;

  $salt   = substr ($decoded,  0, 16);  # longer than -m 8700 (5 vs 16 <- new)

  my $byte10 = (ord (substr ($salt, 3, 1)) - 4);

  if ($byte10 < 0)
  {
    $byte10 = 256 + $byte10;
  }

  substr ($salt, 3, 1) = chr ($byte10);

  $iterations = substr ($decoded,  16, 10);

  if ($iterations =~ /^?d*$/)
  {
    # continue

    $iterations = $iterations + 0;            # hack: make sure it is an int now (atoi ())
    $chars = substr ($decoded, 26, 2);        # in my example it is "02"
    $digest = substr ($decoded, 28, 8);       # only of length of 8 vs 20 SHA1 bytes
  }

  return ($digest, $salt, $iterations, $chars);
}

sub domino_base64_decode
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

  my $ret = 0;

  my $i = 1;

  while ($i <= $n)
  {
    my $idx = (index ($itoa64, substr ($v, $n - $i, 1))) & 0x3f;

    $ret += ($idx << (6 * ($i - 1)));

    $i = $i + 1;
  }

  return $ret
}

sub domino_encode
{
  my $final = shift;
  my $char  = shift;

  my $byte10 = (ord (substr ($final, 3, 1)) + 4);

  if ($byte10 > 255)
  {
    $byte10 = $byte10 - 256;
  }

  substr ($final, 3, 1) = chr ($byte10);

  my $passwd = "";

  $passwd .= domino_base64_encode ((int (ord (substr ($final,  0, 1))) << 16) | (int (ord (substr ($final,  1, 1))) << 8) | (int (ord (substr ($final,  2, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  3, 1))) << 16) | (int (ord (substr ($final,  4, 1))) << 8) | (int (ord (substr ($final,  5, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  6, 1))) << 16) | (int (ord (substr ($final,  7, 1))) << 8) | (int (ord (substr ($final,  8, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  9, 1))) << 16) | (int (ord (substr ($final, 10, 1))) << 8) | (int (ord (substr ($final, 11, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 12, 1))) << 16) | (int (ord (substr ($final, 13, 1))) << 8) | (int (ord (substr ($final, 14, 1)))), 4);

  if (defined ($char))
  {
    substr ($passwd, 18, 1) = $char;
  }
  substr ($passwd, 19, 1) = "";

  return $passwd;
}

sub domino_85x_encode
{
  my $final = shift;
  my $char  = shift;

  my $byte10 = (ord (substr ($final, 3, 1)) + 4);

  if ($byte10 > 255)
  {
    $byte10 = $byte10 - 256;
  }

  substr ($final, 3, 1) = chr ($byte10);

  my $passwd = "";

  $passwd .= domino_base64_encode ((int (ord (substr ($final,  0, 1))) << 16) | (int (ord (substr ($final,  1, 1))) << 8) | (int (ord (substr ($final,  2, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  3, 1))) << 16) | (int (ord (substr ($final,  4, 1))) << 8) | (int (ord (substr ($final,  5, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  6, 1))) << 16) | (int (ord (substr ($final,  7, 1))) << 8) | (int (ord (substr ($final,  8, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final,  9, 1))) << 16) | (int (ord (substr ($final, 10, 1))) << 8) | (int (ord (substr ($final, 11, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 12, 1))) << 16) | (int (ord (substr ($final, 13, 1))) << 8) | (int (ord (substr ($final, 14, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 15, 1))) << 16) | (int (ord (substr ($final, 16, 1))) << 8) | (int (ord (substr ($final, 17, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 18, 1))) << 16) | (int (ord (substr ($final, 19, 1))) << 8) | (int (ord (substr ($final, 20, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 21, 1))) << 16) | (int (ord (substr ($final, 22, 1))) << 8) | (int (ord (substr ($final, 23, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 24, 1))) << 16) | (int (ord (substr ($final, 25, 1))) << 8) | (int (ord (substr ($final, 26, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 27, 1))) << 16) | (int (ord (substr ($final, 28, 1))) << 8) | (int (ord (substr ($final, 29, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 30, 1))) << 16) | (int (ord (substr ($final, 31, 1))) << 8) | (int (ord (substr ($final, 32, 1)))), 4);
  $passwd .= domino_base64_encode ((int (ord (substr ($final, 33, 1))) << 16) | (int (ord (substr ($final, 34, 1))) << 8) | (int (ord (substr ($final, 35, 1)))), 4);

  if (defined ($char))
  {
    substr ($passwd, 18, 1) = $char;
  }

  return $passwd;
}

sub domino_base64_encode
{
  my $v = shift;
  my $n = shift;

  my $itoa64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

  my $ret = "";

  while (($n - 1) >= 0)
  {
    $n = $n - 1;

    $ret = substr ($itoa64, $v & 0x3f, 1) . $ret;

    $v = $v >> 6;
  }

  return $ret
}

sub pseudo_base64
{
  my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $md5 = shift;
  my $s64 = "";
  for my $i (0..3) {
      my $v = unpack "V", substr ($md5, $i*4, 4);
      for (1..4) {
          $s64 .= substr ($itoa64, $v & 0x3f, 1);
          $v >>= 6;
      }
  }
  return $s64;
}

sub racf_hash
{
  my ($username, $password) = @_;

  $username = substr ($username . " " x 8, 0, 8);
  $password = substr ($password . " " x 8, 0, 8);

  my $username_ebc = ascii2ebcdic ($username);
  my $password_ebc = ascii2ebcdic ($password);

  my @pw = split ("", $password_ebc);

  for (my $i = 0; $i < 8; $i++)
  {
    $pw[$i] = unpack ("C", $pw[$i]);
    $pw[$i] ^= 0x55;
    $pw[$i] <<= 1;
    $pw[$i] = pack ("C", $pw[$i] & 0xff);
  }

  my $key = join ("", @pw);

  my $cipher = new Crypt::DES $key;

  my $ciphertext = $cipher->encrypt ($username_ebc);

  my $ct = unpack ("H16", $ciphertext);

  return $ct;
}

sub oracle_hash
{
  my ($username, $password) = @_;

  my $userpass = pack ('n*', unpack ('C*', uc ($username.$password)));
  $userpass .= pack ('C', 0) while (length ($userpass) % 8);

  my $key = pack ('H*', "0123456789ABCDEF");
  my $iv = pack ('H*', "0000000000000000");

  my $c = new Crypt::CBC (
    -literal_key => 1,
    -cipher => "DES",
    -key => $key,
    -iv => $iv,
    -header => "none"
  );
  my $key2 = substr ($c->encrypt ($userpass), length ($userpass)-8, 8);

  my $c2 = new Crypt::CBC (
    -literal_key => 1,
    -cipher => "DES",
    -key => $key2,
    -iv => $iv,
    -header => "none"
  );
  my $hash = substr ($c2->encrypt ($userpass), length ($userpass)-8, 8);

  return uc (unpack ('H*', $hash));
}

sub androidpin_hash
{
  my $word_buf = shift;

  my $salt_buf = shift;

  my $w = sprintf ("%d%s%s", 0, $word_buf, $salt_buf);

  my $digest = sha1 ($w);

  for (my $i = 1; $i < 1024; $i++)
  {
    $w = $digest . sprintf ("%d%s%s", $i, $word_buf, $salt_buf);

    $digest = sha1 ($w);
  }

  my ($A, $B, $C, $D, $E) = unpack ("N5", $digest);

  return sprintf ("%08x%08x%08x%08x%08x", $A, $B, $C, $D, $E);
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

  return $ret
}

sub md5_crypt
{
  my $magic = shift;

  my $iter = shift;
  my $pass = shift;
  my $salt = shift;

  my $hash = ""; # hash to be returned by this function

  my $final = md5 ($pass . $salt . $pass);

  $salt = substr ($salt, 0, 8);

  my $tmp = $pass . $magic . $salt;

  my $pass_len = length ($pass);

  my $i;

  for ($i = $pass_len; $i > 0; $i -= 16)
  {
    my $len = 16;

    if ($i < $len)
    {
      $len = $i;
    }

    $tmp .= substr ($final, 0, $len);
  }

  $i = $pass_len;

  while ($i > 0)
  {
    if ($i & 1)
    {
      $tmp .= chr (0);
    }
    else
    {
      $tmp .= substr ($pass, 0, 1);
    }

    $i >>= 1;
  }

  $final = md5 ($tmp);

  for ($i = 0; $i < $iter; $i++)
  {
    $tmp = "";

    if ($i & 1)
    {
      $tmp .= $pass;
    }
    else
    {
      $tmp .= $final;
    }

    if ($i % 3)
    {
      $tmp .= $salt;
    }

    if ($i % 7)
    {
      $tmp .= $pass;
    }

    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $pass;
    }

    $final = md5 ($tmp);
  }

  # done
  # now format the output sting ("hash")

  my $hash_buf;

  $hash  = to64 ((ord (substr ($final, 0, 1)) << 16) | (ord (substr ($final,  6, 1)) << 8) | (ord (substr ($final, 12, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 1, 1)) << 16) | (ord (substr ($final,  7, 1)) << 8) | (ord (substr ($final, 13, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 2, 1)) << 16) | (ord (substr ($final,  8, 1)) << 8) | (ord (substr ($final, 14, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 3, 1)) << 16) | (ord (substr ($final,  9, 1)) << 8) | (ord (substr ($final, 15, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 4, 1)) << 16) | (ord (substr ($final, 10, 1)) << 8) | (ord (substr ($final,  5, 1))), 4);
  $hash .= to64 (ord (substr ($final, 11, 1)), 2);

  if ($iter == 1000) # default
  {
    $hash_buf = sprintf ("%s%s\$%s", $magic , $salt , $hash);
  }
  else
  {
    $hash_buf = sprintf ("%srounds=%i\$%s\$%s", $magic, $iter, $salt , $hash);
  }

  return $hash_buf;
}

sub sha512_crypt
{
  my $iter = shift;
  my $pass = shift;
  my $salt = shift;

  my $hash = ""; # hash to be returned by this function

  my $final = sha512 ($pass . $salt . $pass);

  $salt = substr ($salt, 0, 16);

  my $tmp = $pass . $salt;

  my $pass_len = length ($pass);
  my $salt_len = length ($salt);

  my $i;

  for ($i = $pass_len; $i > 0; $i -= 16)
  {
    my $len = 16;

    if ($i < $len)
    {
      $len = $i;
    }

    $tmp .= substr ($final, 0, $len);
  }

  $i = $pass_len;

  while ($i > 0)
  {
    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $pass;
    }

    $i >>= 1;
  }

  $final = sha512 ($tmp);

  # p_bytes

  my $p_bytes = "";

  for ($i = 0; $i < $pass_len; $i++)
  {
    $p_bytes .= $pass;
  }

  $p_bytes = sha512 ($p_bytes);
  $p_bytes = substr ($p_bytes, 0, $pass_len);

  # s_bytes

  my $final_first_byte = ord (substr ($final, 0, 1));

  my $s_bytes = "";

  for ($i = 0; $i < (16 + $final_first_byte); $i++)
  {
    $s_bytes .= $salt;
  }

  $s_bytes = sha512 ($s_bytes);
  $s_bytes = substr ($s_bytes, 0, $salt_len);

  for ($i = 0; $i < $iter; $i++)
  {
    $tmp = "";

    if ($i & 1)
    {
      $tmp .= $p_bytes;
    }
    else
    {
      $tmp .= $final;
    }

    if ($i % 3)
    {
      $tmp .= $s_bytes;
    }

    if ($i % 7)
    {
      $tmp .= $p_bytes;
    }

    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $p_bytes;
    }

    $final = sha512 ($tmp);
  }

  # done
  # now format the output string ("hash")

  my $hash_buf;

  $hash .= to64 ((ord (substr ($final,  0, 1)) << 16) | (ord (substr ($final, 21, 1)) << 8) | (ord (substr ($final, 42, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 22, 1)) << 16) | (ord (substr ($final, 43, 1)) << 8) | (ord (substr ($final,  1, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 44, 1)) << 16) | (ord (substr ($final,  2, 1)) << 8) | (ord (substr ($final, 23, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  3, 1)) << 16) | (ord (substr ($final, 24, 1)) << 8) | (ord (substr ($final, 45, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 25, 1)) << 16) | (ord (substr ($final, 46, 1)) << 8) | (ord (substr ($final,  4, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 47, 1)) << 16) | (ord (substr ($final,  5, 1)) << 8) | (ord (substr ($final, 26, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  6, 1)) << 16) | (ord (substr ($final, 27, 1)) << 8) | (ord (substr ($final, 48, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 28, 1)) << 16) | (ord (substr ($final, 49, 1)) << 8) | (ord (substr ($final,  7, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 50, 1)) << 16) | (ord (substr ($final,  8, 1)) << 8) | (ord (substr ($final, 29, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  9, 1)) << 16) | (ord (substr ($final, 30, 1)) << 8) | (ord (substr ($final, 51, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 31, 1)) << 16) | (ord (substr ($final, 52, 1)) << 8) | (ord (substr ($final, 10, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 53, 1)) << 16) | (ord (substr ($final, 11, 1)) << 8) | (ord (substr ($final, 32, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 12, 1)) << 16) | (ord (substr ($final, 33, 1)) << 8) | (ord (substr ($final, 54, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 34, 1)) << 16) | (ord (substr ($final, 55, 1)) << 8) | (ord (substr ($final, 13, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 56, 1)) << 16) | (ord (substr ($final, 14, 1)) << 8) | (ord (substr ($final, 35, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 15, 1)) << 16) | (ord (substr ($final, 36, 1)) << 8) | (ord (substr ($final, 57, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 37, 1)) << 16) | (ord (substr ($final, 58, 1)) << 8) | (ord (substr ($final, 16, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 59, 1)) << 16) | (ord (substr ($final, 17, 1)) << 8) | (ord (substr ($final, 38, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 18, 1)) << 16) | (ord (substr ($final, 39, 1)) << 8) | (ord (substr ($final, 60, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 40, 1)) << 16) | (ord (substr ($final, 61, 1)) << 8) | (ord (substr ($final, 19, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 62, 1)) << 16) | (ord (substr ($final, 20, 1)) << 8) | (ord (substr ($final, 41, 1))), 4);
  $hash .= to64 (ord (substr ($final,  63, 1)), 2);

  my $magic = '$6$';

  if ($iter == 5000) # default
  {
    $hash_buf = sprintf ("%s%s\$%s", $magic, $salt , $hash);
  }
  else
  {
    $hash_buf = sprintf ("%srounds=%i\$%s\$%s", $magic, $iter, $salt , $hash);
  }

  return $hash_buf;
}

sub sha256_crypt
{
  my $iter = shift;
  my $pass = shift;
  my $salt = shift;

  my $hash = ""; # hash to be returned by this function

  my $final = sha256 ($pass . $salt . $pass);

  $salt = substr ($salt, 0, 16);

  my $tmp = $pass . $salt;

  my $pass_len = length ($pass);
  my $salt_len = length ($salt);

  my $i;

  for ($i = $pass_len; $i > 0; $i -= 16)
  {
    my $len = 16;

    if ($i < $len)
    {
      $len = $i;
    }

    $tmp .= substr ($final, 0, $len);
  }

  $i = $pass_len;

  while ($i > 0)
  {
    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $pass;
    }

    $i >>= 1;
  }

  $final = sha256 ($tmp);

  # p_bytes

  my $p_bytes = "";

  for ($i = 0; $i < $pass_len; $i++)
  {
    $p_bytes .= $pass;
  }

  $p_bytes = sha256 ($p_bytes);
  $p_bytes = substr ($p_bytes, 0, $pass_len);

  # s_bytes

  my $final_first_byte = ord (substr ($final, 0, 1));

  my $s_bytes = "";

  for ($i = 0; $i < (16 + $final_first_byte); $i++)
  {
    $s_bytes .= $salt;
  }

  $s_bytes = sha256 ($s_bytes);
  $s_bytes = substr ($s_bytes, 0, $salt_len);

  for ($i = 0; $i < $iter; $i++)
  {
    $tmp = "";

    if ($i & 1)
    {
      $tmp .= $p_bytes;
    }
    else
    {
      $tmp .= $final;
    }

    if ($i % 3)
    {
      $tmp .= $s_bytes;
    }

    if ($i % 7)
    {
      $tmp .= $p_bytes;
    }

    if ($i & 1)
    {
      $tmp .= $final;
    }
    else
    {
      $tmp .= $p_bytes;
    }

    $final = sha256 ($tmp);
  }

  # done
  # now format the output string ("hash")

  my $hash_buf;

  $hash .= to64 ((ord (substr ($final,  0, 1)) << 16) | (ord (substr ($final, 10, 1)) << 8) | (ord (substr ($final, 20, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 21, 1)) << 16) | (ord (substr ($final,  1, 1)) << 8) | (ord (substr ($final, 11, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 12, 1)) << 16) | (ord (substr ($final, 22, 1)) << 8) | (ord (substr ($final,  2, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  3, 1)) << 16) | (ord (substr ($final, 13, 1)) << 8) | (ord (substr ($final, 23, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 24, 1)) << 16) | (ord (substr ($final,  4, 1)) << 8) | (ord (substr ($final, 14, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 15, 1)) << 16) | (ord (substr ($final, 25, 1)) << 8) | (ord (substr ($final,  5, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  6, 1)) << 16) | (ord (substr ($final, 16, 1)) << 8) | (ord (substr ($final, 26, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 27, 1)) << 16) | (ord (substr ($final,  7, 1)) << 8) | (ord (substr ($final, 17, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 18, 1)) << 16) | (ord (substr ($final, 28, 1)) << 8) | (ord (substr ($final,  8, 1))), 4);
  $hash .= to64 ((ord (substr ($final,  9, 1)) << 16) | (ord (substr ($final, 19, 1)) << 8) | (ord (substr ($final, 29, 1))), 4);
  $hash .= to64 ((ord (substr ($final, 31, 1)) <<  8) | (ord (substr ($final, 30, 1))), 3);

  my $magic = '$5$';

  if ($iter == 5000) # default
  {
    $hash_buf = sprintf ("%s%s\$%s", $magic, $salt , $hash);
  }
  else
  {
    $hash_buf = sprintf ("%srounds=%i\$%s\$%s", $magic, $iter, $salt , $hash);
  }

  return $hash_buf;
}

sub aix_ssha256_pbkdf2
{
  my $word_buf   = shift;
  my $salt_buf   = shift;
  my $iterations = shift;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256);

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
    output_len   => 32
  );

  my $hash_buf = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

  my $tmp_hash = "";

  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  0, 1))) << 16) | (int (ord (substr ($hash_buf,  1, 1))) << 8) | (int (ord (substr ($hash_buf,  2, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  3, 1))) << 16) | (int (ord (substr ($hash_buf,  4, 1))) << 8) | (int (ord (substr ($hash_buf,  5, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  6, 1))) << 16) | (int (ord (substr ($hash_buf,  7, 1))) << 8) | (int (ord (substr ($hash_buf,  8, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  9, 1))) << 16) | (int (ord (substr ($hash_buf, 10, 1))) << 8) | (int (ord (substr ($hash_buf, 11, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 12, 1))) << 16) | (int (ord (substr ($hash_buf, 13, 1))) << 8) | (int (ord (substr ($hash_buf, 14, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 15, 1))) << 16) | (int (ord (substr ($hash_buf, 16, 1))) << 8) | (int (ord (substr ($hash_buf, 17, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 18, 1))) << 16) | (int (ord (substr ($hash_buf, 19, 1))) << 8) | (int (ord (substr ($hash_buf, 20, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 21, 1))) << 16) | (int (ord (substr ($hash_buf, 22, 1))) << 8) | (int (ord (substr ($hash_buf, 23, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 24, 1))) << 16) | (int (ord (substr ($hash_buf, 25, 1))) << 8) | (int (ord (substr ($hash_buf, 26, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 27, 1))) << 16) | (int (ord (substr ($hash_buf, 28, 1))) << 8) | (int (ord (substr ($hash_buf, 29, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 30, 1))) << 16) | (int (ord (substr ($hash_buf, 31, 1))) << 8)                                          , 3);

  return $tmp_hash;
}

sub aix_ssha512_pbkdf2
{
  my $word_buf   = shift;
  my $salt_buf   = shift;
  my $iterations = shift;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512);

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
  );

  my $hash_buf = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

  my $tmp_hash = "";

  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  0, 1))) << 16) | (int (ord (substr ($hash_buf,  1, 1))) << 8) | (int (ord (substr ($hash_buf,  2, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  3, 1))) << 16) | (int (ord (substr ($hash_buf,  4, 1))) << 8) | (int (ord (substr ($hash_buf,  5, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  6, 1))) << 16) | (int (ord (substr ($hash_buf,  7, 1))) << 8) | (int (ord (substr ($hash_buf,  8, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  9, 1))) << 16) | (int (ord (substr ($hash_buf, 10, 1))) << 8) | (int (ord (substr ($hash_buf, 11, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 12, 1))) << 16) | (int (ord (substr ($hash_buf, 13, 1))) << 8) | (int (ord (substr ($hash_buf, 14, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 15, 1))) << 16) | (int (ord (substr ($hash_buf, 16, 1))) << 8) | (int (ord (substr ($hash_buf, 17, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 18, 1))) << 16) | (int (ord (substr ($hash_buf, 19, 1))) << 8) | (int (ord (substr ($hash_buf, 20, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 21, 1))) << 16) | (int (ord (substr ($hash_buf, 22, 1))) << 8) | (int (ord (substr ($hash_buf, 23, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 24, 1))) << 16) | (int (ord (substr ($hash_buf, 25, 1))) << 8) | (int (ord (substr ($hash_buf, 26, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 27, 1))) << 16) | (int (ord (substr ($hash_buf, 28, 1))) << 8) | (int (ord (substr ($hash_buf, 29, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 30, 1))) << 16) | (int (ord (substr ($hash_buf, 31, 1))) << 8) | (int (ord (substr ($hash_buf, 32, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 33, 1))) << 16) | (int (ord (substr ($hash_buf, 34, 1))) << 8) | (int (ord (substr ($hash_buf, 35, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 36, 1))) << 16) | (int (ord (substr ($hash_buf, 37, 1))) << 8) | (int (ord (substr ($hash_buf, 38, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 39, 1))) << 16) | (int (ord (substr ($hash_buf, 40, 1))) << 8) | (int (ord (substr ($hash_buf, 41, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 42, 1))) << 16) | (int (ord (substr ($hash_buf, 43, 1))) << 8) | (int (ord (substr ($hash_buf, 44, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 45, 1))) << 16) | (int (ord (substr ($hash_buf, 46, 1))) << 8) | (int (ord (substr ($hash_buf, 47, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 48, 1))) << 16) | (int (ord (substr ($hash_buf, 49, 1))) << 8) | (int (ord (substr ($hash_buf, 50, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 51, 1))) << 16) | (int (ord (substr ($hash_buf, 52, 1))) << 8) | (int (ord (substr ($hash_buf, 53, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 54, 1))) << 16) | (int (ord (substr ($hash_buf, 55, 1))) << 8) | (int (ord (substr ($hash_buf, 56, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 57, 1))) << 16) | (int (ord (substr ($hash_buf, 58, 1))) << 8) | (int (ord (substr ($hash_buf, 59, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 60, 1))) << 16) | (int (ord (substr ($hash_buf, 61, 1))) << 8) | (int (ord (substr ($hash_buf, 62, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 63, 1))) << 16)                                                                                         , 2);

  return $tmp_hash;
}

sub aix_ssha1_pbkdf2
{
  my $word_buf   = shift;
  my $salt_buf   = shift;
  my $iterations = shift;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
  );

  my $hash_buf = $pbkdf2->PBKDF2 ($salt_buf, $word_buf);

  my $tmp_hash = "";

  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  0, 1))) << 16) | (int (ord (substr ($hash_buf,  1, 1))) << 8) | (int (ord (substr ($hash_buf,  2, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  3, 1))) << 16) | (int (ord (substr ($hash_buf,  4, 1))) << 8) | (int (ord (substr ($hash_buf,  5, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  6, 1))) << 16) | (int (ord (substr ($hash_buf,  7, 1))) << 8) | (int (ord (substr ($hash_buf,  8, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf,  9, 1))) << 16) | (int (ord (substr ($hash_buf, 10, 1))) << 8) | (int (ord (substr ($hash_buf, 11, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 12, 1))) << 16) | (int (ord (substr ($hash_buf, 13, 1))) << 8) | (int (ord (substr ($hash_buf, 14, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 15, 1))) << 16) | (int (ord (substr ($hash_buf, 16, 1))) << 8) | (int (ord (substr ($hash_buf, 17, 1)))), 4);
  $tmp_hash .= to64 ((int (ord (substr ($hash_buf, 18, 1))) << 16) | (int (ord (substr ($hash_buf, 19, 1))) << 8)                                          , 3);

  return $tmp_hash;
}

sub sapb_transcode
{
  my $data_s = shift;

  my @data = split "", $data_s;

  my $transTable_s =
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\x3f\x40\x41\x50\x43\x44\x45\x4b\x47\x48\x4d\x4e\x54\x51\x53\x46" .
    "\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x56\x55\x5c\x49\x5d\x4a" .
    "\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" .
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x58\x5b\x59\xff\x52" .
    "\x4c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" .
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x57\x5e\x5a\x4f\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

  my @transTable = unpack ("C256", $transTable_s);

  my @out;

  for (my $i = 0; $i < scalar @data; $i++)
  {
    $out[$i] = $transTable[int (ord ($data[$i]))];
  }

  return pack ("C*", @out);
}

sub sapb_waldorf
{
  my $digest_s = shift;

  my $w_s = shift;
  my $s_s = shift;

  my @w = unpack "C*", $w_s;
  my @s = unpack "C*", $s_s;

  my $bcodeTable_s =
    "\x14\x77\xf3\xd4\xbb\x71\x23\xd0\x03\xff\x47\x93\x55\xaa\x66\x91" .
    "\xf2\x88\x6b\x99\xbf\xcb\x32\x1a\x19\xd9\xa7\x82\x22\x49\xa2\x51" .
    "\xe2\xb7\x33\x71\x8b\x9f\x5d\x01\x44\x70\xae\x11\xef\x28\xf0\x0d";

  my @bcodeTable = unpack ("C48", $bcodeTable_s);

  my @abcd = unpack ("C16", $digest_s);

  my $sum20 = ($abcd[0] & 3)
            + ($abcd[1] & 3)
            + ($abcd[2] & 3)
            + ($abcd[3] & 3)
            + ($abcd[5] & 3);

  $sum20 |= 0x20;

  my @out;

  for (my $i2 = 0; $i2 < $sum20; $i2++)
  {
    $out[$i2] = 0;
  }

  for (my $i1 = 0, my $i2 = 0, my $i3 = 0; $i2 < $sum20; $i2++, $i2++)
  {
    if ($i1 < length $w_s)
    {
      if ($abcd[15 - $i1] & 1)
      {
        $out[$i2] = $bcodeTable[48 - 1 - $i1];

        $i2++;
      }

      $out[$i2] = $w[$i1];

      $i1++;
      $i2++;
    }

    if ($i3 < length $s_s)
    {
      $out[$i2] = $s[$i3];

      $i2++;
      $i3++;
    }

    $out[$i2] = $bcodeTable[$i2 - $i1 - $i3];
  }

  return substr (pack ("C*", @out), 0, $sum20);
}

sub setup_des_key
{
  my @key_56 = split (//, shift);

  my $key = "";

  $key = $key_56[0];

  $key .= chr (((ord ($key_56[0]) << 7) | (ord ($key_56[1]) >> 1)) & 255);
  $key .= chr (((ord ($key_56[1]) << 6) | (ord ($key_56[2]) >> 2)) & 255);
  $key .= chr (((ord ($key_56[2]) << 5) | (ord ($key_56[3]) >> 3)) & 255);
  $key .= chr (((ord ($key_56[3]) << 4) | (ord ($key_56[4]) >> 4)) & 255);
  $key .= chr (((ord ($key_56[4]) << 3) | (ord ($key_56[5]) >> 5)) & 255);
  $key .= chr (((ord ($key_56[5]) << 2) | (ord ($key_56[6]) >> 6)) & 255);
  $key .= chr (( ord ($key_56[6]) << 1) & 255);

  return $key;
}

sub randbytes
{
  my $len = shift;

  my @arr;

  for (my $i = 0; $i < $len; $i++)
  {
    my $c = get_random_chr (0, 255);

    push (@arr, $c);
  }

  return join ("", @arr);
}

sub get_random_netntlmv1_salt
{
  my $len_user   = shift;
  my $len_domain = shift;

  my $char;
  my $type;
  my $user = "";

  for (my $i = 0; $i < $len_user; $i++)
  {
    $type = get_random_num (1, 3);

    if ($type == 1)
    {
      $char = get_random_chr (0x30, 0x39);
    }
    elsif ($type == 2)
    {
      $char = get_random_chr (0x41, 0x5A);
    }
    else
    {
      $char = get_random_chr (0x61, 0x7A);
    }

    $user .= $char;
  }

  my $domain = "";

  for (my $i = 0; $i < $len_domain; $i++)
  {
    $type = get_random_num (1, 3);

    if ($type == 1)
    {
      $char = get_random_chr (0x30, 0x39);
    }
    elsif ($type == 2)
    {
      $char = get_random_chr (0x41, 0x5A);
    }
    else
    {
      $char = get_random_chr (0x61, 0x7A);
    }

    $domain .= $char;
  }

  my $c_challenge = randbytes (8);
  my $s_challenge = randbytes (8);

  my $salt_buf = $user . "::" . $domain . ":" . unpack ("H*", $c_challenge) . unpack ("H*", $s_challenge);

  return $salt_buf;
}

sub get_random_netntlmv2_salt
{
  my $len_user   = shift;
  my $len_domain = shift;

  my $char;
  my $type;
  my $user = "";

  if ($len_user + $len_domain > 27)
  {
    if ($len_user > $len_domain)
    {
      $len_user = 27 - $len_domain;
    }
    else
    {
      $len_domain = 27 - $len_user;
    }
  }

  for (my $i = 0; $i < $len_user; $i++)
  {
    $type = get_random_num (1, 3);

    if ($type == 1)
    {
      $char = get_random_chr (0x30, 0x39);
    }
    elsif ($type == 2)
    {
      $char = get_random_chr (0x41, 0x5A);
    }
    else
    {
      $char = get_random_chr (0x61, 0x7A);
    }

    $user .= $char;
  }

  my $domain = "";

  for (my $i = 0; $i < $len_domain; $i++)
  {
    $type = get_random_num (1, 3);

    if ($type == 1)
    {
      $char = get_random_chr (0x30, 0x39);
    }
    elsif ($type == 2)
    {
      $char = get_random_chr (0x41, 0x5A);
    }
    else
    {
      $char = get_random_chr (0x61, 0x7A);
    }

    $domain .= $char;
  }

  my $c_challenge = randbytes (8);
  my $s_challenge = randbytes (8);

  my $temp = "\x01\x01" .
             "\x00" x 6 .
             randbytes (8) .
             $c_challenge .
             "\x00" x 4 .
             randbytes (20 * rand () + 1) .
             "\x00";

  my $salt_buf = $user . "::" . $domain . ":" . unpack ("H*", $s_challenge) . unpack ("H*", $temp);

  return $salt_buf;
}

sub get_random_ike_salt
{
  my $nr_buf = "";

  for (my $i = 0; $i < 40; $i++)
  {
    $nr_buf .= get_random_chr (0, 0xff);
  }

  my $msg_buf = "";

  for (my $i = 0; $i < 440; $i++)
  {
    $msg_buf .= get_random_chr (0, 0xff);
  }

  my $nr_buf_hex  = unpack ("H*", $nr_buf);
  my $msg_buf_hex = unpack ("H*", $msg_buf);

  my $salt_buf = sprintf ("%s:%s:%s:%s:%s:%s:%s:%s", substr ($msg_buf_hex, 0, 256), substr ($msg_buf_hex, 256, 256), substr ($msg_buf_hex, 512, 16), substr ($msg_buf_hex, 528, 16), substr ($msg_buf_hex, 544, 320), substr ($msg_buf_hex, 864, 16), substr ($nr_buf_hex, 0, 40), substr ($nr_buf_hex, 40, 40));

  return $salt_buf;
}

sub get_random_agilekeychain_salt
{
  my $salt_buf = "";

  for (my $i = 0; $i < 8; $i++)
  {
    $salt_buf .= get_random_chr (0x0, 0xff);
  }

  my $iv = "";

  for (my $i = 0; $i < 16; $i++)
  {
    $iv .= get_random_chr (0x0, 0xff);
  }

  my $prefix = "\x00" x 1008;

  my $ret = unpack ("H*", $salt_buf . $prefix . $iv);

  return $ret;
}

sub get_random_cloudkeychain_salt
{
  my $salt_buf = "";

  for (my $i = 0; $i < 16; $i++)
  {
    $salt_buf .= get_random_chr (0x0, 0xff);
  }

  for (my $i = 0; $i < 304; $i++)
  {
    $salt_buf .= get_random_chr (0x0, 0xff);
  }

  my $ret = unpack ("H*", $salt_buf);

  return $ret;
}

sub get_random_kerberos5_salt
{
  my $custom_salt = shift;

  my $clear_data = randbytes (14) .
                   strftime ("%Y%m%d%H%M%S", localtime) .
                   randbytes (8);

  my $user  = "user";
  my $realm = "realm";
  my $salt  = "salt";

  my $salt_buf = $user . "\$" . $realm . "\$" . $salt . "\$" . unpack ("H*", $custom_salt) . "\$" . unpack ("H*", $clear_data) . "\$";

  return $salt_buf;
}

sub get_random_kerberos5_tgs_salt
{
  my $nonce = randbytes (8);

  my $user  = "user";
  my $realm = "realm";
  my $spn   = "test/spn";

  my $salt_buf = $user . "\$" . $realm . "\$" . $spn . "\$" . unpack ("H*", $nonce);

  return $salt_buf;
}

sub get_random_kerberos5_as_rep_salt
{
  my $nonce = randbytes (8);

  my $user_principal_name  = "user\@domain.com";
  my $salt_buf = $user_principal_name . ":" . unpack ("H*", $nonce);

  return $salt_buf;
}

sub get_random_axcrypt_salt
{
  my $mysalt = randbytes (16);

  $mysalt = unpack ("H*", $mysalt);

  my $iteration = get_random_num (6, 100000);

  my $salt_buf = $iteration . '*' . $mysalt;

  return $salt_buf;
}

sub get_random_keepass_salt
{
  my $version = get_random_num (1, 3);

  my $algorithm;

  my $iteration;

  my $final_random_seed;

  if ($version == 1)
  {
    $algorithm = get_random_num (0, 2);

    $iteration = get_random_num (50000, 100000);

    $final_random_seed = randbytes (16);
    $final_random_seed  = unpack ("H*", $final_random_seed);
  }
  elsif ($version == 2)
  {
    $algorithm = 0;

    $iteration = get_random_num (6000, 100000);

    $final_random_seed = randbytes (32);
    $final_random_seed  = unpack ("H*", $final_random_seed);
  }

  my $transf_random_seed = randbytes (32);
  $transf_random_seed = unpack ("H*", $transf_random_seed);

  my $enc_iv = randbytes (16);
  $enc_iv = unpack ("H*", $enc_iv);

  my $contents_hash = randbytes (32);
  $contents_hash = unpack ("H*", $contents_hash);

  my $inline_flag = 1;

  my $contents_len = get_random_num (128, 500);

  my $contents = randbytes ($contents_len);

  $contents_len += 16 - $contents_len % 16;

  $contents = unpack ("H*", $contents);

  my $salt_buf;

  my $is_keyfile = get_random_num (0, 2);

  my $keyfile_attributes = "";

  if ($is_keyfile == 1)
  {
    $keyfile_attributes = $keyfile_attributes
                          . "1*64*"
                          . unpack ("H*", randbytes (32));
  }

  if ($version == 1)
  {
    $salt_buf = $version   . '*' .
                $iteration . '*' .
                $algorithm . '*' .
                $final_random_seed  . '*' .
                $transf_random_seed . '*' .
                $enc_iv        . '*' .
                $contents_hash . '*' .
                $inline_flag   . '*' .
                $contents_len  . '*' .
                $contents      . '*' .
                $keyfile_attributes;
  }
  elsif ($version == 2)
  {
    $contents = randbytes (32);
    $contents = unpack ("H*", $contents);

    $salt_buf = $version   . '*' .
                $iteration . '*' .
                $algorithm . '*' .
                $final_random_seed  . '*' .
                $transf_random_seed . '*' .
                $enc_iv        . '*' .
                $contents_hash . '*' .
                $contents      . '*' .
                $keyfile_attributes;
  }

  return $salt_buf;
}

sub get_pstoken_salt
{
  my $pstoken_length = get_random_num (16, 256);

  ## not a valid pstoken but a better test
  ## because of random length

  my $pstoken_const = randbytes ($pstoken_length);

  return unpack ("H*", $pstoken_const);
}

sub get_random_md5chap_salt
{
  my $salt_buf = shift;

  my $salt = unpack ("H*", $salt_buf);

  $salt .= ":";

  $salt .= unpack ("H*", randbytes (1));

  return $salt;
}

sub get_random_dnssec_salt
{
  my $salt_buf = "";

  $salt_buf .= ".";

  for (my $i = 0; $i < 8; $i++)
  {
    $salt_buf .= get_random_chr (0x61, 0x7a);
  }

  $salt_buf .= ".net";

  $salt_buf .= ":";

  for (my $i = 0; $i < 8; $i++)
  {
    $salt_buf .= get_random_chr (0x30, 0x39);
  }

  return $salt_buf;
}

sub get_random_dpapimk_salt
{
  my $salt_buf = "";

  my $version = shift;

  my $context = get_random_num (1, 3);

  my $cipher_algo = "";

  my $hash_algo = "";

  my $iterations;

  my $SID = sprintf ('S-15-21-%d-%d-%d-%d',
             get_random_num (400000000,490000000),
             get_random_num (400000000,490000000),
             get_random_num (400000000,490000000),
             get_random_num (1000,1999));

  my $cipher_len = 0;

  if ($version == 1)
  {
    $iterations = get_random_num (4000, 24000);

    $cipher_algo = "des3";

    $hash_algo = "sha1";

    $cipher_len = 208;
  }
  elsif ($version == 2)
  {
    $iterations = get_random_num (8000, 17000);

    $cipher_algo = "aes256";

    $hash_algo = "sha512";

    $cipher_len = 288;
  }

  my $iv = randbytes (16);
  $iv    = unpack ("H*", $iv);

  $salt_buf = $version . '*' .
              $context . '*' .
              $SID     . '*' .
              $cipher_algo   . '*' .
              $hash_algo     . '*' .
              $iterations    . '*' .
              $iv         . '*' .
              $cipher_len . '*';

  return $salt_buf;
}

sub get_random_jwt_salt
{
  my @hashes =
  (
    "HS256",
    #"HS384", #this is support in hashcat, but commented out here to prevent mixed hash output files in single mode
    #"HS512", #this is support in hashcat, but commented out here to prevent mixed hash output files in single mode
    #"RS256", #not supported by hashcat
    #"RS384",
    #"RS512",
    #"PS256",
    #"PS384",
    #"PS512",
    #"ES256",
    #"ES384",
    #"ES512",
  );

  my $rnd = get_random_num (0, scalar @hashes);

  my $hash = $hashes[$rnd];

  my $header =
  {
    "alg" => $hash
  };

  my $random_key = get_random_num (1, 100000000);
  my $random_val = get_random_num (1, 100000000);

  my $payload =
  {
    $random_key => $random_val
  };

  my $header_json    = encode_json ($header);
  my $payload_json   = encode_json ($payload);

  my $header_base64  = encode_base64url ($header_json, "");
  my $payload_base64 = encode_base64url ($payload_json, "");

  return $header_base64 . "." . $payload_base64;
}

sub md5bit
{
  my $digest = shift;
  my $bit = shift;

  $bit %= 128;

  my $byte_off = int ($bit / 8);
  my $bit_off  = int ($bit % 8);

  my $char = substr ($digest, $byte_off, 1);
  my $num  = ord ($char);

  return (($num & (1 << $bit_off)) ? 1 : 0);
}

sub sun_md5
{
  my $pw   = shift;
  my $salt = shift;
  my $iter = shift;

  my $constant_phrase =
  "To be, or not to be,--that is the question:--\n"        .
  "Whether 'tis nobler in the mind to suffer\n"            .
  "The slings and arrows of outrageous fortune\n"          .
  "Or to take arms against a sea of troubles,\n"           .
  "And by opposing end them?--To die,--to sleep,--\n"      .
  "No more; and by a sleep to say we end\n"                .
  "The heartache, and the thousand natural shocks\n"       .
  "That flesh is heir to,--'tis a consummation\n"          .
  "Devoutly to be wish'd. To die,--to sleep;--\n"          .
  "To sleep! perchance to dream:--ay, there's the rub;\n"  .
  "For in that sleep of death what dreams may come,\n"     .
  "When we have shuffled off this mortal coil,\n"          .
  "Must give us pause: there's the respect\n"              .
  "That makes calamity of so long life;\n"                 .
  "For who would bear the whips and scorns of time,\n"     .
  "The oppressor's wrong, the proud man's contumely,\n"    .
  "The pangs of despis'd love, the law's delay,\n"         .
  "The insolence of office, and the spurns\n"              .
  "That patient merit of the unworthy takes,\n"            .
  "When he himself might his quietus make\n"               .
  "With a bare bodkin? who would these fardels bear,\n"    .
  "To grunt and sweat under a weary life,\n"               .
  "But that the dread of something after death,--\n"       .
  "The undiscover'd country, from whose bourn\n"           .
  "No traveller returns,--puzzles the will,\n"             .
  "And makes us rather bear those ills we have\n"          .
  "Than fly to others that we know not of?\n"              .
  "Thus conscience does make cowards of us all;\n"         .
  "And thus the native hue of resolution\n"                .
  "Is sicklied o'er with the pale cast of thought;\n"      .
  "And enterprises of great pith and moment,\n"            .
  "With this regard, their currents turn awry,\n"          .
  "And lose the name of action.--Soft you now!\n"          .
  "The fair Ophelia!--Nymph, in thy orisons\n"             .
  "Be all my sins remember'd.\n\x00";

  my $constant_len = length ($constant_phrase);

  my $hash_buf = md5 ($pw . $salt);

  my $W;

  my $to_hash;

  for (my $round = 0; $round < $iter; $round++)
  {
    my $shift_a = md5bit ($hash_buf, $round +  0);
    my $shift_b = md5bit ($hash_buf, $round + 64);

    my @shift_4;
    my @shift_7;

    for (my $k = 0; $k < 16; $k++)
    {
       my $s7shift = ord (substr ($hash_buf, $k, 1)) % 8;

       my $l = ($k + 3) % 16;

       my $num = ord (substr ($hash_buf, $l, 1));

       $shift_4[$k] = $num % 5;

       $shift_7[$k] = ($num >> $s7shift) & 1;
    }

    my @indirect_4;

    for (my $k = 0; $k < 16; $k++)
    {
      $indirect_4[$k] = (ord (substr ($hash_buf, $k, 1)) >> $shift_4[$k]) & 0xf;
    }

    my @indirect_7;

    for (my $k = 0; $k < 16; $k++)
    {
      $indirect_7[$k] = (ord (substr ($hash_buf, $indirect_4[$k], 1)) >> $shift_7[$k]) & 0x7f;
    }

    my $indirect_a = 0;
    my $indirect_b = 0;

    for (my $k = 0; $k < 8; $k++)
    {
      $indirect_a |= md5bit ($hash_buf, $indirect_7[$k + 0]) << $k;

      $indirect_b |= md5bit ($hash_buf, $indirect_7[$k + 8]) << $k;
    }

    $indirect_a = ($indirect_a >> $shift_a) & 0x7f;
    $indirect_b = ($indirect_b >> $shift_b) & 0x7f;

    my $bit_a = md5bit ($hash_buf, $indirect_a);
    my $bit_b = md5bit ($hash_buf, $indirect_b);

    $W = $hash_buf;

    my $pos = 16;

    my $total = $pos;

    $to_hash = "";

    if ($bit_a ^ $bit_b)
    {
      substr ($W, 16, 48) = substr ($constant_phrase, 0, 48);

      $total += 48;

      $to_hash .= substr ($W, 0, 64);

      my $constant_off;

      for ($constant_off = 48; $constant_off < $constant_len - 64; $constant_off += 64)
      {
        substr ($W, 0, 64) = substr ($constant_phrase, $constant_off, 64);

        $total += 64;

        $to_hash .= substr ($W, 0, 64);
      }

      $pos = $constant_len - $constant_off;

      $total += $pos;

      substr ($W, 0, $pos) = substr ($constant_phrase, $constant_off, $pos);
    }

    my $a_len = 0;

    my @a_buf;
    $a_buf[0] = 0;
    $a_buf[1] = 0;
    $a_buf[2] = 0;
    $a_buf[3] = 0;

    my $tmp = $round;

    do
    {
      my $round_div = int ($tmp / 10);
      my $round_mod = int ($tmp % 10);

      $tmp = $round_div;

      $a_buf[int ($a_len / 4)] = (($round_mod + 0x30) | ($a_buf[int ($a_len / 4)] << 8));

      $a_len++;

    } while ($tmp);

    my $tmp_str = "";

    my $g;

    for ($g = 0; $g < $a_len; $g++)
    {
      my $remainder = $a_buf[$g];
      my $factor = 7;
      my $started = 1;

      my $sub;

      while ($remainder > 0)
      {
        $sub = $remainder >> (8 * $factor);

        if ($started != 1 || $sub > 0)
        {
          $started = 0;

          $tmp_str = chr ($sub) . $tmp_str;

          $remainder -= ($sub << (8 * $factor));
        }

        $factor--;
      }

    }

    substr ($W, $pos, $a_len) = $tmp_str;

    $pos += $a_len;

    $total += $a_len;

    $to_hash .= substr ($W, 0, $pos);

    $to_hash = substr ($to_hash, 0, $total);

    $hash_buf = md5 ($to_hash);
  }

  my $passwd = "";

  $passwd .= to64 ((int (ord (substr ($hash_buf,  0, 1))) << 16) | (int (ord (substr ($hash_buf,  6, 1))) << 8) | (int (ord (substr ($hash_buf, 12, 1)))), 4);
  $passwd .= to64 ((int (ord (substr ($hash_buf,  1, 1))) << 16) | (int (ord (substr ($hash_buf,  7, 1))) << 8) | (int (ord (substr ($hash_buf, 13, 1)))), 4);
  $passwd .= to64 ((int (ord (substr ($hash_buf,  2, 1))) << 16) | (int (ord (substr ($hash_buf,  8, 1))) << 8) | (int (ord (substr ($hash_buf, 14, 1)))), 4);
  $passwd .= to64 ((int (ord (substr ($hash_buf,  3, 1))) << 16) | (int (ord (substr ($hash_buf,  9, 1))) << 8) | (int (ord (substr ($hash_buf, 15, 1)))), 4);
  $passwd .= to64 ((int (ord (substr ($hash_buf,  4, 1))) << 16) | (int (ord (substr ($hash_buf, 10, 1))) << 8) | (int (ord (substr ($hash_buf,  5, 1)))), 4);
  $passwd .= to64 ((int (ord (substr ($hash_buf, 11, 1)))), 2);

  return $passwd;
}

sub usage_die
{
  die ("usage: $0 single|passthrough| [mode] [len]\n" .
       "       or\n" .
       "       $0 verify              [mode] [hashfile] [cracks] [outfile]\n");
}

sub pad16
{
  my $block_ref = shift;

  my $offset = shift;

  my $value = 16 - $offset;

  for (my $i = $offset; $i < 16; $i++)
  {
    push @{$block_ref}, $value;
  }
}

sub lotus_mix
{
  my $in_ref = shift;

  my $p = 0;

  for (my $i = 0; $i < 18; $i++)
  {
    for (my $j = 0; $j < 48; $j++)
    {
      $p = ($p + 48 - $j) & 0xff;

      my $c = $LOTUS_MAGIC_TABLE->[$p];

      $p = $in_ref->[$j] ^ $c;

      $in_ref->[$j] = $p;
    }
  }
}

sub lotus_transform_password
{
  my $in_ref  = shift;
  my $out_ref = shift;

  my $t = $out_ref->[15];

  for (my $i = 0; $i < 16; $i++)
  {
    $t ^= $in_ref->[$i];

    my $c = $LOTUS_MAGIC_TABLE->[$t];

    $out_ref->[$i] ^= $c;

    $t = $out_ref->[$i];
  }
}

sub mdtransform_norecalc
{
  my $state_ref = shift;
  my $block_ref = shift;

  my @x;

  push (@x, @{$state_ref});
  push (@x, @{$block_ref});

  for (my $i = 0; $i < 16; $i++)
  {
    push (@x, $x[0 + $i] ^ $x[16 + $i]);
  }

  lotus_mix (\@x);

  for (my $i = 0; $i < 16; $i++)
  {
    $state_ref->[$i] = $x[$i];
  }
}

sub mdtransform
{
  my $state_ref    = shift;
  my $checksum_ref = shift;
  my $block_ref    = shift;

  mdtransform_norecalc ($state_ref, $block_ref);

  lotus_transform_password ($block_ref, $checksum_ref);
}

sub domino_big_md
{
  my $saved_key_ref = shift;

  my $size = shift;

  @{$saved_key_ref} = splice (@{$saved_key_ref}, 0, $size);

  my @state = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  my @checksum;

  my $curpos;

  for ($curpos = 0; $curpos + 16 < $size; $curpos += 16)
  {
    my @block = splice (@{$saved_key_ref}, 0, 16);

    mdtransform (\@state, \@checksum, \@block);
  }

  my $left = $size - $curpos;

  my @block = splice (@{$saved_key_ref}, 0, 16);

  pad16 (\@block, $left);

  mdtransform (\@state, \@checksum, \@block);

  mdtransform_norecalc (\@state, \@checksum);

  return @state;
}

sub pdf_compute_encryption_key
{
  my $word_buf  = shift;
  my $padding   = shift;
  my $id        = shift;
  my $u         = shift;
  my $o         = shift;
  my $P         = shift;
  my $V         = shift;
  my $R         = shift;
  my $enc       = shift;

  ## start

  my $data;

  $data .= $word_buf;

  $data .= substr ($padding, 0, 32 - length $word_buf);

  $data .= pack ("H*", $o);

  $data .= pack ("I", $P);

  $data .= pack ("H*", $id);

  if ($R >= 4)
  {
    if (!$enc)
    {
      $data .= pack ("I", -1);
    }
  }

  my $res = md5 ($data);

  if ($R >= 3)
  {
    for (my $i = 0; $i < 50; $i++)
    {
      $res = md5 ($res);
    }
  }

  return $res;
}

sub gen_random_wpa_eapol
{
  my $keyver = shift;
  my $snonce = shift;

  my $ret = "";

  # version

  my $version = 1; # 802.1X-2001

  $ret .= pack ("C*", $version);

  my $type = 3;    # means that this EAPOL frame is used to transfer key information

  $ret .= pack ("C*", $type);

  my $length; # length of remaining data

  if ($keyver == 1)
  {
    $length = 119;
  }
  else
  {
    $length = 117;
  }

  $ret .= pack ("n*", $length);

  my $descriptor_type;

  if ($keyver == 1)
  {
    $descriptor_type = 254; # EAPOL WPA key
  }
  else
  {
    $descriptor_type = 1; # EAPOL RSN key
  }

  $ret .= pack ("C*", $descriptor_type);

  # key_info is a bit vector:
  # generated from these 13 bits: encrypted key data, request, error, secure, key mic, key ack, install, key index (2), key type, key descriptor (3)

  my $key_info = 0;

  $key_info |= 1 << 8; # set key MIC
  $key_info |= 1 << 3; # set if it is a pairwise key

  if ($keyver == 1)
  {
    $key_info |= 1 << 0; # RC4 Cipher, HMAC-MD5 MIC
  }
  else
  {
    $key_info |= 1 << 1; # AES Cipher, HMAC-SHA1 MIC
  }

  $ret .= pack ("n*", $key_info);

  my $key_length;

  if ($keyver == 1)
  {
    $key_length = 32;
  }
  else
  {
    $key_length = 0;
  }

  $ret .= pack ("n*", $key_length);

  my $replay_counter = 1;

  $ret .= pack ("Q>*", $replay_counter);

  $ret .= $snonce;

  my $key_iv = "\x00" x 16;

  $ret .= $key_iv;

  my $key_rsc = "\x00" x 8;

  $ret .= $key_rsc;

  my $key_id = "\x00" x 8;

  $ret .= $key_id;

  my $key_mic = "\x00" x 16;

  $ret .= $key_mic;

  my $key_data_len;

  if ($keyver == 1)
  {
    $key_data_len = 24; # length of the key_data (== WPA info)
  }
  else
  {
    $key_data_len = 22; # length of the key_data (== RSN info)
  }

  $ret .= pack ("n*", $key_data_len);

  my $key_data = "";

  if ($keyver == 1)
  {
    # wpa info

    my $wpa_info = "";

    my $vendor_specific_data = "";

    my $tag_number = 221; # means it is a vendor specific tag

    $vendor_specific_data .= pack ("C*", $tag_number);

    my $tag_len = 22;     # length of the remaining "tag data"

    $vendor_specific_data .= pack ("C*", $tag_len);

    my $vendor_specific_oui = pack ("H*", "0050f2"); # microsoft

    $vendor_specific_data .= $vendor_specific_oui;

    my $vendor_specific_oui_type = 1; # WPA Information Element

    $vendor_specific_data .= pack ("C*", $vendor_specific_oui_type);

    my $vendor_specific_wpa_version = 1;

    $vendor_specific_data .= pack ("v*", $vendor_specific_wpa_version);

    # multicast

    my $vendor_specific_multicast_oui = pack ("H*", "0050f2");

    $vendor_specific_data .= $vendor_specific_multicast_oui;

    my $vendor_specific_multicast_type = 2; # TKIP

    $vendor_specific_data .= pack ("C*", $vendor_specific_multicast_type);

    # unicast

    my $vendor_specific_unicast_count = 1;

    $vendor_specific_data .= pack ("v*", $vendor_specific_unicast_count);

    my $vendor_specific_unicast_oui = pack ("H*", "0050f2");

    $vendor_specific_data .= $vendor_specific_unicast_oui;

    my $vendor_specific_unicast_type = 2; # TKIP

    $vendor_specific_data .= pack ("C*", $vendor_specific_unicast_type);

    # Auth Key Management (AKM)

    my $auth_key_management_count = 1;

    $vendor_specific_data .= pack ("v*", $auth_key_management_count);

    my $auth_key_management_oui = pack ("H*", "0050f2");

    $vendor_specific_data .= $auth_key_management_oui;

    my $auth_key_management_type = 2; # Pre-Shared Key (PSK)

    $vendor_specific_data .= pack ("C*", $auth_key_management_type);

    $wpa_info = $vendor_specific_data;

    $key_data = $wpa_info;
  }
  else
  {
    # rsn info

    my $rsn_info = "";

    my $tag_number = 48; # RSN info

    $rsn_info .= pack ("C*", $tag_number);

    my $tag_len = 20;    # length of the remaining "tag_data"

    $rsn_info .= pack ("C*", $tag_len);

    my $rsn_version = 1;

    $rsn_info .= pack ("v*", $rsn_version);

    # group cipher suite

    my $group_cipher_suite_oui = pack ("H*", "000fac"); # Ieee8021

    $rsn_info .= $group_cipher_suite_oui;

    my $group_cipher_suite_type = 4; # AES (CCM)

    $rsn_info .= pack ("C*", $group_cipher_suite_type);

    # pairwise cipher suite

    my $pairwise_cipher_suite_count = 1;

    $rsn_info .= pack ("v*", $pairwise_cipher_suite_count);

    my $pairwise_cipher_suite_oui = pack ("H*", "000fac"); # Ieee8021

    $rsn_info .= $pairwise_cipher_suite_oui;

    my $pairwise_cipher_suite_type = 4; # AES (CCM)

    $rsn_info .= pack ("C*", $pairwise_cipher_suite_type);

    # Auth Key Management (AKM)

    my $auth_key_management_count = 1;

    $rsn_info .= pack ("v*", $auth_key_management_count);

    my $auth_key_management_oui = pack ("H*", "000fac"); # Ieee8021

    $rsn_info .= $auth_key_management_oui;

    my $auth_key_management_type = 2; # Pre-Shared Key (PSK)

    $rsn_info .= pack ("C*", $auth_key_management_type);

    # RSN Capabilities

    # bit vector of these 9 bits: peerkey enabled, management frame protection (MFP) capable, MFP required,
    # RSN GTKSA Capabilities (2), RSN PTKSA Capabilities (2), no pairwise Capabilities, Pre-Auth Capabilities

    my $rsn_capabilities = pack ("H*", "0000");

    $rsn_info .= $rsn_capabilities;

    $key_data = $rsn_info;
  }

  $ret .= $key_data;

  return $ret;
}

sub wpa_prf_512
{
  my $keyver = shift;
  my $pmk    = shift;
  my $stmac  = shift;
  my $bssid  = shift;
  my $snonce = shift;
  my $anonce = shift;

  my $data = "Pairwise key expansion";

  if (($keyver == 1) || ($keyver == 2))
  {
    $data .= "\x00";
  }

  #
  # Min(AA, SPA) || Max(AA, SPA)
  #

  # compare if greater: Min()/Max() on the MACs (6 bytes)

  if (memcmp ($stmac, $bssid, 6) < 0)
  {
    $data .= $stmac;
    $data .= $bssid;
  }
  else
  {
    $data .= $bssid;
    $data .= $stmac;
  }

  #
  # Min(ANonce,SNonce) || Max(ANonce,SNonce)
  #

  # compare if greater: Min()/Max() on the nonces (32 bytes)

  if (memcmp ($snonce, $anonce, 32) < 0)
  {
    $data .= $snonce;
    $data .= $anonce;
  }
  else
  {
    $data .= $anonce;
    $data .= $snonce;
  }

  my $prf_buf;

  if (($keyver == 1) || ($keyver == 2))
  {
    $data .= "\x00";

    $prf_buf = hmac ($data, $pmk, \&sha1);
  }
  else
  {
    my $data3 = "\x01\x00" . $data . "\x80\x01";

    $prf_buf = hmac ($data3, $pmk, \&sha256);
  }

  $prf_buf = substr ($prf_buf, 0, 16);

  return $prf_buf;
}

sub itunes_aes_wrap
{
  my $key = shift;
  my $A   = shift;
  my $R_l = shift;

  my $k = scalar (@$R_l);
  my $n = $k + 1;

  my @R;

  for (my $i = 0; $i < $n; $i++)
  {
    $R[$i] = @$R_l[$i];
  }

  # AES mode ECB

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  # main wrap loop

  my ($i, $j, $a);

  for ($j = 0; $j <= 5; $j++)
  {
    for ($i = 1, $a = 0; $i <= $k; $i++, $a++)
    {
      my $input;

      $input  = pack ("Q>", $A);
      $input .= pack ("Q>", $R[$a]);

      my $t = $m->encrypt ($input, $key);

      $A     = unpack ("Q>", substr ($t, 0, 8));
      $A    ^= $k * $j + $i;

      $R[$a] = unpack ("Q>", substr ($t, 8, 8));
    }
  }

  my $WPKY = pack ("Q>", $A);

  for (my $i = 0; $i < $k; $i++)
  {
    $WPKY .= pack ("Q>", $R[$i]);
  }

  return $WPKY;
}

sub itunes_aes_unwrap
{
  my $key  = shift;
  my $WPKY = shift;

  my @B;

  for (my $i = 0; $i < length ($WPKY) / 8; $i++)
  {
    $B[$i] = unpack ("Q>", substr ($WPKY, $i * 8, 8));
  }

  my $n = scalar (@B);
  my $k = $n - 1;

  my @R;

  for (my $i = 0; $i < $k; $i++)
  {
    $R[$i] = $B[$i + 1];
  }

  # AES mode ECB

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  # main unwrap loop

  my $A = $B[0];

  my ($i, $j, $a);

  for ($j = 5; $j >= 0; $j--)
  {
    for ($i = $k, $a = $k - 1; $i > 0; $i--, $a--)
    {
      my $input;

      $input  = pack ("Q>", $A ^ ($k * $j + $i));
      $input .= pack ("Q>", $R[$a]);

      my $t = $m->decrypt ($input, $key);

      $A     = unpack ("Q>", substr ($t, 0, 8));
      $R[$a] = unpack ("Q>", substr ($t, 8, 8));
    }
  }

  return ($A, \@R);
}

sub memcmp
{
  my $str1 = shift;
  my $str2 = shift;
  my $len  = shift;

  my $len_str1 = length ($str1);
  my $len_str2 = length ($str2);

  if (($len > $len_str1) || ($len > $len_str2))
  {
    print "ERROR: memcmp () lengths wrong";

    exit (1);
  }

  for (my $i = 0; $i < $len; $i++)
  {
    my $c_1 = ord (substr ($str1, $i, 1));
    my $c_2 = ord (substr ($str2, $i, 1));

    return -1 if ($c_1 < $c_2);
    return  1 if ($c_1 > $c_2);
  }

  return 0;
}

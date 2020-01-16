#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

#
# Helper functions
#

sub read_bytes
{
  my $handle = shift;
  my $size   = shift;

  my $data = "";

  read ($handle, $data, $size);

  # this function is very strict:
  # it only returns something if all the bytes can be read

  if (length ($data) != $size)
  {
    die "ERROR: Couldn't read data from the file. Maybe incorrect file format?\n";
  }

  return $data;
}

#
# Start
#

if (scalar (@ARGV) != 1)
{
  die "usage: $0 file.txt.aes\n";
}

my $file_name = $ARGV[0];

my $file_handle;

if (! open ($file_handle, "<", $file_name))
{
  die "ERROR: Couldn't open file '$file_name'\n";
}

binmode ($file_handle);


# Signature:

my $signature = read_bytes ($file_handle, 3);

if ($signature ne "AES")
{
  die "ERROR: The file doesn't seem to be a correct aescrypt file (signature mismatch)\n";
}

# Version

my $version = read_bytes ($file_handle, 1);

if ($version ne "\x02")
{
  die "ERROR: Currently only aescrypt file version 2 is supported by this script\n";
}


read_bytes ($file_handle, 1); # reservered/skip (normally should be just \x00)


# Loop over the extensions until we got extension size 0

my $extension_size = read_bytes ($file_handle, 2);

while ($extension_size ne "\x00\x00")
{
  my $skip_size = unpack ("S>", $extension_size); # 16-bit lengths

  read_bytes ($file_handle, $skip_size); # skip the extension

  $extension_size = read_bytes ($file_handle, 2);
}

# IV (for KDF)

my $iv = read_bytes ($file_handle, 16);


# IV (encrypted IV for AES decryption)

my $iv_enc = read_bytes ($file_handle, 16);


# key_enc

my $key_enc = read_bytes ($file_handle, 32);


# HMAC

my $hmac = read_bytes ($file_handle, 32);

#
# Hex conversion
#

$iv      = unpack ("H*", $iv);
$iv_enc  = unpack ("H*", $iv_enc);
$key_enc = unpack ("H*", $key_enc);
$hmac    = unpack ("H*", $hmac);

#
# Final output
#

print sprintf ("\$aescrypt\$1*%s*%s*%s*%s\n", $iv, $iv_enc, $key_enc, $hmac);

#
# Cleanup
#

close ($file_handle);

exit (0);

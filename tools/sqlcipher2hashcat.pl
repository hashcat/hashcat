#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# In a first version I wrote a kernel that followed the original sqlcipher scheme which uses a MAC to verify the integrity (and therefore we knew we had guessed the correct password).
# But it turns out it's much easier to exploit the sqlite header format, which guarantees 20 zero bytes starting from offset 72.
# See: https://www.sqlite.org/fileformat.html
# The advantage is the user doesn't need to guess the MAC hash type and/or pagesize (in case it they customized).
# The user still needs to know the KDF hash type and iteration count, but they sqlcipher v3 and v4 come with a default for these.
# We'll check only 12 of 16 bytes from the encrypted block as an optimization so we only need to decrypt one block.
# Another optimization is that since the scheme uses CBC we do not need to find the correct position of the IV.
# This position is depending on the pagesize and the KDF hash type (which could be customized).
# As an alternative, or in case the sqlite header changes, we could also use entropy test.
# -atom

use strict;
use warnings;

if (scalar (@ARGV) < 2)
{
  print "usage: $0 encrypted.db preset [hash] [iteration]\n\n";
  print "preset 1 = SQLCIPHER v3\n";
  print "preset 2 = SQLCIPHER v4\n";
  print "preset 3 = CUSTOM, please specify hash type (1 = SHA1, 2 = SHA256, 3 = SHA512) and iteration count\n";

  exit -1;
}

my $db     = $ARGV[0];
my $preset = $ARGV[1];

my $type = 0;
my $iter = 0;

if ($preset == 1)
{
  $type = 1;
  $iter = 64000;
}
elsif ($preset == 2)
{
  $type = 3;
  $iter = 256000;
}
elsif ($preset == 3)
{
  $type = $ARGV[2];
  $iter = $ARGV[3];
}
else
{
  die "Invalid preset\n";
}

open (IN, $db) or die ("$db: $!\n");

binmode (IN);

my $data;

if (read (IN, $data, 96) != 96)
{
  die "ERROR: Couldn't read data from the file. Maybe incorrect file format?\n";
}

close (IN);

my $salt = substr ($data,  0, 16);
my $iv   = substr ($data, 64, 16);
my $enc  = substr ($data, 80, 16);

printf ("SQLCIPHER*%d*%d*%s*%s*%s\n", $type, $iter, unpack ("H*", $salt), unpack ("H*", $iv), unpack ("H*", $enc));

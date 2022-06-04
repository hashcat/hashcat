#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# for this hashcat extraction tool the input should be a export/dump of the registry key
# [HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security\1]
#
# "reg export" cmd command can be used for this:
# reg export "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security\1" radmin3_export.reg
#
# Note: this tool is intentionally not designed to do an automatic registry key read
# but this could be done easily also in software/perl:
# use Win32::TieRegistry (Delimiter => '/');
# my $reg_key = $Registry->{'HKEY_LOCAL_MACHINE/SOFTWARE/WOW6432Node/Radmin/v3.0/Server/Parameters/Radmin Security'};
# my $file_content = $reg_key->{'/1'};
#
# An example input file (first command line parameter):
#
# [HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security\1]
# "1"=hex:10,00,00,0a,72,00,6f,00,67,00,65,00,72,00,30,00,01,00,98,47,fc,7e,0f,\
#   89,1d,fd,5d,02,f1,9d,58,7d,8f,77,ae,c0,b9,80,d4,30,4b,01,13,b4,06,f2,3e,2c,\
#   ec,58,ca,fc,a0,4a,53,e3,6f,b6,8e,0c,3b,ff,92,cf,33,57,86,b0,db,e6,0d,fe,41,\
#   78,ef,2f,cd,2a,4d,d0,99,47,ff,d8,df,96,fd,0f,9e,29,81,a3,2d,a9,55,03,34,2e,\
#   ca,9f,08,06,2c,bd,d4,ac,2d,7c,df,81,0d,b4,db,96,db,70,10,22,66,26,1c,d3,f8,\
#   bd,d5,6a,10,2f,c6,ce,ed,bb,a5,ea,e9,9e,61,27,bd,d9,52,f7,a0,d1,8a,79,02,1c,\
#   88,1a,e6,3e,c4,b3,59,03,87,f5,48,59,8f,2c,b8,f9,0d,ea,36,fc,4f,80,c5,47,3f,\
#   db,6b,0c,6b,db,0f,db,af,46,01,f5,60,dd,14,91,67,ea,12,5d,b8,ad,34,fd,0f,d4,\
#   53,50,de,c7,2c,fb,3b,52,8b,a2,33,2d,60,91,ac,ea,89,df,d0,6c,9c,4d,18,f6,97,\
#   24,5b,d2,ac,92,78,b9,2b,fe,7d,ba,fa,a0,c4,3b,40,a7,1f,19,30,eb,c4,fd,24,c9,\
#   e5,a2,e5,a4,cc,f5,d7,f5,15,44,d7,0b,2b,ca,4a,f5,b8,d3,7b,37,9f,d7,74,0a,68,\
#   2f,40,00,00,01,05,50,00,00,20,f9,89,48,2b,a8,3b,63,45,fd,1d,d7,e2,13,13,dc,\
#   d5,55,22,ba,57,15,b5,79,ea,b8,74,d7,64,33,92,8d,72,60,00,01,00,01,2a,1b,fd,\
#   53,4a,88,d9,19,40,70,e6,1e,76,07,fd,69,90,94,ea,b6,3b,53,b2,76,6b,0c,f3,5e,\
#   73,fb,cc,21,41,ae,d3,28,1f,64,ca,62,0b,27,95,1c,f5,e2,c2,78,60,37,54,27,5f,\
#   c1,63,51,ee,f0,8f,bb,e3,0c,f5,d9,27,be,c5,61,e5,ea,98,a6,df,a1,ee,e9,00,4b,\
#   00,83,4f,d9,ca,d5,ae,59,1e,ef,4f,c8,8b,f9,73,75,04,d2,9e,c5,93,34,6c,cd,1d,\
#   76,18,82,37,73,8e,0b,6e,8a,f8,47,ef,4a,74,a9,a4,d9,df,04,8d,5d,6b,f2,19,c7,\
#   ab,f5,40,72,00,c3,5d,3c,dc,d5,e7,e2,c6,51,fe,0d,77,bc,60,41,e1,51,96,46,f5,\
#   8b,1c,cc,a2,11,1a,37,25,86,6b,be,2b,60,4f,9d,17,2f,28,53,9a,97,5d,1d,0f,99,\
#   7e,4c,d2,8c,49,7f,ad,62,a7,90,e7,35,2f,19,40,1e,fb,7d,7f,b6,ba,cb,85,e0,67,\
#   4e,ab,03,1d,78,2f,a0,e7,3d,8e,b4,b4,0a,c6,ee,cc,a8,d9,87,fd,b9,0c,c1,01,54,\
#   a5,39,6a,26,7c,69,cb,47,68,c3,a6,43,59,12,bb,b6,0d,68,91,d2,1b,de,bc,da,0f,\
#   0a,b5,20,00,00,04,ff,01,00,00

use strict;
use warnings;
use utf8;


#
# Constants:
#

my $REGISTRY_PREFIX = "=hex:";

my $ENTRY_KEY_USER       = 16;
my $ENTRY_KEY_MODULUS    = 48;
my $ENTRY_KEY_GENERATOR  = 64;
my $ENTRY_KEY_SALT       = 80;
my $ENTRY_KEY_VERIFIER   = 96;

my $HARD_CODED_GENERATOR = "05";
my $HARD_CODED_MODULUS   = "9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96db70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a79021c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb0fdbaf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d6091acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f1930ebc4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f";


#
# Start:
#

if (scalar (@ARGV) < 1)
{
  print STDERR "Usage:\n" . $0 . " <radmin3.reg>\n\n";
  print STDERR "Please specify the Radmin 3 registry export file as command line parameter\n\n";
  print STDERR "The registry key is something like:\n";
  print STDERR "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin Security\\1\n";

  exit (1);
}

my $file_name = $ARGV[0];

my $fh;

if (! open ($fh, "<", $file_name))
{
  print STDERR "ERROR: Could not open the registry dump file '$file_name'\n";

  exit (1);
}

binmode ($fh);

my $file_content = "";

{
  local $/ = undef;

  $file_content = <$fh>;
}

close ($fh);


if (length ($file_content) < 5 + 0) # replace 0 with minimum expected length
{
  print STDERR "ERROR: File size of file '$file_name' is invalid\n";

  exit (1);
}

$file_content =~ s/[\x00]//g; # this could be true if UTF16 + BOM are being used

my $prefix_idx = index ($file_content, $REGISTRY_PREFIX);

if ($prefix_idx < 0)
{
  print STDERR "ERROR: Could not find the key '=hex:' within the file content\n";

  exit (1);
}

$file_content = substr ($file_content, $prefix_idx + length ($REGISTRY_PREFIX));

# $file_content =~ s/[ \r\n,\\]//g;

# we could also remove every character that is not an hexadecimal symbol:
$file_content =~ s/[^0-9a-fA-F]//g;

$file_content = pack ("H*", $file_content);


# final length check (needed ?):

my $file_content_len = length ($file_content);

if ($file_content_len < 2 + 1 + 2 + 1 + 2 + 32 + 2 + 256 + 2 + 256) # replace with min length
{
  print STDERR "ERROR: File content of file '$file_name' is too short\n";

  exit (1);
}


# loop over the data:

my $user     = "";
my $salt     = "";
my $verifier = "";

my $found_user      = 0;
my $found_modulus   = 0;
my $found_generator = 0;
my $found_salt      = 0;
my $found_verifier  = 0;

for (my $i = 0; $i < $file_content_len; $i += 4)
{
  if ($i + 4 > $file_content_len)
  {
    print STDERR "ERROR: Unexpected EOF (end of file) in file '$file_name'\n";

    exit (1);
  }

  my $type = ord (substr ($file_content, $i + 1, 1)) * 256 +
             ord (substr ($file_content, $i + 0, 1));
  my $len  = ord (substr ($file_content, $i + 2, 1)) * 256 +
             ord (substr ($file_content, $i + 3, 1));

  my $pos = $i + 4;

  $i += $len;

  # we are not interested in other values than what we need:

  if (($type != $ENTRY_KEY_USER)      &&
      ($type != $ENTRY_KEY_MODULUS)   &&
      ($type != $ENTRY_KEY_GENERATOR) &&
      ($type != $ENTRY_KEY_SALT)      &&
      ($type != $ENTRY_KEY_VERIFIER))
  {
    next;
  }

  if ($i > $file_content_len)
  {
    print STDERR "ERROR: Unexpected EOF (end of file) in file '$file_name'\n";

    exit (1);
  }


  #
  # get the data, finally:
  #

  my $value = substr ($file_content, $pos, $len);

  $value = unpack ("H*", $value);

  if ($type == $ENTRY_KEY_USER)
  {
    $user = $value;

    $found_user = 1;
  }
  elsif ($type == $ENTRY_KEY_MODULUS)
  {
    if ($value ne $HARD_CODED_MODULUS)
    {
      print STDERR "ERROR: Non-default modulus found in file '$file_name'\n";

      exit (1);
    }

    $found_modulus = 1;
  }
  elsif ($type == $ENTRY_KEY_GENERATOR)
  {
    if ($value ne $HARD_CODED_GENERATOR)
    {
      print STDERR "ERROR: Non-default generator found in file '$file_name'\n";

      exit (1);
    }

    $found_generator = 1;
  }
  elsif ($type == $ENTRY_KEY_SALT)
  {
    $salt = $value;

    $found_salt = 1;
  }
  elsif ($type == $ENTRY_KEY_VERIFIER)
  {
    $verifier = $value;

    $found_verifier = 1;
  }
}

if ($found_user == 0)
{
  print STDERR "ERROR: No user name found in file '$file_name'\n";

  exit (1);
}

if ($found_modulus == 0)
{
  print STDERR "ERROR: No modulus found in file '$file_name'\n";

  exit (1);
}

if ($found_generator == 0)
{
  print STDERR "ERROR: No generator found in file '$file_name'\n";

  exit (1);
}

if ($found_salt == 0)
{
  print STDERR "ERROR: No salt found in file '$file_name'\n";

  exit (1);
}

if ($found_verifier == 0)
{
  print STDERR "ERROR: No verifier found in file '$file_name'\n";

  exit (1);
}


#
# Output:
#

print sprintf ("\$radmin3\$%s*%s*%s\n",
  $user,
  $salt,
  $verifier);

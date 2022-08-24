#!/usr/bin/env perl

##
## This script was created to be used in conjunction with Hashcat mode 29700 (Keepass in keyfile only mode).
## This can be useful if you have a partition and forgot which of the files was used as the keyfile.
## 
## Example use (if your target drive is mounted to /mnt/sda1 and (optionally) another one to /mnt/sda2):
##
## $ perl recursivefiles2sha256sum /mnt/sda1 /mnt/sda2 > wordlist.dict
## $ ./hashcat kdbxdb.hash wordlist.dict
##
## Note that the redirection operator > also works on Windows cmd.exe.
## To run perl in Windows use strawberry perl

use strict;
use warnings;
use File::Find;
use Digest::SHA;

my $sha = Digest::SHA->new ("sha256");

my @folders = @ARGV;

if (scalar @folders == 0) 
{
  die ("use: $0 folder1 folder2...\n");
}

find (\&handlefile, @folders);

sub handlefile 
{
  my $file = $_;

  return unless -f $file;
  return unless -r $file;
  
  my $sha_copy = $sha->clone;

  $sha_copy->addfile  ($file);

  my $digest = $sha_copy->hexdigest;

  print "$digest\n";
}

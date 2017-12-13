#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;
use DBI;
use DBD::SQLite;

die "usage: $0 NoteStore.sqlite\n" unless (scalar @ARGV == 1);

my $database = shift @ARGV;
my $dsn      = "DBI:SQLite:dbname=$database";
my $userid   = "";
my $password = "";

my $dbh = DBI->connect ($dsn, $userid, $password, { RaiseError => 1 }) or die $DBI::errstr;

my $sth = $dbh->prepare ("SELECT Z_PK,ZCRYPTOITERATIONCOUNT,ZCRYPTOSALT,ZCRYPTOWRAPPEDKEY FROM ZICCLOUDSYNCINGOBJECT WHERE ZISPASSWORDPROTECTED=1");

$sth->execute () or die $DBI::errstr;

while (my $row = $sth->fetchrow_arrayref ())
{
  printf ("\$ASN\$*%d*%d*%s*%s\n", $row->[0], $row->[1], unpack ("H*", $row->[2]), unpack ("H*", $row->[3]));
}

$sth->finish;

$dbh->disconnect ();

exit (0);

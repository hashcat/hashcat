#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

# ShangMi 3 (SM3), raw unsalted digest. No Perl core/Digest module ships SM3, so
# compute it with Python's hashlib (OpenSSL provides "sm3"). test.pl generates
# numeric-only passwords, so passing $word straight into the shell is safe here.

sub module_generate_hash
{
  my $word = shift;

  my $digest = do
  {
    local $ENV{PYTHONUTF8} = 1;
    qx{python3 -c 'import sys,hashlib; sys.stdout.write(hashlib.new("sm3", sys.argv[1].encode()).hexdigest())' "$word"};
  };

  $digest =~ s/[\r\n]//g;

  my $hash = sprintf ("%s", $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;

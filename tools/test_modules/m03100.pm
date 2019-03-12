#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;

sub module_constraints { [[-1, -1], [-1, -1], [0, 30], [0, 30], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = oracle_hash ($salt, $word);

  my $hash = sprintf ("%s:%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
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

1;

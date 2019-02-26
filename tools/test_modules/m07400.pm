#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [0, 16], [0, 15], [0, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $hash_buf;

  if (defined $iter)
  {
    $hash_buf = crypt ($word, "\$5\$rounds=$iter\$$salt\$");
  }
  else
  {
    $hash_buf = crypt ($word, "\$5\$$salt\$");
  }

  my $hash = sprintf ("%s", $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":", 30);

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  $index1 = index ($hash_in,  ",", 1);

  my $index2 = index ($hash_in, "\$", 1);

  if ($index1 != -1)
  {
    if ($index1 < $index2)
    {
      $index2 = $index1;
    }
  }

  #$param = substr ($hash_in, $index2, 1);

  $index2++;

  # rounds= if available
  my $iter;

  if (substr ($hash_in, $index2, 7) eq "rounds=")
  {
    my $old_index = $index2;

    $index2 = index ($hash_in, "\$", $index2 + 1);

    return if $index2 < 1;

    $iter = substr ($hash_in, $old_index + 7, $index2 - $old_index - 7);

    $index2++;
  }

  # get salt
  my $index3 = rindex ($hash_in, "\$");

  return if $index3 < 1;

  my $salt = substr ($hash_in, $index2, $index3 - $index2);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;


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
    $hash_buf = crypt ($word, "\$6\$rounds=$iter\$$salt\$");
  }
  else
  {
    $hash_buf = crypt ($word, "\$6\$$salt\$");
  }

  my $hash = sprintf ("%s", $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $index1 = index ($hash, ',', 1);
  my $index2 = index ($hash, '$', 1);

  if ($index1 != -1)
  {
    if ($index1 < $index2)
    {
      $index2 = $index1;
    }
  }

  $index2++;

  # rounds= if available
  my $iter = 0;

  if (substr ($hash, $index2, 7) eq "rounds=")
  {
    my $old_index = $index2;

    $index2 = index ($hash, '$', $index2 + 1);

    return if $index2 < 1;

    $iter = substr ($hash, $old_index + 7, $index2 - $old_index - 7);

    $index2++;
  }

  # get salt
  my $index3 = rindex ($hash, '$');

  return if $index3 < 1;

  my $salt = substr ($hash, $index2, $index3 - $index2);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;

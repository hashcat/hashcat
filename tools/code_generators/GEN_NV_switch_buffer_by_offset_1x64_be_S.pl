#!/usr/bin/perl

use strict;
use warnings;

for (my $i = 0, my $s = 0; $i < 64; $i++, $s++)
{
  printf ("    case %2d:\n", $i);

  for (my $j = 64 - 1; $j >= 0; $j--)
  {
    if ((($j - $s - 1) >= 0) && (($j - $s - 0) >= 0))
    {
      printf ("      w[%2d] = hc_byte_perm_S (w[%2d], w[%2d], selector);\n", $j, $j - $s - 0, $j - $s - 1);
    }
    elsif (($j - $s - 0) >= 0)
    {
      printf ("      w[%2d] = hc_byte_perm_S (w[%2d],     0, selector);\n", $j, $j - $s - 0);
    }
    else
    {
      printf ("      w[%2d] = 0;\n", $j);
    }
  }
  printf ("\n");

  printf ("      break;\n");
  printf ("\n");
}

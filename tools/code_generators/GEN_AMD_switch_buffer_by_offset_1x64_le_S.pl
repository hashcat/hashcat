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
      printf ("      w[%2d] = hc_bytealign_S (w[%2d], w[%2d], offset_minus_4);\n", $j, $j - $s - 0, $j - $s - 1);
    }
    elsif (($j - $s - 0) >= 0)
    {
      printf ("      w[%2d] = hc_bytealign_S (w[%2d],     0, offset_minus_4);\n", $j, $j - $s - 0);
    }
    else
    {
      printf ("      w[%2d] = 0;\n", $j);
    }
  }
  printf ("\n");

  printf ("      if (offset_mod_4 == 0)\n");
  printf ("      {\n");
  for (my $j = $i; $j < 64 - 1; $j++)
  {
    printf ("        w[%2d] = w[%2d];\n", $j, $j + 1);
  }
  printf ("        w[63] = 0;\n");
  printf ("      }\n");
  printf ("\n");

  printf ("      break;\n");
  printf ("\n");
}

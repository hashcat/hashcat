#!/usr/bin/perl

use strict;
use warnings;

for (my $i = 0, my $s = 0; $i < 16; $i++, $s++)
{
  printf ("    case %2d:\n", $i);

  for (my $j = 16 - 1; $j >= 0; $j--)
  {
    my $jd4   = $j / 4;
    my $jm4   = $j % 4;

    my $js1d4 = ($j - $s - 1) / 4;
    my $js1m4 = ($j - $s - 1) % 4;

    my $js0d4 = ($j - $s - 0) / 4;
    my $js0m4 = ($j - $s - 0) % 4;

    if ((($j - $s - 1) >= 0) && (($j - $s - 0) >= 0))
    {
      printf ("      w%d[%d] = hc_byte_perm_S (w%d[%d], w%d[%d], selector);\n", $jd4, $jm4, $js0d4, $js0m4, $js1d4, $js1m4);
    }
    elsif (($j - $s - 0) >= 0)
    {
      printf ("      w%d[%d] = hc_byte_perm_S (w%d[%d],     0, selector);\n", $jd4, $jm4, $js0d4, $js0m4);
    }
    else
    {
      printf ("      w%d[%d] = 0;\n", $jd4, $jm4, );
    }
  }
  printf ("\n");

  printf ("      break;\n");
  printf ("\n");
}

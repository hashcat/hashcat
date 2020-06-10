#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

for (my $i = 0, my $s = 0; $i < 32; $i++, $s++)
{
  printf ("    case %2d:\n", $i);
  for (my $j = 64 - 1; $j >= 0; $j--)
  {
    my $jd4   = $j / 4;
    my $jm4   = $j % 4;

    my $js1d4 = ($j - $s - 1) / 4;
    my $js1m4 = ($j - $s - 1) % 4;

    my $js0d4 = ($j - $s - 0) / 4;
    my $js0m4 = ($j - $s - 0) % 4;

    next if (($j - $s) > 32);

    my $c1 = "w";
    my $c2 = "w";
    my $c3 = "w";

    if ($jd4 >= 8)
    {
      $jd4 -= 8;

      $c1 = "c";
    }

    if ($js0d4 >= 8)
    {
      printf ("      %s%d[%d] = hc_bytealign_S (%s%d[%d],     0, offset);\n", $c1, $jd4, $jm4, $c2, $js1d4, $js1m4);
    }
    elsif ((($j - $s - 1) >= 0) && (($j - $s - 0) >= 0))
    {
      printf ("      %s%d[%d] = hc_bytealign_S (%s%d[%d], %s%d[%d], offset);\n", $c1, $jd4, $jm4, $c2, $js1d4, $js1m4, $c3, $js0d4, $js0m4);
    }
    elsif (($j - $s - 0) >= 0)
    {
      printf ("      %s%d[%d] = hc_bytealign_S (    0, %s%d[%d], offset);\n", $c1, $jd4, $jm4, $c2, $js0d4, $js0m4);
    }
    else
    {
      printf ("      %s%d[%d] = 0;\n", $c1, $jd4, $jm4);
    }
  }
  printf ("\n");

  printf ("      break;\n");
  printf ("\n");
}

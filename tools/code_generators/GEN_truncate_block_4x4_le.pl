#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

for (my $i = 0; $i < 16; $i++)
{
  printf ("    case %2d:\n", $i);

  my $id4 = int ($i / 4);
  my $im4 = int ($i % 4);

  if ($im4 == 0)
  {
    printf ("      w%d[%d]  = 0;\n", $id4 / 4, $id4 % 4);
  }
  elsif ($im4 == 1)
  {
    printf ("      w%d[%d] &= 0x000000ff;\n", $id4 / 4, $id4 % 4);
  }
  elsif ($im4 == 2)
  {
    printf ("      w%d[%d] &= 0x0000ffff;\n", $id4 / 4, $id4 % 4);
  }
  elsif ($im4 == 3)
  {
    printf ("      w%d[%d] &= 0x00ffffff;\n", $id4 / 4, $id4 % 4);
  }

  for (my $j = $id4 + 1; $j < 4; $j++)
  {
    my $jd4 = int ($j / 4);
    my $jm4 = int ($j % 4);

    printf ("      w%d[%d]  = 0;\n", $jd4, $jm4);
  }

  printf ("\n");

  printf ("      break;\n");
  printf ("\n");
}

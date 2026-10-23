#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import re

HEADER = os.path.join (os.path.dirname (os.path.abspath (__file__)), "..", "..", "bridges", "fpga", "hcfpga.h")

PATTERN = re.compile (r'^\s*#define\s+FPGA_ABI_CURRENT\s+(\d+)', re.MULTILINE)

def fpga_abi_current ():
  path = os.path.normpath (HEADER)

  try:
    text = open (path, encoding = "utf-8", errors = "replace").read ()
  except OSError as exc:
    raise SystemExit ("cannot read the wire ABI from %s: %s\n"
                      "The bridge header is the only place FPGA_ABI_CURRENT is written down. Build\n"
                      "through 'make -C src/fpga' from a complete checkout, or pass --abi yourself."
                      % (path, exc))

  found = PATTERN.search (text)

  if found is None:
    raise SystemExit ("no '#define FPGA_ABI_CURRENT <n>' in %s\n"
                      "Either the header moved or the define was renamed. Fix this script rather than\n"
                      "guessing a value: a wrong ABI builds for hours and is then refused." % path)

  abi = int (found.group (1))

  return abi

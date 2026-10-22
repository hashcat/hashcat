#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HASH = "$pdf$4*4*128*-1028*1*16*71801606599758691188663457360617*32*bcbcf8b9b35221fa093bb171a85b030400000000000000000000000000000000*32*62ef4b123c08b03f007758fe759b5e4a0dae57f649e6fd23b66efa4b33c6d044"
PASSWORD = "829131696217853"


def main():
  parser = argparse.ArgumentParser(description="Check copied temporary data after amplifier packing")
  parser.add_argument("--hashcat", type=Path, default=ROOT / "hashcat", help="hashcat binary to test")
  parser.add_argument("-D", dest="device", default="1", help="hashcat device type (default: CPU)")
  parser.add_argument("-f", dest="force", action="store_true", help="pass --force to hashcat")
  args = parser.parse_args()

  with tempfile.TemporaryDirectory(prefix="test_copy_tmps_") as tmp:
    work = Path(tmp)
    (work / "cache").mkdir()

    def words(name, values):
      path = work / name
      path.write_text("".join(value + "\n" for value in values))
      return str(path)

    left = words("left", ["5", PASSWORD[:7]])
    right = words("right", ["2", PASSWORD[7:]])
    whole = words("whole", [PASSWORD])
    rules = words("rules", ["$x", ":"])
    head = words("head", [PASSWORD[:-1]])
    tail = words("tail", ["2", PASSWORD[1:]])

    cases = [
      ("literal mask", 3, [PASSWORD]),
      ("rules", 0, [whole, "-r", rules]),
      ("combinator", 1, [left, right]),
      ("append mask", 6, [head, "?d"]),
      ("prepend mask", 7, ["?d", tail]),
      ("word mask", 12, ["?d?w", tail]),
    ]

    failures = 0

    for name, attack, inputs in cases:
      outfile = work / (str(attack) + ".out")
      command = [str(args.hashcat.resolve()), "-m", "25400", "-a", str(attack),
                 "-D", args.device, "--quiet", "--potfile-disable", "--restore-disable", "--logfile-disable",
                 "--session", work.name,
                 "--cache-path", str(work / "cache"), "--outfile", str(outfile),
                 "--outfile-format", "2"]

      if args.force:
        command.append("--force")

      command += [HASH, *inputs]
      result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      actual = outfile.read_bytes() if outfile.exists() else b""
      expected = (PASSWORD + "    (user password not set)").encode("ascii")

      if result.returncode != 0 or actual.splitlines() != [expected]:
        failures += 1
        print("FAIL %s: rc=%d, outfile=%r" % (name, result.returncode, actual))
        print(result.stdout.decode("utf-8", "replace"))
      else:
        print("PASS " + name)

    print("Errors detected: %d" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
  raise SystemExit(main())

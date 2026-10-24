#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct
import unittest

import hcshared


class GenericRecordsTest(unittest.TestCase):
  def test_variable_records(self):
    records = [(b"", b""), (b"hash", b"short"), (b"other", b"x" * 131072)]
    payload = b"".join(struct.pack("=II", len(h), len(s)) + h + s for h, s in records)

    self.assertEqual(len(payload), sum(8 + len(h) + len(s) for h, s in records))
    self.assertEqual(hcshared.extract_generic_esalts(payload),
                     [{"hash_buf": h, "salt_buf": s} for h, s in records])
    self.assertEqual(hcshared.extract_generic_esalts(b""), [])

  def test_truncated_records(self):
    payload = struct.pack("=II", 4, 5) + b"hashshort"

    for end in range(1, len(payload)):
      with self.subTest(end=end):
        with self.assertRaises(ValueError):
          hcshared.extract_generic_esalts(payload[:end])

    with self.assertRaises(ValueError):
      hcshared.extract_generic_esalts(payload + b"x")

    with self.assertRaises(ValueError):
      hcshared.extract_generic_esalts(struct.pack("=II", 0xffffffff, 0xffffffff))


if __name__ == "__main__":
  unittest.main()

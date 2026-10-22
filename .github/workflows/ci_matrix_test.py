#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from collections import Counter
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import ci_matrix

ROOT = Path(__file__).resolve().parents[2]


def plan(*args):
    output = subprocess.check_output([sys.executable, str(Path(__file__).with_name("ci_matrix.py")),
                                      *args], cwd=ROOT, text=True)
    values = dict(line.split("=", 1) for line in output.splitlines())
    return json.loads(values["matrix"])["include"]


def modes(rows, kind):
    return [int(mode) for row in rows if row["kind"] == kind for mode in row["modes"].split()]


class MatrixTests(unittest.TestCase):
    def test_full_matrix_fits_github_limit_and_covers_each_mode_once(self):
        rows = plan("test", "all")
        self.assertLessEqual(len(rows), 256)
        self.assertEqual(Counter(row["kind"] for row in rows),
                         {"opt": 48, "pure": 48, "bridge": 48, "container": 16, "edge": 96})
        self.assertEqual(len({row["name"] for row in rows}), len(rows))

        for kind in ("opt", "pure", "bridge", "edge", "container"):
            selected = modes(rows, kind)
            self.assertEqual(len(selected), len(set(selected)))
            self.assertTrue(all(row["modes"] for row in rows))

        for kind in ("pure", "bridge", "edge"):
            self.assertEqual(set(modes(rows, kind)), set(modes(rows, "opt")))

        self.assertFalse(set(modes(rows, "edge")) & set(modes(rows, "container")))

    def test_ordinary_selection_keeps_the_existing_matrix(self):
        rows = plan("test", "all", "--kinds", "opt,pure,bridge,container")
        self.assertEqual(len(rows), 160)
        self.assertNotIn("edge", {row["kind"] for row in rows})

    def test_edge_only_and_selected_modes(self):
        rows = plan("test", "all", "--kinds", "edge")
        self.assertEqual(len(rows), 96)
        self.assertEqual({row["kind"] for row in rows}, {"edge"})

        rows = plan("test", "list", "0 9500 9500", "--kinds", "edge")
        self.assertEqual(sorted(modes(rows, "edge")), [0, 9500])
        self.assertEqual(len(rows), 2)

    def test_mixed_selection_keeps_containers_separate(self):
        rows = plan("test", "list", "0 9500 13711", "--kinds", "pure,container,edge")
        self.assertEqual(sorted(modes(rows, "pure")), [0, 9500])
        self.assertEqual(sorted(modes(rows, "edge")), [0, 9500])
        self.assertEqual(modes(rows, "container"), [13711])
        self.assertEqual(len(rows), 5)

    def test_pull_request_stays_optimized_only(self):
        output = io.StringIO()

        with patch.object(sys, "argv", ["ci_matrix.py", "test", "pr", "HEAD", "--kinds", "edge"]), \
             patch.object(ci_matrix, "changed_files", return_value=[".github/workflows/test.yml", "src/modules/module_09500.c"]), \
             contextlib.redirect_stdout(output):
            ci_matrix.main()

        values = dict(line.split("=", 1) for line in output.getvalue().splitlines())
        rows = json.loads(values["matrix"])["include"]
        self.assertEqual({row["kind"] for row in rows}, {"opt"})
        self.assertIn(9500, modes(rows, "opt"))

    def test_fuzz_matrix_keeps_its_existing_shape(self):
        rows = plan("fuzz", "all")
        self.assertLessEqual(len(rows), 16)
        self.assertTrue(rows)
        self.assertTrue(all("kind" not in row and "rule_tok" in row for row in rows))


if __name__ == "__main__":
    unittest.main()

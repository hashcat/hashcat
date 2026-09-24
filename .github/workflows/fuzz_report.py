#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Turns the log of one fuzz target that stopped on a finding into something a
## reader can act on without opening the log: what was found, where in the
## source, the input, and a command that reproduces it.
##
##   fuzz_report.py <target> <log> <crash dir>
##
## Prints a ::error annotation, pointed at the source line so it shows on the
## pull request's diff when that line is in it, and appends a section to
## $GITHUB_STEP_SUMMARY.

import base64
import glob
import os
import re
import sys

# the first frame in hashcat's own code is where to look, less the allocator a
# leak is always reported from and the harness that called the parser

FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) \S*?/((?:src|include|tools)/[^:\s]+):(\d+)")
SKIP = ("src/memory.c", "tools/fuzz/")

# past this the input goes in the artifact only, an annotation is not the place for it

INLINE_MAX = 600


def finding(log):
    m = re.search(r"ERROR: (AddressSanitizer|MemorySanitizer|LeakSanitizer|libFuzzer): ([^\n]+?)(?: on address.*)?$", log, re.M)

    if m:
        kind = "memory leak" if m.group(1) == "LeakSanitizer" else m.group(2).strip()
    else:
        m = re.search(r"runtime error: ([^\n]+)", log)
        kind = "undefined behaviour: " + m.group(1) if m else "the target exited non zero"

    detail = re.search(r"^\s*((?:READ|WRITE) of size \d+|Direct leak of \d+ byte\(s\))", log, re.M)

    return kind, detail.group(1) if detail else ""


def where(log):
    frames = FRAME.findall(log)

    for func, path, line in frames:
        if not path.startswith(SKIP):
            return func, path, int(line)

    return (frames[0][0], frames[0][1], int(frames[0][2])) if frames else (None, None, None)


def main():
    target, log_path, crash_dir = sys.argv[1:4]

    with open(log_path, errors="replace") as f:
        log = f.read()

    kind, detail = finding(log)
    func, path, line = where(log)

    crashes = sorted(glob.glob(os.path.join(crash_dir, "*")), key=os.path.getmtime)

    data = open(crashes[0], "rb").read() if crashes else None

    if target.startswith("parse_"):
        build = f"FUZZ_MODES={int(target[6:]):05d} tools/fuzz/build.sh"
    else:
        build = "tools/fuzz/build.sh"

    if data is not None and len(data) <= INLINE_MAX:
        b64 = base64.b64encode(data).decode()
        repro = f"{build} && echo {b64} | base64 -d > crash && ./fuzz_out/fuzz_{target} crash"
    elif data is not None:
        repro = f"{build} && ./fuzz_out/fuzz_{target} {os.path.basename(crashes[0])}   (the input is in the job's artifact, {len(data)} bytes)"
    else:
        repro = f"{build}, then run ./fuzz_out/fuzz_{target} on the input in the job's artifact"

    at = f" in {func} ()" if func else ""
    title = f"fuzz_{target}: {kind}"
    text = f"{detail}{at}. Reproduce: {repro}".lstrip(". ")

    # An annotation message ends at the first newline and loses '%', so both are escaped. A
    # property value is also cut at ',' and at ':', which a sanitizer's own wording carries
    # ("signed integer overflow: ..."), so title and file escape those two as well.

    esc = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def prop(value):
        return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A") \
                         .replace(":", "%3A").replace(",", "%2C")

    loc = f"file={prop(path)},line={line}," if path else ""

    print(f"::error {loc}title={prop(title)}::{esc}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")

    if summary:
        with open(summary, "a") as f:
            f.write(f"### fuzz_{target}: {kind}\n\n")

            if path:
                f.write(f"{detail}{at}, `{path}:{line}`\n\n")

            # the line itself when it can be read as one, the base64 in the command otherwise

            if data is not None and len(data) <= INLINE_MAX and re.fullmatch(rb"[\x20-\x7e]*", data) and b"`" not in data:
                f.write(f"Input, {len(data)} bytes: `{data.decode()}`\n\n")

            f.write(f"```\n{repro}\n```\n\n")


if __name__ == "__main__":
    main()

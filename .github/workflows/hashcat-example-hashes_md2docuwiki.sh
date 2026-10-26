#!/usr/bin/env bash

set -euo pipefail

# Convert the markdown to DokuWiki formatting for:
# https://hashcat.net/wiki/doku.php?id=example_hashes

cat ../../docs/hashcat-example-hashes.md |
    sed -E 's/\[\^(.+)\]/<sup>\1<\/sup>/g' | # Replace footnotes
    sed 's/| hash-Mode | hash-Name | Example |/\^ hash-Mode \^ hash-Name \^ Example \^/g' | # Replace header
    grep -Fv -- '-----------' |  # Remove unnecessary table style
    sed 's/`//g' | # Remove backticks
    sed -E 's/\[([0-9]+)\]\(\/src\/modules\/module_([0-9]{5})\.c\)/[[\1|https:\/\/github.com\/hashcat\/hashcat\/tree\/master\/src\/modules\/module_\2.c]]/'   # Replace URLs to GitHub modules

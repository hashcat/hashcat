Reference RAR hash for tools/test.sh
====================================

23800.hash is the hash John's rar2john read out of a real RAR3 archive with a
password-encrypted, compressed member. The password is "hashcat", which is what
test.sh's RAR_TEST_PASS holds.

Why this is committed rather than generated
-------------------------------------------

Every other RAR mode has a test.pl oracle in tools/test_modules/ that makes a
hash for an arbitrary password. 23800 (RAR3-p, compressed) cannot have one: the
hash covers a genuinely compressed RAR3 stream, so an oracle would have to
reproduce RAR's compressor.

test.sh's -g does build one with the real rar, but that needs a RARLAB rar 6.x
or older, which is not packaged by any distribution and cannot be installed
with a package manager. Leaving 23800 to -g alone would make it the only hash
mode whose coverage depends on a binary almost nobody has. A single line of
text covers it in every run instead, and -g stays as the stronger check on top,
building a fresh archive every time it runs.

Only the hash is kept here. The archive it came from is not, because nothing in
the test needs it: hashcat is given the hash, and anyone who wants the archive
back can rebuild it in three commands.

Rebuilding
----------

  # rar 6.x or older; rar 7.x dropped -ma4 and can only write RAR5
  curl -O https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
  mkdir -p "${HOME}/rar-old"
  tar xzf rarlinux-x64-612.tar.gz -C "${HOME}/rar-old" --strip-components=1

  yes "pattern the quick brown fox jumps over the lazy dog " | head -c 8000 > payload.txt
  "${HOME}/rar-old/rar" a -ma4 -m3 -phashcat -inul 23800.rar payload.txt

  rar2john 23800.rar | sed -E 's/^[^:]*://' | grep -oE '^\$RAR3\$[^:]+' | head -1 > 23800.hash

-m3 is what makes the member compressed, which is what separates 23800 from
23700; the payload repeats so that it really does compress, 8000 bytes in and
96 out for the hash committed here. Any archive built this way will do: the
salt differs every time, and the test only needs a hash whose password is
known.

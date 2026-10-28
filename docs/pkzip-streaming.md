# PKZIP streaming mode 17240

Mode 17240 reads a ZIP archive directly. It supports traditional ZipCrypto with
stored (method 0) and DEFLATE (method 8) members in single-volume ZIP and ZIP64
archives, including data descriptors. AES and strong encryption are unsupported.

```sh
make
./hashcat -m 17240 -a 0 archive.zip passwords.txt
./hashcat -m 17240 -a 3 archive.zip '?d?d?d?d?d?d'
./hashcat -m 17240 --pkzip-member-index 2 -a 0 archive.zip passwords.txt
```

The default member is the smallest supported encrypted file with enough verification
data: at least 4 bytes for stored members, and nonempty content for DEFLATE. The
optional index is zero-based and counts all central directory entries, including
directories and unsupported members. An explicitly selected empty, short stored or
unsupported entry is an error. Empty passwords remain valid for supported data.

ZipCrypto can produce multiple valid password candidates. Use `--keep-guessing` to
continue after a match. DEFLATE verification requires the zlib runtime. Stored
members can be verified without it.

The GPU derives the ZipCrypto keys, checks the encryption header and rejects
invalid DEFLATE headers. Surviving candidates go to a host hook that decrypts in
32 KiB chunks, inflates when necessary, and verifies the complete length and CRC32.
Each hook worker owns separate file handles and buffers for each backend device.
Memory usage is independent of the member size.

The source path comes only from the command-line input. ZIP member names are never
opened. The archive must remain available and unchanged during the attack. A source
open, seek or read failure, or a detected change in its identity, size, timestamp or
sample, stops the session with a task error. It is not reported as exhaustion.

Potfile storage, `--show` and outfile checking are disabled, as with container modes.
The `--remove` option is rejected because its hash-list rewrite would damage the ZIP.
Use `--outfile` to retain recovered passwords. For ZIP input the hash field in the
output is the archive path, which can be used as input again with the same member
selection option. Inline input retains its inline format. Existing native PKZIP
modes remain available for inputs that fit their buffers.

For self-tests and small oracle vectors only, a complete inline member is accepted:

```text
$pkzip-stream$*METHOD*0*PACKED*UNPACKED*CRC*CHECK*SAMPLE*-
```

Numeric fields are hexadecimal. CRC has eight digits and CHECK has two. SAMPLE
contains the entire encrypted member, including its 12-byte encryption header, and
is at most 256 bytes. UNPACKED must be at least 4 for stored members and nonzero for
DEFLATE. External path references from the previous experimental format are rejected
without opening the referenced path.

```sh
python3 tools/test.py -S -m 17240
python3 tools/test.py -P -m 17240 -a all
python3 tools/test.py --edge -m 17240
python3 tools/test_pkzip_stream.py
```

The direct-input tests create synthetic encrypted archives. They cover stored,
fixed and dynamic DEFLATE, ZIP64, signed and unsigned data descriptors, Unicode,
empty and short members, empty passwords, explicit member selection, output paths,
source failures, wrong passwords and CRCs, damaged data, truncated input and rejected
external references. The default member size is 1 MiB. Use `--size-mib` for larger
inputs and `--backend-arg` for runtime options.

Streaming trades the native modes' fixed data buffers for host verification and
file reads. Stored members have a weaker initial filter and can be CPU or I/O bound.
The mode removes the member-size barrier but cannot promise the same speed for every
archive. Select `--hook-threads` using the actual workload.

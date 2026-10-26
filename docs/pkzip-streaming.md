# PKZIP streaming mode 17240

This mode recovers traditional ZipCrypto passwords for stored (method 0) and DEFLATE
(method 8) members without putting the whole encrypted member in an esalt. It does not change modes
17200, 17210, 17220, 17225 or 17230.

The GPU derives the three ZipCrypto keys, checks the encryption header and rejects invalid DEFLATE
headers. Candidates that survive go to a host hook. The hook decrypts the referenced member in
32 KiB chunks, inflates it when required, and checks the final CRC32 and uncompressed length.
Only a complete verification can reach the result kernel, outfile or potfile.

Memory per hook thread is independent of the member size. It consists of two 32 KiB buffers, the
CRC table and a zlib window. Offsets and lengths are 64 bit. Windows paths are decoded from UTF-8
and opened with the wide-character file API.

Normal hashcat device and host batch buffers still apply. Passwords can contain up to 256 bytes.

## Hash format

```text
$pkzip-stream$*METHOD*OFFSET*PACKED*UNPACKED*CRC*CHECK*SAMPLE*PATH
```

All numeric fields are hexadecimal. CRC has eight digits and CHECK has two. SAMPLE is 12 to 256
encrypted bytes beginning at the member's encryption header. PATH is the UTF-8 path encoded as hex.
OFFSET points to the first encryption-header byte, and PACKED includes its 12 bytes. CHECK is the
last plaintext byte of that header, selected from the CRC or DOS timestamp according to ZIP flag 8.

The source file must remain available and unchanged. Loading validates the declared bounds and
sample. Each surviving candidate checks the sample again before streaming the member. A missing or
truncated source is rejected, and a stream with a wrong length or CRC is never accepted.

For self-tests and small oracle vectors, PATH can be `-`. In that case SAMPLE must contain the
complete encrypted member, so PACKED must equal the sample length.

## Build and run

The normal build discovers `src/modules/module_17240.c` automatically. A working zlib runtime is
required for this mode, using the same dynamic loader as the other DEFLATE users.

```sh
make
python3 tools/zip2hashcat-stream.py archive.zip > archive.hash
./hashcat -m 17240 -a 0 archive.hash passwords.txt
./hashcat -m 17240 -a 3 archive.hash '?d?d?d?d?d?d'
python3 tools/test.py --edge -m 17240 --allow-all-attacks
python3 tools/test_pkzip_stream.py
```

The extractor selects the smallest supported encrypted member. Use `--member` with an exact member
name to select a different one. AES and strong-encryption ZIP members are not supported by this mode.
A hash from another machine needs its referenced file at the encoded path, or it must be exported
again locally.

`test_pkzip_stream.py` creates members larger than 320 KiB and checks both compression methods,
the standalone extractor, data descriptors, wrong passwords, incorrect CRCs, damaged data, UTF-8
paths and truncated sources. Its default member size is 1 MiB. Use `--size-mib` for a larger
reproduction and `--backend-arg` for device
runtime options.

## Performance

Keep using the existing modes when their input fits. Streaming trades their fixed data buffer for
host verification and source-file reads. A DEFLATE header can reject many false candidates cheaply.
Stored members provide a weaker initial filter, so their searches can be CPU- or I/O-bound. This
mode removes the 320 KiB member-size barrier, but it cannot promise the same rate for every ZIP.

For DEFLATE, `--hook-threads 1` can reduce dispatch overhead when most candidates are rejected by
the GPU or after a short inflate attempt. Stored members may benefit from multiple workers because
each surviving header needs full-file verification. Select the count with the actual target workload.

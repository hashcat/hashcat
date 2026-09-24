# Encrypted plains

Normally, hashcat writes recovered passwords in clear text to the outfile, potfile and screen. Anyone operating the cracking job can therefore read them, which is usually acceptable when working with your own hashes.

That trust model may be unsuitable when cracking a hash for someone else. A lost cryptocurrency wallet is a typical example: recovering its seed phrase can take days, and the result directly controls the funds.

Option `--encrypt-with-pubkey` protects the recovered password. The customer creates a key pair and sends only the public key to the operator. hashcat encrypts each recovered password before writing it anywhere. The operator can run and monitor the job, then return the result, but only the customer can decrypt it.

## Example: cracking a hash for someone else

A complete job has two roles: the __customer__, who owns the hash and needs the password, and the __operator__, who provides the cracking hardware.

### Step 1: The customer creates a key pair

This happens on the customer's machine, not yours:

```
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out private.pem
$ openssl rsa -in private.pem -pubout -out public.pem
writing RSA key
```

The customer keeps `private.pem` and never sends it anywhere. They send you `public.pem` together with the hash. The public key is not secret. It can encrypt a result but cannot decrypt one.

Use a 4096-bit key. hashcat needs at least 3344 bits for its largest possible payload and recommends the common 4096-bit size. The error message reports the required minimum if the key is too small.

### Step 2: The operator cracks the hash

You received two things from the customer: `public.pem` and the hash itself. Put the hash in a file. This one is taken from hashcat's own `example0.hash`, so you can follow along:

```
$ echo e11c594e6a2f4eb499cceadfca988595 > one.hash
```

Now run hashcat as usual, and add `--encrypt-with-pubkey`:

```
$ ./hashcat -m 0 -a 0 one.hash example.dict --encrypt-with-pubkey=public.pem -o cracked.txt
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: e11c594e6a2f4eb499cceadfca988595
Speed.#02........: 29437.6 kH/s (0.25ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: [Protected]
Rejected.........: [Protected]
Restore.Point....: [Protected]
Restore.Sub.#02..: [Protected]
Candidates.#02...: [Protected]
```

The status confirms that the hash was cracked without revealing the password or the exact position reached.

Candidate previews are hidden because the correct password would otherwise appear in the display as hashcat traverses the keyspace.

The position is hidden because the exact offset from a long-running job provides a useful restart point. An operator could rerun the attack without encryption and skip directly to the relevant part of the keyspace. For the same reason, a protected run writes __no restore file__.

Speed and estimated time remain visible. The operator can already approximate progress from the elapsed time and speed, while the exact offset is more valuable to an unprotected restart. Retaining the ETA also makes a multi-day job practical to supervise.

The outfile has the answer in it, but not in a form you can read:

```
$ cat cracked.txt
e11c594e6a2f4eb499cceadfca988595:$HCENC$1$b2d4b762819616ef$MLiE2GGndyxO2kiRQE8U7kXkFpQdYCTatVcWavoKsxu/gwFa5wYVEHkhUNse/gOX/3qU5bMnpTsZOAMB/f0og...
```

Send that file back to the customer.

### Step 3: The customer decrypts the result

On the customer's machine, use `private.pem` to decrypt the result. First remove the marker and decode the Base64 data:

```
$ cut -d: -f2 cracked.txt | sed 's/^\$HCENC\$1\$[0-9a-f]*\$//' | base64 -d > cracked.bin
```

Then decrypt it:

```
$ openssl pkeyutl -decrypt -inkey private.pem -in cracked.bin \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256
v1
449f17fa8d64e83a2941b17376816f4fe9a2cd523e5420c19d678b96637c438c
1786365128
13LEXON
```

The recovered password is `13LEXON`. The customer needs only OpenSSL to decrypt the result, not hashcat or any tool supplied by the operator.

## What those four lines mean

You get four lines back, not just the password:

```
v1                    <- format version
449f17fa8d64e8...     <- SHA-256 of the hash line this password belongs to
1786365128            <- when the cracking run started (Unix time)
13LEXON               <- the password
```

The password begins on line 4 and is copied byte for byte, so it can contain spaces, newlines or any other value. Extract everything from line 4 onward:

```
$ ... | tail -n +4
13LEXON
```

Line 2 is worth checking before you act on a result:

```
$ echo -n "e11c594e6a2f4eb499cceadfca988595" | sha256sum
449f17fa8d64e83a2941b17376816f4fe9a2cd523e5420c19d678b96637c438c
```

A matching digest confirms that the password was recovered for this hash. Discard the result if the digest differs. Encryption hides the password but does not authenticate the ciphertext because the operator can encrypt arbitrary data with the public key. The digest detects a result associated with the wrong hash, while line 3 indicates whether the result is current.

## The output format

```
$HCENC$1$<keyid>$<base64 ciphertext>
```

Marker `$HCENC$` prevents an encrypted entry from being mistaken for a password. Field `keyid` is a short fingerprint of the public key, so one potfile can hold results for several different customers and each knows which lines are theirs.

Encryption is RSA with OAEP padding, using SHA-256 for both the OAEP and the MGF1 digest.

## Things to know

__The potfile is also encrypted.__ Potfiles persist and would otherwise retain the recovered password in clear text, so `--show` and `--left` return encrypted entries.

This has two consequences. A potfile shared by normal and protected runs contains both kinds of entry, which can be separated with `--potfile-path` and distinguished by the `$HCENC$` marker. In addition, randomized encryption produces a different ciphertext each time the same password is recovered, so the potfile cannot deduplicate those results.

__No restore file is written.__ A restore file records the exact position that the protected run must conceal. Option `--encrypt-with-pubkey` disables restore automatically, and `--restore-file-path` cannot re-enable it. A stopped protected run must therefore restart from the beginning.

__Every status format hides the position.__ Options `--status-json` and `--machine-readable` report the protected fields as zero, preventing a monitoring script from recovering information omitted from the screen. The keyspace total remains visible because the operator supplied the candidate source and already knows its size.

__Some options are refused.__ These would write a password, its source word, or the position somewhere in the clear, so hashcat stops instead of half-protecting you:

| Option | Reason |
| --- | --- |
| `--loopback` | The loopback file would get encrypted plains and feed them back as candidates |
| `--debug-file` | Records the originating word in the clear |
| `--debug-mode` | Records the originating word in the clear |
| `--restore` | A protected run writes no restore file, so no restore state is available |

__The key must be RSA and large enough for every payload.__ Elliptic-curve and Ed25519 keys are rejected. hashcat checks the key size at startup before beginning the attack. With the current 256-byte password limit and 96-byte binding header, RSA-OAEP with SHA-256 requires at least 3344 bits, and a 4096-bit key is recommended.

A 2048-bit key can carry only 190 bytes after OAEP overhead. hashcat rejects it rather than risk reaching a password that cannot be encrypted. If encryption fails during a run, hashcat aborts instead of writing the password in clear text.

__OpenSSL 3 is required at runtime.__ hashcat loads it only when this option is used and does not link against it. A machine without OpenSSL can therefore run hashcat normally and reports the missing library only when encryption is requested.

__This option does not protect against a malicious operator.__ It prevents the protected run from writing or displaying the password, but an operator who controls the machine can rerun hashcat without the option or inspect process memory. Its benefit is that the protected run itself produces no usable password, so obtaining one requires a deliberate additional action. Where that distinction matters, combine it with an operational control such as responding to the result before a second run can finish.

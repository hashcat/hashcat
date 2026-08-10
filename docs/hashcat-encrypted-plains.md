# Encrypted plains

Normally hashcat writes a recovered password in the clear - to the outfile, to the potfile, and to your screen. That means whoever runs the job can read it. Usually that's fine, because you are cracking your own hashes.

Sometimes it isn't. If a customer sends you a hash and you crack it on your hardware, the password is worth taking, and they have to trust you not to. The classic case is a lost wallet: the seed phrase takes days to crack, and it is money.

`--encrypt-with-pubkey` fixes that. The customer creates a key pair and sends you only the public half. Hashcat encrypts every password it recovers with that public key before writing it anywhere. You can run the job, see that it finished, and send the result back - but you cannot read it. Only the customer can.

## Example: cracking a hash for someone else

Let's walk through a complete job. There are two people here: the __customer__, who owns the hash and wants the password, and the __operator__, who owns the GPUs and does the cracking.

### Step 1: The customer creates a key pair

This happens on the customer's machine, not yours:

```
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out private.pem
$ openssl rsa -in private.pem -pubout -out public.pem
writing RSA key
```

The customer keeps `private.pem` and never sends it anywhere. They send you `public.pem` together with the hash. The public key is not a secret - it can only lock, not unlock.

Use 4096 bits. Hashcat rejects anything smaller, and the error message explains why.

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

You can see it cracked. You cannot see what it cracked, or how far it got.

Candidates are hidden because as hashcat walks the keyspace the right candidate would appear in that display like any other. The position is hidden for a different reason: on a job that runs for days, the exact offset is a ready made starting point. Someone could restart without encryption and jump straight to the part of the keyspace that matters, instead of repeating the whole search. For the same reason a protected run writes __no restore file__.

Speed and estimated time are still shown. Whoever started the run knows how long it has been going, so they can already approximate the position from the speed - only the exact offset is worth withholding, and losing the ETA would make a multi-day job impossible to supervise.

The outfile has the answer in it, but not in a form you can read:

```
$ cat cracked.txt
e11c594e6a2f4eb499cceadfca988595:$HCENC$1$b2d4b762819616ef$MLiE2GGndyxO2kiRQE8U7kXkFpQdYCTatVcWavoKsxu/gwFa5wYVEHkhUNse/gOX/3qU5bMnpTsZOAMB/f0og...
```

Send that file back to the customer.

### Step 3: The customer decrypts the result

Back on the customer's machine, with `private.pem`. First strip the marker and decode the base64:

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

There's the password: `13LEXON`. Note that everything here is plain OpenSSL - the customer does not need hashcat, or any tool you gave them, to read their own result.

## What those four lines mean

You get four lines back, not just the password:

```
v1                    <- format version
449f17fa8d64e8...     <- SHA-256 of the hash line this password belongs to
1786365128            <- when the cracking run started (unix time)
13LEXON               <- the password
```

The password comes last and is copied byte for byte, so it can contain anything - spaces, newlines, whatever. Take everything from line 4 onward:

```
$ ... | tail -n +4
13LEXON
```

Line 2 is worth checking before you act on a result:

```
$ echo -n "e11c594e6a2f4eb499cceadfca988595" | sha256sum
449f17fa8d64e83a2941b17376816f4fe9a2cd523e5420c19d678b96637c438c
```

It matches, so this password really was recovered for this hash. If it doesn't match, throw the result away. Encryption hides the password, but it does not prove who made the ciphertext - the operator holds the public key, so they can encrypt anything to it. This line is what catches a result moved onto the wrong hash, or an old result sent again. Line 3 tells you whether it is fresh.

## The output format

```
$HCENC$1$<keyid>$<base64 ciphertext>
```

The `$HCENC$` marker means an encrypted entry can never be mistaken for a password. `keyid` is a short fingerprint of the public key, so one potfile can hold results for several different customers and each knows which lines are theirs.

Encryption is RSA with OAEP padding, using SHA-256 for both the OAEP and the MGF1 digest.

## Things to know

__The potfile is encrypted too.__ That's the point - the potfile lives a long time and would otherwise be the one place the password survives in the clear. So `--show` and `--left` return encrypted entries. Two side effects: if you use the same potfile for normal and protected runs it will hold a mix of both (the `$HCENC$` marker tells them apart, and `--potfile-path` keeps them separate), and because encryption is randomised, cracking the same hash twice gives two different ciphertexts that the potfile cannot deduplicate.

__No restore file is written.__ The restore file exists to record how far the run got, which is exactly what a protected run must not leave behind. Setting `--encrypt-with-pubkey` turns it off the same way `--restore-disable` does, so you do not need to pass that yourself, and `--restore-file-path` will not bring it back. The trade is that a protected run cannot be resumed - if you stop it, it starts over.

__The position is hidden in every status output.__ `--status-json` and `--machine-readable` report the same fields as zero, so a monitoring script cannot be used to read out what the screen refuses to show. The keyspace total is still reported - whoever runs the job supplied the wordlist, so it is not news to them.

__Some options are refused.__ These would write a password, its source word, or the position somewhere in the clear, so hashcat stops instead of half-protecting you:

| Option | Reason |
| --- | --- |
| `--loopback` | The loopback file would get encrypted plains and feed them back as candidates |
| `--debug-file` | Records the originating word in the clear |
| `--debug-mode` | Records the originating word in the clear |
| `--restore` | A protected run writes no restore file, so there is nothing to resume from |

__The key must be RSA and at least 4096 bits.__ Elliptic curve and Ed25519 keys are rejected. The size is checked once at startup, before any cracking. A 2048-bit key can only hold 190 bytes, and a 24-word BIP39 seed phrase can reach 215 - a seed phrase cut short is worth nothing, so hashcat refuses the key rather than risk it. If encryption fails during a run for any reason, hashcat aborts instead of falling back to writing the password in the clear.

__You need OpenSSL 3 at runtime.__ Hashcat loads it only when you use this option, and is not linked against it, so a machine without OpenSSL runs hashcat normally and only complains if you ask for encryption.

__This is not magic.__ It stops the password from landing on disk or on screen. It does not stop an operator who controls the machine - they can simply run hashcat again without the option, or read the process memory. What it buys you is that the protected run produces nothing usable, so getting the password takes a deliberate second run. If that matters, pair it with something outside hashcat: being reachable to act on the result the moment it arrives, so a second run would come too late.

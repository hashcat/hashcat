# Token Mask Attack (-a 13)

The token mask attack is a mask attack whose custom charsets are sets of *strings* rather than
sets of *bytes*. A built-in charset such as `?l` is still the 26 lowercase letters, one byte each,
but a custom charset `?1` through `?8` is a file whose lines are its tokens. So `?1?1` over a file
holding the single line `test` spells the candidate `testtest`.

This is what lets one mask position carry a multibyte character, a whole word, a syllable, or any
other string a byte charset cannot hold. It reaches foreign-language characters and other arbitrary
constructions that a normal mask cannot.

## Basic usage

```
./hashcat -a 13 -m 0 hashes.txt ?1?1 -1 tokens.txt
```

The mask uses the same syntax as a normal mask: `?l ?u ?d ?s ?a ?b ?h ?H` are the built-ins, `?1`
through `?8` are the custom charsets, `??` is a literal question mark, and every other byte is a
literal. The custom charsets are given with `-1` through `-8` exactly as a brute-force attack gives
them, or with the feed's own `c1=` through `c8=` settings.

`-a 13` is a front-end alias. It runs the `tokenmask` feed under the generic attack mode, so the two
commands below are the same attack:

```
./hashcat -a 13 -m 0 hashes.txt ?1?1 -1 tokens.txt
./hashcat -a 8  -m 0 hashes.txt tokenmask ?1?1 -1 tokens.txt
```

## --increment

`--increment` runs a mask at every length rather than only its own, where a length is a number of
token POSITIONS, not a number of bytes, because a token mask's positions are not one byte each. So
`?1?1?1` under `--increment` runs `?1`, then `?1?1`, then `?1?1?1`. `--increment-min` and
`--increment-max` bound the position count:

```
./hashcat -a 13 -m 0 hashes.txt ?1?1?1?1 -1 tokens.txt --increment --increment-min 2 --increment-max 3
```

One mask per run. Running several masks together, and mask files, are not supported; give one mask on
the command line.

## --debug-mode

With `--debug-mode` and no rules, the feed writes how it made each cracked candidate: its tokens,
separated by a space so their boundaries show. For example a crack of `testab` from `?1?1` writes
`test ab`. With rules, `--debug-mode` writes the rule as usual.

## Custom charsets

A custom charset value is read as a file when a file of that name exists, and its lines are the
tokens. A blank line is not a token. Otherwise the value is an inline charset read the same way a
normal mask reads one: `?l` through `?H` and `?1` through `?8` expand, `??` is a literal question
mark, and every other run is bytes. A `?N` inside an inline charset pulls in that charset's tokens,
so an inline set can name a file's multibyte tokens as well as its own bytes.

```
-1 words.txt           a file: every line is one token
-1 ?d?s                inline: the digits and the symbols, one byte each
-1 abc                 inline: the three bytes a, b and c
```

## Prebuilt token sets

The `tokensets/` folder ships ready-made token files. Each line is one token as its UTF-8 bytes, so a
file is used as a custom charset directly. Each file holds a language or script's characters that are
not plain ASCII, the multibyte ones:

- `emoji.tokenset` - every fully-qualified emoji.
- `cyrillic.tokenset`, `greek.tokenset`, `hebrew.tokenset`, `arabic.tokenset` - those alphabets.
- `hiragana.tokenset`, `katakana.tokenset` - the Japanese kana.
- `french.tokenset`, `german.tokenset`, `spanish.tokenset`, `portuguese.tokenset`, `italian.tokenset`,
  `polish.tokenset`, `czech.tokenset`, `turkish.tokenset`, `swedish.tokenset`, `danish-norwegian.tokenset`,
  `icelandic.tokenset`, `romanian.tokenset`, `hungarian.tokenset` - the accented letters each language
  adds beyond A-Z.

A script file is used on its own:

```
./hashcat -a 13 -m 0 hashes.txt ?1?1?1 -1 tokensets/cyrillic.tokenset
```

A Latin language file holds only the accented letters, so for its full alphabet add them to `?l` and
`?u` in a custom charset of its own and use that:

```
./hashcat -a 13 -m 0 hashes.txt ?2?2?2?2 -1 tokensets/french.tokenset -2 ?l?u?1
```

A token set whose tokens could contain a newline, a carriage return or a null byte stores them in
hexadecimal instead, and the run adds `--hex-charset`. The shipped sets do not need it: a multibyte
UTF-8 character never contains those bytes.

## Settings

A setting is written `key=value` among the arguments. Settings are part of the attack: they are
recorded in the restore file and hashed into the brain, so two runs that differ only in a setting are
two attacks.

| Setting | Default | Meaning |
|---|---|---|
| `pw-min` | the hash mode's own minimum | shortest candidate to keep |
| `pw-max` | the hash mode's own maximum | longest candidate to keep |
| `c1` .. `c8` | the `-1` .. `-8` option | token charset for `?1` .. `?8`, a file or an inline set |

## Candidate length

Unlike a normal mask, a token mask candidate is not a fixed length: two tokens of one position can
differ in length. A candidate whose length falls outside the hash mode's `pw_min` and `pw_max` is
skipped, so the mask's position in the keyspace stays the same on every run and `--skip`, `--limit`
and `--restore` keep working.

A single token is at most as long as a candidate may be (256 bytes). Several tokens in a row can add
up past that, and a mask whose shortest possible candidate is already longer than a candidate may be
is refused when it is read, rather than silently skipping every candidate it makes.

## --hex-charset

With `--hex-charset`, a token is given in hexadecimal, two hex digits to a byte, the same format the
option has everywhere else. A file line is one hex string and decodes to one token, which is how a
token can carry a byte a line cannot, a newline or a null among them. An inline charset's literal
bytes are read as hex pairs the same way.

```
./hashcat -a 13 -m 0 hashes.txt ?1 -1 hextokens.txt --hex-charset
```

## Rules

Rules apply to the candidates a token mask makes, the same as they do to a wordlist:

```
./hashcat -a 13 -m 0 hashes.txt ?1?1 -1 tokens.txt -r rules/best64.rule
```

## Performance

On a fast hash the feed amplifies on the card through the PCFG device engine, the same infrastructure
the PCFG and table attacks use, so no candidate crosses the PCIe bus and the card is not starved. The
mask's trailing positions are walked in the kernel and only the leading ones are produced on the host,
which runs within a small factor of a brute-force mask of the same size, orders of magnitude faster
than generating every candidate on the host.

The device engine is used only where it can be: a slow hash, `--stdout`, `--slow-candidates` and a hash
mode with no device-engine kernel all run on the host engine instead, and so does a mask whose
candidates are longer than the device's candidate buffer (around 127 bytes) or could be shorter than
the hash mode's minimum. The startup line says which engine the run got.

## Notes

- Candidate order is a plain odometer: the rightmost position runs fastest, each position a digit
  over its own token count, exactly as a byte mask counts. Candidate number N is a function of N, so
  a seek is exact and a restore is reliable.
- The keyspace is the product of the per-position token counts, counted in 128 bits, so a mask over
  several large token files is counted exactly.
- A charset is read once and shared by every position that names it.

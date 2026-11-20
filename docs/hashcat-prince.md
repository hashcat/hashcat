# PRINCE attacks in hashcat

This document explains how to run PRINCE attacks in hashcat and how the feed relates to the original princeprocessor (`pp`). PRINCE combines several words from one wordlist into one candidate: `sun` and `flower` become `sunflower`, and `my`, `cat` and `2019` become `mycat2019`. Where a rule attack decorates one word, PRINCE chains words, which is what makes long passphrases reachable.

## 1. Running it

PRINCE is feed `prince` of the generic attack mode:

```
$ ./hashcat -m 0 hashes.txt -a 8 prince wordlist.txt
```

The feed generates the candidates on the device itself; there is no pipe and no intermediate storage. Interrupt and resume work as for any other attack, and so do `--skip`, `--limit`, `--total-candidates` and distributed runs.

A quick look at the stream without a hash list:

```
$ ./hashcat --stdout -a 8 prince wordlist.txt
```

## 2. Options

The feed takes the wordlist as its one positional argument, then key=value pairs:

| option | default | meaning |
|---|---|---|
| `pw-min` | 1 | shortest candidate |
| `pw-max` | 16 | longest candidate, as in pp |
| `elem-cnt-min` | 1 | fewest elements (words) per chain |
| `elem-cnt-max` | min(pw-max, 8) | most elements per chain; see section 4 |
| `wl-max` | 10000000 | most words to read from the wordlist, 0 for all |
| `wl-dist-len` | off | take the per-length round quotas from the wordlist, as pp's --wl-dist-len does |
| `kbits` | 20 | inner loop width as a power of two |

Example, passphrases of three or four words totaling 12 to 24 characters:

```
$ ./hashcat -m 0 hashes.txt -a 8 prince wordlist.txt pw-min=12 pw-max=24 elem-cnt-min=3 elem-cnt-max=4
```

## 3. Candidate order

The feed reproduces princeprocessor's order exactly, including its round schedule: pp does not emit one password length as a single block but cuts every length's stream into per-round quota slices and interleaves the lengths. A run that pp would print, this feed prints in the same order, so a stop and resume lands on the same candidate either way.

Duplicate words in the wordlist are dropped while loading, as pp does. A candidate that two different chains can build is emitted twice, also as pp does.

## 4. What differs from pp

**Chains longer than eight elements.** The device engine has eight slots per cell, so chains past eight elements are skipped. With stock options this never happens, because the default `elem-cnt-max` is min(pw-max, 8). It comes up only when `elem-cnt-max` is raised by hand, and the feed says what it skipped:

```
$ ./hashcat --stdout -a 8 prince dict.txt elem-cnt-max=12
prince: 3 words kept, 0 duplicates dropped
prince: 3168 chains have more than 8 elements and were skipped, 568688 candidates left out
```

**Lengths with a quota of zero.** pp's round schedule assigns every password length a share of each round. With `wl-dist-len=1` a length whose words are absent from the wordlist gets a quota of zero, and pp would never finish such a length. The feed runs those lengths once, after the round schedule ends, so their candidates are not lost.

**Two engines.** The run goes to the device engine unless one of these forces the host engine: `--stdout`, a rules pass, `--slow-candidates`, a slow hash-mode, or a pool too large for the weakest device. The feed prints which one took the run. The candidate set and order are the same on both. What differs is what positions count:

- On the device engine, one position is one unit (a base word plus its cell), so `--keyspace`, `--skip`, `--limit` and the restore point count units. The progress line counts candidates on either engine, and `--total-candidates` reports the exact candidate count either way.
- On the host engine, one position is one candidate, and `--keyspace` and `--skip` count and land on candidates exactly, `--skip` matching pp's own `--skip`.

**Keyspaces past 2^128.** The totals are counted in 128 bits. A combination that overflows even that (for example a wide length window over a large wordlist) is reported as unknown rather than miscounted, and the startup line says so.

## 5. pp options without a counterpart

- `--case-permute`: not implemented. Words are loaded as they are; the counterpart is a prepared wordlist.
- `--dupe-check-disable`: not implemented; duplicate words are always dropped, matching pp's default.
- `--save-pos-disable`: no counterpart needed; position saving is part of hashcat's own session handling.
- `--output-file`: use hashcat's `-o`.
- `--keyspace`: use `--total-candidates`.

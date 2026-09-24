# PCFG attacks in hashcat

This document introduces PCFG attacks to users who have not worked with one before. It explains what a PCFG is, how to run one in hashcat, and how hashcat's version differs from the original. It does not cover training a ruleset. Training is performed by a separate tool. The examples assume that a trained ruleset directory is already available.

## 1. The idea

Real passwords have recognizable structures. Instead of selecting random characters, people often choose a word and decorate it. `monkey12`, `nicole2010`, `soccer!` and `Daniel99` are all the same idea with different parts filled in.

A PCFG, or Probabilistic Context-Free Grammar, represents those structures explicitly. It splits a password into two questions:

1. **What shape is it?** `monkey12` is a six letter word followed by two digits.
2. **Which word and which digits?** The word is `monkey` and the digits are `12`.

A trained ruleset answers both questions with probabilities. It has learned that "six letters then two digits" is a common shape, that `monkey` is a common six letter word, and that `12` is a common pair of digits.

Multiplying the three values gives the probability of `monkey12`. Repeating that calculation for every shape and set of terminals produces password guesses ordered by probability. This ordering is the primary benefit. A wordlist does not express which line is most promising, while a PCFG does.

## 2. What a ruleset looks like

A ruleset is a directory of plain text files. Each line is a value, a tab, and a probability.

```
$ ls ruleset
Alpha  Capitalization  Context  Digits  Grammar  Keyboard  Omen  Other  Years
```

File `Grammar/grammar.txt` holds the shapes in descending probability order:

```
M       0.40004227816694393
D6      0.051105353916786035
A6D2    0.037839499289255306
A6      0.037156138225371546
A7      0.025911933402529241
A8      0.024715511666296652
```

Token `D6` means six digits, `A6` means six alphabetic characters and `A6D2` means six letters followed by two digits, the structure of `monkey12`. Token `M` represents the other half of the model, a Markov chain rather than a grammar structure, and is covered in section 7.4. The letters identify the corresponding directory:

| letter | directory | what it holds |
|---|---|---|
| `A` | `Alpha` | words, lowercased |
| `C` | `Capitalization` | which letters of the preceding word are uppercase |
| `D` | `Digits` | runs of digits |
| `O` | `Other` | runs of symbols |
| `K` | `Keyboard` | keyboard walks like `qwerty` or `1qaz2wsx` |
| `X` | `Context` | things that do not fit the others |
| `Y` | `Years` | four digit years |

The number after the letter is a length, and it is also the file name. So `A6` means `Alpha/6.txt`:

```
$ head -4 ruleset/Alpha/6.txt
qwerty  0.0067210802045213538
dragon  0.0032347148775242426
daniel  0.0030595661646911267
master  0.0028884438590495768
```

and `D2` means `Digits/2.txt`:

```
$ head -4 ruleset/Digits/2.txt
12      0.081662990094803337
11      0.047789012263745823
13      0.035510563532023691
10      0.033652927222128988
```

Capitalization requires separate explanation because it is represented indirectly. Words in `Alpha` are always stored lowercase. Every `A` token carries a hidden `C` token of the same length that specifies which letters to uppercase afterward:

```
$ head -4 ruleset/Capitalization/6.txt
LLLLLL  0.86537548300305567
ULLLLL  0.10933250192575741
UUUUUU  0.0099566830879285681
LLLLLU  0.0013423768152759595
```

Mask `LLLLLL` leaves a six-letter word lowercase and is the most common case. Mask `ULLLLL` capitalizes its first letter. This is why `monkey` and `Monkey` are one entry in `Alpha/6.txt` and not two: the ruleset stores the word once and the shape decides the case.

So `monkey12` is `A6` + `C6` + `D2`, and its probability is:

```
P(A6D2) x P("monkey") x P("LLLLLL") x P("12")
```

The result is `0.0378 x 0.00263 x 0.865 x 0.0817`, or approximately one in 142,000. Every candidate receives such a value, and the attack enumerates them from highest to lowest probability.

hashcat reads the directories in the table above, along with `Grammar` and, for the `M` structure, `Omen`. A ruleset from the trainer also has `Prince`, `Masks`, `Emails` and `Websites` directories and a `config.ini`. hashcat ignores those, so you can delete them if you want the ruleset smaller.

A ruleset does not have to be a directory. The whole of it in one `.tar.xz` works wherever a ruleset is named, and a ruleset trained on `example.dict` is 3.2 MB as a directory and 275 KB as one file:

```
tar cf - -C /path/to/ruleset . | xz -9 > ruleset.tar.xz

./hashcat -m 0 -a 4 example0.hash ruleset.tar.xz
```

hashcat strips a leading `./` or one common top-level directory from every member, so either archive layout works.

Single files may be compressed instead, with `.xz` appended: hashcat looks for `Alpha/8.txt` and then for `Alpha/8.txt.xz`. Compress the whole ruleset, part of it, or none of it, and the run is the same run either way.

```
find /path/to/ruleset -type f -exec xz -9 {} +
```

## 3. Running it

PCFG uses attack mode 4 and can run with only a hash file:

```
./hashcat -m 0 -a 4 example0.hash
```

That runs the ruleset hashcat ships as its default, which is trained on passwords.

To use your own instead, name it after the hash file:

```
./hashcat -m 0 -a 4 example0.hash /path/to/ruleset
```

Name several rulesets to merge them with equal shares by default. Combining rulesets trained on different data can produce candidates that none can reach alone, as described in section 6. Setting `weights=` controls the share assigned to each ruleset.

An installed ruleset, whether bundled or user-provided, can be selected by name just as `-m 0` selects a hash mode and `-a 8 wordlist` selects a feed:

```
./hashcat -m 0 -a 4 example0.hash example
```

hashcat searches two locations for a named ruleset, checking the user location first:

```
<profile>/pcfg/<name>        $XDG_DATA_HOME/hashcat/pcfg, or ~/.local/share/hashcat/pcfg
<shared>/pcfg/<name>         where make install puts what hashcat ships
```

In each location, a directory takes precedence over a `<name>.tar.xz` archive with the same name. **Any value containing a slash is treated as a path and is not searched by name**, preserving the behavior of existing commands. An unmatched name is also tried as a path, so a ruleset directory in the working directory still works.

### 3.1. The rulesets hashcat ships

hashcat ships two rulesets. Attack mode 4 uses the first when none is specified.

| ruleset | what it is |
|---|---|
| `default-passwords` | trained on passwords, which is what a password guesser wants first |
| `hints` | the same grammar with the words taken out, for when you supply them yourself. Section 4 |

A ruleset trained on ordinary language covers words a password list does not have, and merging one with `default-passwords` reaches candidates neither reaches alone. hashcat does not ship such a ruleset, because the training text carries a licence of its own. Train one with `pcfg_cracker`, whose ruleset format the feed reads directly, using text you are permitted to obtain and process.

Name your own beside the shipped one and both run:

```
./hashcat -m 0 -a 4 example0.hash default-passwords my-russian
```

Two rulesets get an even split. Weight it toward whichever you trust more:

```
./hashcat -m 0 -a 4 example0.hash default-passwords my-russian weights=2:1
```

Internally, PCFG is an attack mode 8 feed, and `-a 4` is rewritten to that generic form before downstream code reads the command line. See `hashcat-generic-attack-mode.md` for what attack-mode 8 is in general. The longer form still works and is the same attack, so a script written before `-a 4` existed keeps running:

```
./hashcat -m 0 -a 8 example0.hash pcfg /path/to/ruleset
```

The remaining examples use the shorter attack mode 4 form.

Here is a real run against hashcat's own example hashes, stopped after twenty seconds:

```
Session..........: hashcat
Status...........: Aborted (Runtime)
Hash.Mode........: 0 (MD5)
Hash.Target......: example0.hash
Time.Started.....: Sun Aug 23 17:08:57 2026 (20 secs)
Speed.#01........: 13369.7 MH/s (12.26ms)  Accel:38 Loops:1024 Thr:64 Vec:1
Speed.#02........: 12525.9 MH/s (13.06ms)  Accel:38 Loops:1024 Thr:64 Vec:1
Speed.#*.........: 25895.6 MH/s
Recovered........: 4990/6494 (76.84%) Digests (total), 4990/6494 (76.84%) Digests (new)
Progress.........: 512430312909/34928193902017160 (0.00%)
Restore.Point....: 258375680/12747516022634 (0.00%)
Candidate.Engine.: Device Generator
Candidates.#01...: MOnTpeL55 -> NACHTEn55
```

The run recovers three quarters of the list in 20 seconds after testing approximately one candidate in every 68,000. Prioritizing that small fraction is the purpose of a PCFG.

The passwords it finds look like what the grammar describes:

```
$ ./hashcat -m 0 -a 4 example0.hash --limit 50000 --quiet --potfile-disable --outfile-format 2
grace2010
rocky2009
findus123
elephant19
Admin11
reggae123
henry2011
1123581322
2football
987654321qwerty
```

### The lines it prints when it starts

```
pcfg: 3582 structures, 134 terminal lists
pcfg: device engine, one base word becomes many candidates inside the hash kernel
pcfg: candidate bound 63 bytes, 16 word array (rectangle gain 1.00x at 32 words, taken at 1.50x)
pcfg: inner loop 27 bits, 7414 candidates to a cell at the front of the run
pcfg: device engine il=134217728, terminal pool 3417 KiB, 240901302469 base words for 1308976582820259 candidates (x5434)
```

Line by line:

* The **3582 structures, 134 terminal lists** line reports the number of known shapes and loaded value files.
* The **device engine** line identifies which implementation the hash mode selected. The remaining lines in this example describe a fast hash. A slow hash prints different details, as explained in section 7.3.
* The **candidate bound** is the longest candidate the run can produce, as derived from the ruleset. Very long entries increase this bound and impose a small performance cost.
* The **inner loop** and **candidates to a cell** values describe how many candidates the GPU generates from one base word near the beginning of the run. These values are also derived from the ruleset.
* The **base words for candidates** line shows device amplification. Here, the host produces 240 billion base words and the GPU expands them into 1.3 quadrillion candidates, averaging approximately 5,434 candidates per base word. This prevents candidate generation by one CPU core from limiting the attack.

A slow hash reports this instead:

```
pcfg: 1427 structures, 51 terminal lists
pcfg: host engine, every candidate is built here and copied over
pcfg: OMEN escape carried, 15 levels over 1 model, 40962142820 guesses, 18 MiB of tables
```

The status line repeats it, because the first lines scroll away and a session log keeps the status:

```
Guess.Base.......: Feed (/path/to/ruleset (scale 1, host, OMEN))
Guess.Base.......: Feed (/path/to/ruleset (scale 1, device))
```

Section 7.3 explains how hashcat selects between the two engines, and section 7.4 describes the escape.

## 4. Attacking one person with what you know about them

A trained ruleset answers two questions: what is the structure, and which word fills it? Sometimes you already know the word. You are cracking one person's password and you know their partner's name, the year they were born, the car they drive and the team they support. What you do not know is what they did to it.

The bundled `hints` ruleset provides the structures without supplying the words. Provide the known words and the grammar applies common surrounding patterns:

```
./hashcat -m 0 -a 4 example0.hash hints hintwords=tom,sarah,1992,bmw,bears,chicago
```

which guesses, in this order:

```
tom sarah 1992 bmw bears chicago tom123 Tom sarah123 1992123 tom1 tomsarah tom1992
sarahtom 1992tom Sarah tom12 tom11 bmw123 bears123 chicago123 sarah1 19921 tombmw
tombears tomchicago sarah1992 1992sarah bmwtom bearstom chicagotom Bmw Bears Chicago
TOM tom13 tom10 tom01 tom22 tom23 tom21 tom99 sarah12 sarah11 199212 ...
```

The attack tries each word alone, every pair in both orders, and common combinations with digits, years, symbols and capitalization. The grammar is unbounded. The order is the trained one: `tom123` comes before `tomchicago` because a word followed by three digits is a more common shape than two words joined, and no hand written rule put it there.

Candidate `tomtom` is intentionally absent. Each word is a fact about one person, and a password built on a fact holds it once, so a candidate spells each of your words at most once and a shape with two word slots joins two different words. The grammar on its own has no such opinion: it learned that a password is often two letter runs with something between them, and once every letter run is one token those shapes read `football2football5football` as readily as `tom1sarah`. Over the first 2 million candidates of the six words above, 53 per cent of them were a word against itself.

The rule is on the word rather than on the bytes, so `tomTom` goes with `tomtom`. The years and digits the grammar appends are its own and are not counted against you, so `1992` as a hint still meets `1992` as a year, which is why `19921992` survives.

There are two ways to allow repeated hints. Naming a word twice, as in `hintwords=tom,tom,sarah`, creates two list entries that can fill a two-slot structure, at the cost of duplicating `tom` wherever one slot is sufficient. Setting `hintrepeat=1` disables the restriction for every hint.

This is the attack to reach for when a targeted rule attack has failed and you have facts rather than a wordlist. It is not a wordlist attack with extra steps. A wordlist has no opinion about which line to try first, and no way to join two of its lines together. This has both, derived from the training data rather than a manually written rule.

For more words than fit on a command line, put them in a file:

```
./hashcat -m 0 -a 4 example0.hash hints hintfile=facts.txt
```

Place one word on each line. A line can include a tab followed by a probability, matching the format of ruleset terminal files and allowing a previously trained list to be used directly.

A word with no probability of its own is worth what its position implies, and `hintrank` decides what that is:

| `hintrank` | what it assumes | when to use it |
|---|---|---|
| `zipf` | the n'th word costs log2 (n) bits | the default, and right for a list in rough order of confidence |
| `linear` | each word is half as likely as the one before it | a few words you ranked carefully. Word n costs n bits, so only the first `costmax` words of a file are kept at all, 64 of them by default, and the ones in front of that reach less of the grammar the later they are |
| `flat` | all equally likely | a list in no particular order. Every word is tried on its own before any of them is decorated |

The `hints` ruleset is derived from `default-passwords` rather than trained separately. Script `tools/pcfg_hints.py` replaces every alphabetic run with one length-independent hint token, adds the probabilities of structures that collapse together and reduces capitalization to three masks that work at any length.

This process converts 23,159 structures into 5,104 shapes. The highest-ranked shapes are a word alone, a word with one to four digits, a repeated word and a word with a year. Retraining the default ruleset requires rebuilding `hints` from it.

The `hints` ruleset deliberately has no OMEN escape. In the trained grammar, structure `M` represents approximately 40 percent of the probability mass and generates complete passwords character by character from a Markov model. Those candidates contain none of the supplied hints, so retaining the escape would spend most of the run on a different problem.

Structures without an alphabetic run are removed for the same reason and account for another approximately 10 percent. Their probability mass is renormalized over the remaining shapes, making the result conditional on the password containing a supplied word. A hint ruleset therefore has no `M` entry, like a ruleset trained with `--coverage 1.0`, and section 7.4 does not apply.

What it cannot do is guess a word you did not give it. Every candidate contains one of your words, so the attack is only as good as what you know.

Attack mode 9 also uses this ruleset, taking words from the hash file rather than the command line: one set per hash, cut out of whatever that hash carries about its owner. That is the `hintaccount` setting, and `hashcat-association.md` is where it is written up. The once rule is not applied there and `hintrepeat` is refused: that attack pairs word N with salt N, so declining a candidate leaves that hash without a guess and provides no replacement for the gap.

A hint attack also generates candidates more slowly than an ordinary ruleset, for the reason explained in section 7.3. A hint word lives in hashcat's memory rather than in the ruleset, so the graphics card cannot read it and the slot has to stay on the host. What the card is left to expand is whatever comes after the hint, which on many of these shapes is no slot at all, so a run makes about two candidates per base word where the trained ruleset makes several thousand. It matters less than it sounds, because this attack is aimed at one person and the whole point is that it does not need to make quadrillions of guesses. `-r` still amplifies on the card if you want the speed back.

The status display reports a large `Rejected` value for this ruleset because the no-repeat rule discards many positions. A position whose words repeat is walked and stepped over rather than left out of the count, so it shows up there exactly as an over-length word from a wordlist does. The six words above reject about half the positions at the front of the run and about four in five a billion candidates in, and what the card is given is the rest. A shape requiring more words than were supplied produces no candidates. hashcat drops those shapes while loading the grammar and reports their count in the following line. That is most of the grammar for a run naming one word: every shape with two word slots.

## 5. Settings

Settings are `key=value` arguments after the ruleset path, the same convention every attack-mode 8 feed uses:

```
./hashcat -m 0 -a 4 example0.hash /path/to/ruleset scale=4 costmax=48
```

The defaults are suitable for most attacks.

| setting | default | what it does |
|---|---|---|
| `scale` | 1 | How finely probabilities are graded. Higher is closer to true probability order and costs memory and startup time. Unrelated to the trainer's `--coverage`. |
| `costmax` | 64 | How deep to enumerate, in bits. This is what bounds the keyspace; the grammar's real keyspace is far larger. |
| `weights` | even | The share each ruleset carries when you give more than one. See below. |
| `threads` | auto | CPU cores used to produce candidates. `0` produces them on the calling thread. The default is 16 on a fast hash and 8 on a slow one, both measured, and capped by the machine. |
| `kbits` | auto | How many candidates a base word may expand into on the card. |
| `maxword` | auto | How long a candidate the card will build, in 4 byte words. Must be a multiple of 16. |
| `maxgain` | 1.5 | How much wider the expansion has to get before the bigger candidate buffer is worth taking. |
| `walk` | 1 | Steps to the next base word where it can instead of working it out from its position. It produces exactly the same run either way, so this is only here to turn off. |
| `omen` | 1 | Carries the OMEN escape. See section 7.4. |
| `hintwords` | none | The words a hint ruleset is given, comma separated. See section 4. |
| `hintfile` | none | The same words out of a file, one per line. |
| `hintrank` | `zipf` | What a hint word with no probability of its own is worth. |
| `hintrepeat` | 0 | Let one candidate spell the same hint word twice. See section 4. |
| `hintaccount` | 0 | Words to take from each hash instead, which is what `-a 9` uses. See `hashcat-association.md`. |
| `pwmin` | from the hash-mode | Shortest candidate to produce. |
| `pwmax` | from the hash-mode | Longest candidate to produce. |

Settings `pwmin` and `pwmax` are useful when the password length is known, such as with a list grouped by length or a format that fixes it. The limits apply while counting the keyspace, so candidates outside the range are never generated.

In the bundled ruleset, 1,370 of 23,159 shapes can produce 12-character passwords and together carry 1.4 percent of the probability mass. Setting `pwmin=12 pwmax=12` for a list of 12-character passwords therefore eliminates almost all unrelated work.

Both settings can only narrow the range allowed by the hash mode. They cannot request a length unsupported by the kernel. A value of `0` leaves the corresponding hash-mode limit unchanged, while a value that would widen the range is reported and ignored.

Setting `scale` belongs to hashcat and is not read from the ruleset. The status display therefore shows `scale 1` unless another value is requested. It is unrelated to `--coverage` in the trainer, which is set when the ruleset is built and cannot be changed afterwards. If a ruleset was trained at a coverage below 1.0 and you are cracking a fast hash, section 7.4 is the part that matters.

Settings `scale`, `costmax` and `omen` change the candidate at each position and are therefore part of the attack identity. Change one and a restore point from before is no longer valid. They travel as arguments, which is what the brain hashes and what the restore file records, so hashcat notices.

## 6. Using more than one ruleset

Several ruleset directories can be supplied at once:

```
./hashcat -m 0 -a 4 example0.hash /path/to/names /path/to/rockyou
```

The rulesets become **one grammar**, not a sequence of separate attacks. Every probability in the result is the weighted average of the probabilities defined by each ruleset, for both shapes and value files.

Merging is useful when rulesets contain complementary knowledge. A ruleset trained on a list of names knows a lot of names and has almost no digits or years, because the list it learned from had none. A ruleset trained on leaked passwords has the digits and years and none of the names. On their own, neither one can produce `hüseyin1`. Merged, the shape "word then one digit" that the password ruleset learned is available over the words the name ruleset learned, and it can.

Setting `weights` sets the split, and the numbers are relative, so `weights=3:1` and `weights=75:25` are the same thing:

```
./hashcat -m 0 -a 4 example0.hash /path/to/names /path/to/rockyou weights=1:3
```

An even split is the default but may not fit the target. A ruleset unrelated to the target can consume much of the run because half the probability mass is assigned to unlikely candidates. Against hashcat's pure ASCII example hashes, a rockyou ruleset on its own recovers 2042 plaintexts in a fixed budget. Merged evenly with a non-Latin name ruleset it recovers 616, and at `weights=3:1` toward rockyou it recovers 1080.

Two things this is not, and both are worth knowing:

* It is not the same as running both attacks and interleaving the results. That would need duplicate detection across the whole stream, which is not possible without giving up `--skip` and `--restore`.
* It is not the same as training one ruleset on both source lists. A real training run weighs each value file by how many tokens went into it. This weighs everything in a ruleset by one number.

Merging a ruleset with itself gives that ruleset back exactly, which is a useful sanity check.

### 6.1. What the merge actually does

The merge runs once per file, at load time, and the same routine handles the grammar and every terminal list. The merge operation does not repeat during the run.

**Weights are normalized first.** Each value in `weights` is divided by their sum, so `weights=3:1` and `weights=75:25` both become 0.75 and 0.25. That is why the numbers are relative, and it is what makes the result a weighted average rather than a weighted sum.

**Each line probability is scaled by its ruleset share, then added.** A file contains `value <tab> probability` lines. Reading ruleset *i*'s copy of a file contributes `p * w[i]` for every line in it. There is no division anywhere afterwards: the average falls out because the shares sum to 1.

**Values are matched by byte sequence.** Entries use an open-addressed hash table keyed by FNV-1a over the value bytes, with linear probing. A value that two rulesets both know is found on the second insert and its probability is accumulated into the entry that is already there, so it ends up with both contributions and appears once.

That is the mechanism behind the `hüseyin1` example above. It is also why a value both rulesets know comes out **earlier** in the run than either ruleset alone would have put it: cost is `-log2(p) * scale`, so a larger probability is a smaller cost.

**A single ruleset bypasses deduplication.** The hash table is built only when several rulesets are supplied. One ruleset appends straight to the list and never hashes anything, so it incurs no deduplication cost. This is also why merging a ruleset with itself is a real test rather than a trivial one: it takes the other path and has to come back with the same answer.

**A missing file in one ruleset is not an error.** That ruleset contributes no entries for the file, while the available copies form the merged list. A grammar trained on names has no `Years/1.txt`, and that is exactly the case merging is for.

**The merged list is sorted by probability, descending, and ties are broken by insertion order.** Without the tiebreak two runs of the same merge could order equal-probability values differently, depending on the sort implementation, and a restore point would not land where it was taken.

**The result is not normalized again.** The weighted probability sums are converted directly into costs.

**Weights are part of the attack identity.** Two runs that differ only in `weights` describe different attacks: the same position means a different candidate. The feed folds the ruleset count and every share into the value hashcat uses to distinguish attacks, so the brain will not credit one run's work to the other and a restore point taken under one split will not resume under another. A single ruleset is deliberately left out of that, because its share is always exactly 1 and its enumeration is unchanged.

## 7. How this differs from the original PCFG

hashcat's PCFG is based on the same model as lakiw's `pcfg_cracker`, but it is not a port of it. Five things differ, and the first two are two sides of one decision.

### 7.1. The keyspace supports counting and random access

A list ordered by real-valued probabilities has no direct calculation for locating its ten-billionth entry. The only way to reach it is to produce the first 9,999,999,999. That is why a PCFG guesser is normally something you pipe into a cracker and let run, with no way to split it, stop it, or resume it.

hashcat first quantizes each probability into a whole number of cost steps. Candidates then fall into groups of equal cost, the size of each group can be worked out in advance, and "the ten billionth candidate" has an answer you can compute in microseconds. That is what gives you:

```
$ ./hashcat -m 0 -a 4 --keyspace
12747516022634
```

and `--skip`, `--limit`, `--restore`, splitting one attack across several GPUs, and the brain. All of those need a keyspace with a fixed order and a way to jump into the middle of it.

```
./hashcat -m 0 -a 4 example0.hash /path/to/ruleset --skip 1000000 --limit 200000
```

### 7.2. The price is that the ordering is approximate

Quantization places candidates with slightly different probabilities into the same cost group, where their internal order is arbitrary. The attack therefore preserves probability order only at the granularity of a group.

At the default `scale=1` that costs very little. Measured against an exact enumerator over the same number of guesses, it reaches 99.83% of the probability mass and 99.994% of the cracks. Raising `scale` narrows the groups and recovers the rest, at the cost of memory and startup time.

Increase `scale` only when measurements show that the finer ordering improves the attack.

### 7.3. On a fast hash the device engine does the guessing

`pcfg_cracker` generates candidates on the CPU and prints them. One core producing a few million guesses a second is fine for a slow hash and nowhere near enough for a fast one.

For a fast hash, hashcat sends the device a base word and a compact description of its variable terminals, which the device expands. The `x5434` in the startup lines is the multiplier: one base word from the host became 5434 candidates on the device.

**A slow hash uses the host engine.** hashcat selects the engine according to the kernel structure: a mode whose attack kernel carries the whole hash runs the device engine, and a mode with a separate iteration kernel does not. Mode 0 is the first kind and mode 3200 is the second. The startup output distinguishes them: the first reports `pcfg: device engine il=...`, while the second omits the device-engine line.

**Three fast hash modes also use the host engine.** The device engine requires a mode-specific `OpenCL/mNNNNN_a4-pure.cl` kernel, or `_a4-optimized.cl` when the mode provides only an optimized kernel. All but three included fast modes have one. The exceptions are modes whose rules kernel does something the shared engine cannot express. Mode 2000 is `STDOUT`, and all of its entry points are empty. Mode 5100 compares three times per candidate at three offsets into a half MD5, while the engine returns one set of four words. Mode 20510 has `NOT AVAILABLE` where its multi-hash entry point would be. Those modes run the host engine and report that selection at startup, as slow hashes do. The command line remains unchanged.

The host engine is not merely an error fallback. It enumerates the whole grammar, where the device engine may have had terminals cut and the escape's budget ceiling lowered to fit what a card can hold, and it takes `-j` and `-k`. A slow hash wants a few hundred thousand candidates a second, one core gives tens of millions, and everything the device engine gave up to reach billions can be given back.

Two things follow from it that are easy to trip over.

**The engines produce different attacks from the same ruleset.** They enumerate different candidate sets and report different keyspaces. Options `--skip`, `--restore` and distributed ranges are not interchangeable, and the brain keeps their coverage separate.

**The host engine uses several CPU cores.** Setting `threads` controls the count and chooses a measured default automatically. That matters only for the quickest modes on the slow side of the line, `-m 12700` and `-m 10500` among them, which run at hundreds of millions of hashes a second: on those the candidates cannot be produced fast enough by one core, and no amount of them quite keeps up either. On anything genuinely slow it makes no difference, because a PCFG attack already feeds bcrypt as fast as a mask does.

This is also why `-O` is refused where the engine has no kernel to run under it:

```
The device engine has no optimized kernel for this hash mode. Run this without -O.
```

A mode with an `_a4-optimized.cl` device kernel can take `-O`. A mode whose only device kernel is `_a4-pure.cl` cannot. If the mode has no optimized straight kernel either, hashcat drops `-O` before the PCFG engine selects its file and reports that change.

**Options `-r` and `-g` keep the device engine.** The rules are applied inside the same kernel that walks the cell. `il_pos` names the rule, exactly as it does for a word list, and the step inside the cell travels in the spare word of the crack record, which is how a crack is reported as the candidate that produced it rather than as the base word. The candidate array is widened to hold what a rule can write, which costs registers, so the kernel carrying the rule engine is a separate build of the same file and a run without `-r` receives the one it always had.

The brain treats runs with and without rules as different attacks, so they do not reuse each other's covered keyspace.

**Rules provide a second form of device amplification.** The device engine expands a cell inside the hash kernel, and the rules multiply what that cell produced, so the two compound. A base word becomes its cell, and every candidate of that cell is tried once per rule. Stacked rules retain their usual cross-product behavior, so `-r a -r b` applies every rule from one file over every rule from the other.

Measured on an RTX 5080 against `-m 0`, the shipped ruleset, twenty seconds each, with autotune left free:

```text
what is in front of the card                      candidates a second
--------------------------------------------------------------------
the cell, escape disabled with omen=0                      24.9 GH/s
the cell, escape carried                                   17.6 GH/s
the cell, and best66.rule over it, 66 rules                 6.6 GH/s
```

The rate per candidate falls because the work per candidate rises, and what the run receives in exchange is 66 candidates where it had one. Rules used to move the run to the host engine, where the same ruleset on the same card ran at 2.3 GH/s.

The `Candidate.Engine` status field identifies the active path: `Device Generator` when something is amplifying on the card, whether that is a cell, a rule set or both, and `Host Generator + PCIe` when the host is building whole candidates and paying for the copy.

`--stdout` shows you the host engine, not the device engine:

```
$ ./hashcat -a 4 --stdout --limit 5 /path/to/ruleset
```

The command prints host-generated candidates without starting a kernel, so it uses the host engine like a slow hash and includes the OMEN escape. There is no way to print what a fast hash would produce: those candidates are the card's output and never exist on the host at all.

Options `-S` and `--slow-candidates` also select the host engine for the same reason. It asks for every candidate to be built on the host, so the card runs the plain straight kernel and there is no inner loop to expand a cell in. `--brain-client` arrives here as well, because hashcat turns it into `--slow-candidates` on the way.

### 7.4. OMEN rides both engines

`pcfg_cracker` trains two models: the PCFG and a Markov model named OMEN. Its generator interleaves candidates from both. A trained grammar contains a structure called `M`, which means "anything the grammar did not cover" and is what OMEN fills in. On a ruleset trained at the default coverage that line carries about 40% of the probability mass.

**hashcat includes the OMEN escape on either engine**, from the ruleset's `Omen` directory, and reports it:

```
pcfg: OMEN escape carried, 15 levels over 1 model, 40962142820 guesses, 18 MiB of tables
```

The resulting candidate sets match the original generator. Every level was compared against `pcfg_cracker`'s own generator, on four rulesets including a Cyrillic one, and the sets are identical. The count is exact, not an estimate, so `--keyspace`, `--skip` and `--restore` mean on the OMEN half exactly what they mean on the rest of the run.

The corresponding tables consume memory and are built at startup: 18 MiB for a ruleset trained on a small corpus, 434 MiB for the largest one tried here. The line above reports the requirement before the build starts.

The device engine described in section 7.3 receives a Cartesian product: a few independent lists, and a candidate is one entry from each. An OMEN guess has a different structure, because each character it writes decides which characters may follow, so it does not factor into independent lists. That is why the fast path went without it for as long as it did, and walking the trellis inside the kernel is what replaces that.

**On a fast hash the card walks it.** The kernel walks the trellis itself, out of tables packed into the same pool it reads the terminals from, and the host walks that same order from the same source file, so a crack is reported as the guess that produced it rather than as the base word the card started from.

**Room has to be made for those tables.** The pool already holds every terminal of the grammar. hashcat cuts the terminals at the highest cost whose pool the weakest card can hold, and where that is still not enough it lowers the escape's own budget ceiling one level at a time, which gives up the dearest OMEN levels rather than all of them. Each step is reported at startup, and all of them are reversed if the run ends up on the host engine anyway, because that engine reads the lists themselves and never touches the pool.

Carrying the escape on the card costs rate. In the measurement in section 7.3 it came to 29 percent of the candidates a second, and what it buys is guesses the run did not make at all before. Setting `omen=0` disables it and returns that rate:

```
pcfg: OMEN escape dropped, omen=0. 40% of the mass, set by coverage
```

The percentage is read from the `M` line of the ruleset you gave, so it is that ruleset's figure and not a general one. A ruleset trained at `--coverage 1.0` has no `M` line and prints no such message.

Training a ruleset with `--coverage 1.0` instructs the trainer not to emit `M` at all. That used to be the advice for a ruleset meant for a fast hash, because the fast path discarded `M`. It no longer is.

The other reason to want `omen=0` is to compare like with like: with it off the two engines enumerate the same set, which is what the device engine is checked against.

### 7.5. Capitalization of non-ASCII rulesets is nearly identical, but not quite

A capitalization mask holds one letter per **character**, and a character in UTF-8 can be one to four bytes. hashcat applies the mask per character, the same as `pcfg_cracker`, and uppercases the character rather than the byte. Russian, Greek, accented Latin and the rest all get their capitals.

There is one exception, and it comes from a hard constraint. Every candidate a structure produces has to be the same length, because that is what the device engine's fixed candidate array, its padding and its cut all rest on. A handful of characters have an uppercase form that is a **different number of bytes** than the lowercase one, and those cannot be uppercased without changing the candidate's length. The commonest by far is the Turkish dotless `i` (`\u0131`), whose uppercase is the ASCII `I`. Those characters are left as they are, so `U` has no effect on those characters.

On a large name ruleset that is about 0.66% of the characters. The other 99.34% either uppercase with the length preserved or have no uppercase form at all.

Scripts with no case at all, such as Arabic and Hebrew, are unaffected: there is no case conversion to apply, and `pcfg_cracker` produces exactly the same single candidate per mask that hashcat does. If your ruleset is mostly such a script, its `Capitalization` lists provide no useful transformations and every mask beyond the all-lowercase one is a duplicate. That is a property of the trained ruleset rather than of hashcat.

### 7.6. Several rulesets can be merged

Section 6 covers multiple rulesets, and section 6.1 explains the merge. Tool `pcfg_cracker` takes one ruleset.

## 8. Seeing which terminals fired

Option `--debug-mode` normally reports the rule responsible for a crack, but a grammar selects one terminal for each structure slot rather than applying rules. For a feed-based attack, hashcat fills that field with information from the feed, so every debug mode works without `-r`. With `-r` there is a rule to report as well, and then modes 1, 3, 4 and 5 name the rule as they do for a word list while mode 6 names the terminals either way. Mode 6 uses the format below, with the same three fields as mode 4:

```
$ hashcat -m 0 -a 4 hashes.txt --debug-mode 6 --debug-file fired.txt
$ cat fired.txt
password1:password/LLLLLLLL,1:password1
a1234567:a/L,1234567:a1234567
```

The three fields are the base word, the terminals selected by the device and the resulting candidate. A capitalization mask writes over the token in front of it rather than adding one of its own, so it is joined to that token with a slash.

Only the slots the card expanded are named. The ones in front of them are already assembled into the base word, which is printed beside them.

## 9. Common points of confusion

* **Option `--stdout` shows the host engine.** It never starts a kernel, so it gets the host generator, escape and all. Fast-path candidates exist only on the device and are therefore unavailable to `--stdout`.
* **`-O` is refused rather than ignored** on a fast hash whose only PCFG device kernel is the pure one. Modes that ship an `_a4-optimized.cl` kernel take it.
* **Options `-i` and `--increment`, along with custom character sets `-1` through `-4`, are rejected.** Both belong to a mask, and `-a 4` takes a ruleset rather than a mask. What decides the lengths here is the grammar and `costmax`.

* **Options `-S`, `--slow-candidates` and `--brain-client` select the host engine** as well, and the startup line reports the selected engine. Both ask for every candidate to be built on the host, which is the one thing the device engine does not do.
* **Options `-r` and `-g` keep the device engine.** The rules run in the same kernel that walks the cell, so a base word is worth its cell once per rule. The line after the ruleset summary reports the selected engine.
* **Options `-j` and `-k` are rejected** while the device engine builds the candidates. Each names a rule for one side of a candidate, and a candidate assembled from the grammar's terminals has no sides. Option `-r` is the one that reaches every candidate. Both still apply wherever the host engine builds the candidates, which is any slow hash, `--stdout` and `--slow-candidates`.
* **The same ruleset against `-m 0` and against `-m 3200` is not the same attack.** Different candidates, a different keyspace and a different number in `--keyspace`. Section 7.3 explains the difference. Both are correct. Neither one's restore point or brain session carries over to the other, and hashcat knows that and will not let them.
* **The keyspace is not the grammar's keyspace.** It is however much of it `costmax` reaches. The real keyspace of a trained grammar is astronomically larger and there is no point enumerating all of it.
* **Progress is counted in candidates and the restore point in base words.** In the status output above, `Progress` is 76 billion of 1.3 quadrillion candidates while `Restore.Point` is 14 million base words. Both are correct and they are counting different things.
* **Startup takes a few seconds** on a large ruleset, and longer when you merge several, because every value file is read and indexed. It happens once.
* **Changing `scale`, `costmax`, `weights` or the ruleset invalidates a restore point.** All of them change which candidate sits at which position. hashcat detects the change and will not silently resume into the wrong place.

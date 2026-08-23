# PCFG attacks in hashcat

This document is for someone who has never used a PCFG before. It explains what a PCFG is, how to run
one in hashcat, and how hashcat's version differs from the original. It does not cover training a
ruleset. Training is a separate job done by a separate tool, and everything here assumes somebody has
already handed you a trained ruleset directory.

## 1. The idea

Real passwords have a shape. People do not pick random characters, they pick a word and then decorate
it. `monkey12`, `nicole2010`, `soccer!` and `Daniel99` are all the same idea with different parts
filled in.

A PCFG, which stands for Probabilistic Context Free Grammar, is a way of writing that down. It splits
a password into two questions:

1. **What shape is it?** `monkey12` is a six letter word followed by two digits.
2. **Which word and which digits?** The word is `monkey` and the digits are `12`.

A trained ruleset answers both questions with probabilities. It has learned that "six letters then two
digits" is a common shape, that `monkey` is a common six letter word, and that `12` is a common pair
of digits.

Multiply the three together and you get the probability of `monkey12`. Do that for every shape and
every filling, sort by the result, and you have a list of password guesses in order of how likely they
are. That ordering is the whole point. A wordlist has no opinion about which line is worth trying
first. A PCFG does.

## 2. What a ruleset looks like

A ruleset is a directory of plain text files. Each line is a value, a tab, and a probability.

```
$ ls ruleset
Alpha  Capitalization  Context  Digits  Grammar  Keyboard  Omen  Other  Years
```

`Grammar/grammar.txt` holds the shapes, most likely first:

```
M       0.40004227816694393
D6      0.051105353916786035
A6D2    0.037839499289255306
A6      0.037156138225371546
A7      0.025911933402529241
A8      0.024715511666296652
```

`D6` is "six digits". `A6` is "six alphabetic characters". `A6D2` is "six letters then two digits",
and it is the shape `monkey12` has. `M` is the other half of the model, a Markov chain rather than a
grammar shape, and it has section 6.4 to itself. The letters tell you which directory to look in:

| letter | directory | what it holds |
|---|---|---|
| `A` | `Alpha` | words, lowercased |
| `C` | `Capitalization` | which letters of the word before it are upper case |
| `D` | `Digits` | runs of digits |
| `O` | `Other` | runs of symbols |
| `K` | `Keyboard` | keyboard walks like `qwerty` or `1qaz2wsx` |
| `X` | `Context` | things that do not fit the others |
| `Y` | `Years` | four digit years |

The number after the letter is a length, and it is also the file name. So `A6` means
`Alpha/6.txt`:

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

Capitalization is worth a word of its own, because it is the one that surprises people. Words in
`Alpha` are always stored lowercase. Every `A` token carries a hidden `C` token of the same length
that says which letters to upper case afterwards:

```
$ head -4 ruleset/Capitalization/6.txt
LLLLLL  0.86537548300305567
ULLLLL  0.10933250192575741
UUUUUU  0.0099566830879285681
LLLLLU  0.0013423768152759595
```

`LLLLLL` means leave it alone, and it is what most six letter words do. `ULLLLL` means
capitalise the first letter. This is why `monkey` and `Monkey` are one entry in `Alpha/6.txt` and not
two: the ruleset stores the word once and the shape decides the case.

So `monkey12` is `A6` + `C6` + `D2`, and its probability is:

```
P(A6D2) x P("monkey") x P("LLLLLL") x P("12")
```

which is `0.0378 x 0.00263 x 0.865 x 0.0817`, or about one in 142,000. Every candidate in the run gets
a number like that, and the run walks them from the largest down.

hashcat reads the directories in the table above, plus `Grammar` and plus `Omen` for the `M` shape. A
ruleset from the trainer also has `Prince`, `Masks`, `Emails` and `Websites` directories and a
`config.ini`. hashcat ignores those, so you can delete them if you want the ruleset smaller.

A ruleset does not have to be a directory. The whole of it in one `.tar.xz` works wherever a ruleset
is named, and a ruleset trained on `example.dict` is 3.2 MB as a directory and 275 KB as one file:

```
tar cf - -C /path/to/ruleset . | xz -9 > ruleset.tar.xz

./hashcat -m 0 -a 4 example0.hash ruleset.tar.xz
```

A `./` in front of every member, or one directory every member shares, is stripped, so it does not
matter which way the archive was built.

Single files may be compressed instead, with `.xz` appended: hashcat looks for `Alpha/8.txt` and then
for `Alpha/8.txt.xz`. Compress the whole ruleset, part of it, or none of it, and the run is the same
run either way.

```
find /path/to/ruleset -type f -exec xz -9 {} +
```

## 3. Running it

PCFG is attack-mode 4, and it needs nothing but a hash file:

```
./hashcat -m 0 -a 4 example0.hash
```

That runs the ruleset hashcat ships as its default, which is trained on passwords.

To use your own instead, name it after the hash file:

```
./hashcat -m 0 -a 4 example0.hash /path/to/ruleset
```

Name several and they run together, each with an equal share of the run. Merging rulesets that know
different things reaches candidates none of them reaches alone, which is what section 5 is about, and
`weights=` says how much of the run each one is worth. Every other setting is yours to change.

A ruleset that is installed, whether hashcat's or your own, is named rather than pathed, the same way
`-m 0` names a hash mode and `-a 8 wordlist` names a feed:

```
./hashcat -m 0 -a 4 example0.hash example
```

A name is looked for in two places, yours first:

```
<profile>/pcfg/<name>        $XDG_DATA_HOME/hashcat/pcfg, or ~/.local/share/hashcat/pcfg
<shared>/pcfg/<name>         where make install puts what hashcat ships
```

and in each of them a directory is preferred to a `<name>.tar.xz` of the same name. **Anything holding
a slash is a path and is never looked for**, so every ruleset already named by path keeps meaning
exactly what it did. A name that matches nothing is tried as a path too, so a ruleset directory
sitting in the working directory still works.

### 3.1. The ruleset hashcat ships

One, and `-a 4` with no ruleset named runs it.

| ruleset | what it is trained on |
|---|---|
| `default-passwords` | passwords, which is what a password guesser wants first |

A ruleset trained on ordinary language covers words a password list does not have, and merging one
with `default-passwords` reaches candidates neither reaches alone. hashcat does not ship such a
ruleset, because the text it would be trained on carries a licence of its own, and shipping a model
built from that text asks a question nobody needs asked. `pcfg/README.md` in the hashcat tree has the
tool that builds one, so the text is yours to fetch and the ruleset is yours to train.

Name your own beside the shipped one and both run:

```
./hashcat -m 0 -a 4 example0.hash default-passwords my-russian
```

Two rulesets get an even split. Weight it toward whichever you trust more:

```
./hashcat -m 0 -a 4 example0.hash default-passwords my-russian weights=2:1
```

What runs underneath is a feed for attack-mode 8, which is hashcat's mode for a generator plugin, and
`-a 4` is rewritten into it before anything else reads the command line. See
`hashcat-generic-attack-mode.md` for what attack-mode 8 is in general. The longer form still works and
is the same attack, so a script written before `-a 4` existed keeps running:

```
./hashcat -m 0 -a 8 example0.hash pcfg /path/to/ruleset
```

Everything below is written in the short form.

Here is a real run against hashcat's own example hashes, stopped after twenty seconds:

```
Session..........: hashcat
Status...........: Aborted (Runtime)
Hash.Mode........: 0 (MD5)
Hash.Target......: example0.hash
Time.Started.....: Sun Aug 23 17:08:57 2026 (20 secs)
Speed.#01........: 13369.7 MH/s (12.26ms) @ Accel:38 Loops:1024 Thr:64 Vec:1
Speed.#02........: 12525.9 MH/s (13.06ms) @ Accel:38 Loops:1024 Thr:64 Vec:1
Speed.#*.........: 25895.6 MH/s
Recovered........: 4990/6494 (76.84%) Digests (total), 4990/6494 (76.84%) Digests (new)
Progress.........: 512430312909/34928193902017160 (0.00%)
Restore.Point....: 258375680/12747516022634 (0.00%)
Candidate.Engine.: Device Generator
Candidates.#01...: MOnTpeL55 -> NACHTEn55
```

Three quarters of the list in twenty seconds, having looked at one candidate in every sixty eight
thousand. That ratio is what a PCFG is for.

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

* **3582 structures, 134 terminal lists.** How many shapes the ruleset knows and how many value files
  were loaded for them.
* **device engine.** Which half of the feed your hash mode picked. Read this one first: everything below
  it is a fast hash's, and a slow hash prints different lines. Section 6.3 says where the line is drawn.
* **candidate bound 63 bytes.** The longest candidate this run will produce. It is chosen from the
  ruleset. A ruleset with very long entries gets a bigger bound and pays a little speed for it.
* **inner loop 27 bits, 7414 candidates to a cell.** How many candidates the graphics card will
  generate from one base word, near the start of the run. Also chosen from the ruleset.
* **240901302469 base words for 1308976582820259 candidates (x5434).** The important one. Your CPU
  produces 240 billion base words and the card turns them into 1.3 quadrillion candidates, so each
  base word is worth about 5434 candidates. This is why a PCFG attack in hashcat is not limited by how
  fast one CPU core can generate guesses.

A slow hash says this instead:

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

Section 6.3 says where the line between the two is drawn and section 6.4 says what the escape is.

## 4. Settings

Settings are `key=value` arguments after the ruleset path, the same convention every attack-mode 8
feed uses:

```
./hashcat -m 0 -a 4 example0.hash /path/to/ruleset scale=4 costmax=48
```

Most people never need any of them.

| setting | default | what it does |
|---|---|---|
| `scale` | 1 | How finely probabilities are graded. Higher is closer to true probability order and costs memory and startup time. |
| `costmax` | 64 | How deep to enumerate, in bits. This is what bounds the keyspace; the grammar's real keyspace is far larger. |
| `weights` | even | The share each ruleset carries when you give more than one. See below. |
| `threads` | auto | CPU cores used to produce candidates. `0` produces them on the calling thread. The default is 16 on a fast hash and 8 on a slow one, both measured, and capped by the machine. |
| `kbits` | auto | How many candidates a base word may expand into on the card. |
| `maxword` | auto | How long a candidate the card will build, in 4 byte words. Must be a multiple of 16. |
| `maxgain` | 1.5 | How much wider the expansion has to get before the bigger candidate buffer is worth taking. |
| `walk` | 1 | Steps to the next base word where it can instead of working it out from its position. It produces exactly the same run either way, so this is only here to turn off. |
| `omen` | 1 | Carries the OMEN escape on a slow hash. See section 6.4. A fast hash cannot carry it whatever this says. |

`scale`, `costmax` and `omen` all change which candidate sits at which position in the run, so they
are part of the attack's identity. Change one and a restore point from before is no longer valid. They
travel as arguments, which is what the brain hashes and what the restore file records, so hashcat
notices.

## 5. Using more than one ruleset

You can give several ruleset directories at once:

```
./hashcat -m 0 -a 4 example0.hash /path/to/names /path/to/rockyou
```

They become **one grammar**, not two attacks run back to back. Every probability in the result is the
weighted average of what each ruleset said, for the shapes and for every value file.

This matters when the rulesets know different things. A ruleset trained on a list of names knows a lot
of names and has almost no digits or years, because the list it learned from had none. A ruleset
trained on leaked passwords has the digits and years and none of the names. On their own, neither one
can produce `hüseyin1`. Merged, the shape "word then one digit" that the password ruleset learned is
available over the words the name ruleset learned, and it can.

`weights` sets the split, and the numbers are relative, so `weights=3:1` and `weights=75:25` are the
same thing:

```
./hashcat -m 0 -a 4 example0.hash /path/to/names /path/to/rockyou weights=1:3
```

An even split is the default and it is often not what you want. Merging in a ruleset that describes
nothing about your target costs you most of the run, because half the probability mass goes to
candidates that were never going to be right. Against hashcat's pure ASCII example hashes, a rockyou
ruleset on its own recovers 2042 plaintexts in a fixed budget. Merged evenly with a non-Latin name
ruleset it recovers 616, and at `weights=3:1` toward rockyou it recovers 1080.

Two things this is not, and both are worth knowing:

* It is not the same as running both attacks and interleaving the results. That would need duplicate
  detection across the whole stream, which is not possible without giving up `--skip` and `--restore`.
* It is not the same as training one ruleset on both source lists. A real training run weighs each
  value file by how many tokens went into it. This weighs everything in a ruleset by one number.

Merging a ruleset with itself gives that ruleset back exactly, which is a useful sanity check.

### 5.1. What the merge actually does

The merge runs once per file, at load time, and the same routine handles the grammar and every
terminal list. Nothing about it happens again during the run.

**The weights are normalised first.** Whatever you write in `weights` is divided by the sum of all of
them, so `weights=3:1` and `weights=75:25` both become 0.75 and 0.25. That is why the numbers are
relative, and it is what makes the result a weighted average rather than a weighted sum.

**Each line's probability is scaled by its ruleset's share, then added.** A file is a list of
`value <tab> probability` lines. Reading ruleset *i*'s copy of a file contributes `p * w[i]` for every
line in it. There is no division anywhere afterwards: the average falls out because the shares sum
to 1.

**Values are matched by their bytes.** Entries go into an open-addressed hash table keyed on the value
itself, FNV-1a over its bytes, with linear probing. A value that two rulesets both know is found on
the second insert and its probability is accumulated into the entry that is already there, so it ends
up with both contributions and appears once.

That is the mechanism behind the `hüseyin1` example above. It is also why a value both rulesets know
comes out **earlier** in the run than either ruleset alone would have put it: cost is
`-log2(p) * scale`, so a larger probability is a smaller cost.

**Deduplication is switched off for a single ruleset.** The hash table is only built when more than
one ruleset was given. One ruleset appends straight to the list and never hashes anything, so it pays
nothing for a feature it cannot use. This is also why merging a ruleset with itself is a real test
rather than a trivial one: it takes the other path and has to come back with the same answer.

**A file one ruleset does not have is not an error.** It contributes nothing and the rulesets that do
have it carry the merged list. A grammar trained on names has no `Years/1.txt`, and that is exactly
the case merging is for.

**The merged list is sorted by probability, descending, and ties are broken by insertion order.**
Without the tiebreak two runs of the same merge could order equal-probability values differently,
depending on the sort implementation, and a restore point would not land where it was taken.

**Nothing is renormalised at the end.** The merged probabilities are the weighted sums, and they go
straight into the cost as they are.

**The weights are part of the attack's identity.** Two runs that differ only in `weights` describe
different attacks: the same position means a different candidate. The feed folds the ruleset count and
every share into the value hashcat uses to tell attacks apart, so the brain will not credit one run's
work to the other and a restore point taken under one split will not resume under another. A single
ruleset is deliberately left out of that, because its share is always exactly 1 and nothing about its
enumeration changed.

## 6. How this differs from the original PCFG

hashcat's PCFG is based on the same model as lakiw's `pcfg_cracker`, but it is not a port of it. Five
things differ, and the first two are two sides of one decision.

### 6.1. It can be counted and jumped into

A probability is a real number, and a list sorted by a real number has no arithmetic that takes you to
the ten billionth entry. The only way to reach it is to produce the first 9,999,999,999. That is why a
PCFG guesser is normally something you pipe into a cracker and let run, with no way to split it, stop
it, or resume it.

hashcat rounds each probability to a whole number of steps first. Candidates then fall into groups of
equal cost, the size of each group can be worked out in advance, and "the ten billionth candidate" has
an answer you can compute in microseconds. That is what gives you:

```
$ ./hashcat -m 0 -a 4 --keyspace
12747516022634
```

and `--skip`, `--limit`, `--restore`, splitting one attack across several GPUs, and the brain. All of
those need a keyspace with a fixed order and a way to jump into the middle of it.

```
./hashcat -m 0 -a 4 example0.hash /path/to/ruleset --skip 1000000 --limit 200000
```

### 6.2. The price is that the ordering is approximate

Rounding puts candidates of slightly different probability into the same group, and within a group the
order is arbitrary. So the run is in probability order only down to the size of a group.

At the default `scale=1` that costs very little. Measured against an exact enumerator over the same
number of guesses, it reaches 99.83% of the probability mass and 99.994% of the cracks. Raising
`scale` narrows the groups and recovers the rest, at the cost of memory and startup time.

Do not raise it because approximate sounds bad. Raise it if you have measured that it helps you.

### 6.3. On a fast hash the device engine does the guessing

`pcfg_cracker` generates candidates on the CPU and prints them. One core producing a few million
guesses a second is fine for a slow hash and nowhere near enough for a fast one.

So on a fast hash, hashcat sends the card a base word plus a small description of what to vary, and
the card expands it. The `x5434` in the startup lines is the multiplier: one base word from the host
became 5434 candidates on the device.

**On a slow hash it does not.** The line hashcat draws between the two is its own: a mode whose attack
kernel carries the whole hash runs the device engine, and a mode with a separate iteration kernel does not.
`-m 0` is the first kind and `-m 3200` is the second. You can tell them apart from the startup lines,
which say `pcfg: device engine il=...` on one and nothing about an device engine on the other.

**And a handful of fast hashes do not either.** The device engine needs a kernel of its own per hash
mode, `OpenCL/mNNNNN_a4-pure.cl`, and 222 of the fast modes have one. The rest do not, because their
rules kernel does something the shared engine cannot express: it records the crack itself instead of
handing back four words to compare, or it takes the candidate as register words rather than as an
array. PKZIP and the Kerberos modes are the shape. Those run the host engine and say so, which is the
same thing that happens on a slow hash, and nothing about the command line changes.

That is not a fallback. It is the better half of the attack, and section 6.4 is why. A slow hash wants
a few hundred thousand candidates a second, one core gives tens of millions, and everything the
device engine gave up to reach billions can be given back.

Two things follow from it that are easy to trip over.

**The two are different attacks against the same ruleset.** They enumerate different sets and report
different keyspaces, so `--skip`, `--restore` and a distributed split are not interchangeable between
them, and hashcat's brain is told they are different so it will not reuse one for the other.

**The host engine uses several cores.** `threads` says how many and it picks a sensible number on its
own. That matters only for the quickest modes on the slow side of the line, `-m 12700` and `-m 10500`
among them, which run at hundreds of millions of hashes a second: on those the candidates cannot be
produced fast enough by one core, and no amount of them quite keeps up either. On anything genuinely
slow it makes no difference, because a PCFG attack already feeds bcrypt as fast as a mask does.

This is also why `-O` is refused on a fast hash:

```
The device engine has no optimized kernel. Run this without -O.
```

**`-r` and `-g` ask for the host engine.** The device engine cannot have rules: the inner loop that
would apply them is the one walking the cell, and there is no second one. The host engine can, because
it is attack mode 0 with a different reader in front of it and hashcat's own rules kernel applies them
there exactly as it does to a word list. So a fast hash with `-r` runs the host engine and says so on
the line it prints at startup, rather than ending the run. It is slower than the same attack without
rules, and it is the attack you asked for.

The two are different attacks and hashcat's brain is told so, the same way it is told for a slow hash,
so a session with rules and a session without will not reuse each other's covered keyspace.

**Rules are a second amplifier rather than a consolation prize.** The device engine amplifies by
expanding a cell inside the hash kernel. hashcat's rules kernel amplifies by applying every rule to
every base word, also inside the hash kernel, and that is what `-a 8` has always done for any other
feed. So a fast hash with rules still has an amplifier on the device: it is a different one, fed with
base words the host engine produced, and it multiplies by the number of rules. Stacked rules stack
here as they do everywhere, so `-r a -r b` gives you every rule of one applied over every rule of the
other.

Measured on an RX 9070 XT against `-m 0`, one grammar, one card, twenty five seconds each:

  what is in front of the card                      candidates a second
  --------------------------------------------------------------------
  device engine, no rules                                    21.0 GH/s
  host engine, best66.rule, 90 rules                          3.4 GH/s
  host engine, 1 rule                                        49.3 MH/s

The middle row is the one to read. The host engine on its own hands the card about 49 million base
words a second and that is the ceiling on everything it feeds, but 90 rules turn each of those into
90 candidates on the device, which is 69 times more work out of the same base word rate. The device
engine is still 6 times faster than that, because a cell expands into thousands rather than into 90,
so rules do not replace it. They put a run that used to end with an error message back within a
factor of a few of the fastest thing the mode has.

`Candidate.Engine` in the status line tells you which one you have: `Device Generator` when something
is amplifying on the card, whether that is a cell or a rule set, and `Host Generator + PCIe` when the
host is building whole candidates and paying for the copy. The bottom row above reports
`Host Generator + PCIe`, because one rule amplifies by one and is not an amplifier.

`--stdout` shows you the host engine, not the device engine:

```
$ ./hashcat -a 4 --stdout --limit 5 /path/to/ruleset
```

It prints what the host produced and never starts a kernel, so the device engine is off for it for the
same reason it is off for a slow hash, and what comes out is what a slow hash would be given, escape
included. There is no way to print what a fast hash would produce: those candidates are the card's
output and never exist on the host at all.

`-S`/`--slow-candidates` takes the host engine too, and for the same reason again. It asks for every
candidate to be built on the host, so the card runs the plain straight kernel and there is no inner
loop to expand a cell in. `--brain-client` arrives here as well, because hashcat turns it into
`--slow-candidates` on the way.

### 6.4. OMEN rides the host engine and not the device engine

`pcfg_cracker` trains two models. The PCFG is one and a Markov model called OMEN is the other, and its
guesser interleaves both. A trained grammar contains a structure called `M`, which means "anything the
grammar did not cover" and is what OMEN fills in. On a ruleset trained at the default coverage that
line carries about 40% of the probability mass.

**On a slow hash hashcat carries it**, from the ruleset's own `Omen` directory, and says so:

```
pcfg: OMEN escape carried, 15 levels over 1 model, 40962142820 guesses, 18 MiB of tables
```

The guesses are the same guesses. Every level was compared against `pcfg_cracker`'s own generator, on
four rulesets including a Cyrillic one, and the sets are identical. The count is exact, not an
estimate, so `--keyspace`, `--skip` and `--restore` mean on the OMEN half exactly what they mean on the
rest of the run.

The tables are the price. They are built at startup and they are not small: 18 MiB for a ruleset
trained on a small corpus, 434 MiB for the largest one tried here. The line above tells you before you
wait for it.

**On a fast hash hashcat drops it**, and says that instead:

```
pcfg: OMEN escape dropped, the device engine cannot walk a trellis. This run covers the grammar and not the escape
```

The reason is section 6.3. The card is handed a rectangle: a few independent lists, and a candidate is
one entry from each. An OMEN guess is nothing like that. Each character it writes decides which
characters may follow, so it does not factor into independent lists and there is no rectangle to send.

If you are having a ruleset trained for you and you mean to use it on a fast hash, ask for
`--coverage 1.0`. That tells the trainer not to emit `M` at all, so the mass goes into the terminal
lists rather than into a structure the fast path discards.

`omen=0` turns the escape off on a slow hash as well. The reason to want that is to compare like with
like: with it off the two engines enumerate the same set, which is what the device engine is checked
against.

### 6.5. Capitalization of non-ASCII rulesets is nearly identical, but not quite

A capitalization mask holds one letter per **character**, and a character in UTF-8 can be one to four
bytes. hashcat applies the mask per character, the same as `pcfg_cracker`, and uppercases the
character rather than the byte. Russian, Greek, accented Latin and the rest all get their capitals.

There is one exception, and it comes from a hard constraint. Every candidate a structure produces has
to be the same length, because that is what the device engine's fixed candidate array, its padding and its
cut all rest on. A handful of characters have an uppercase form that is a **different number of
bytes** than the lowercase one, and those cannot be uppercased without changing the candidate's
length. The commonest by far is the Turkish dotless `i` (`\u0131`), whose uppercase is the ASCII
`I`. Those characters are left as they are, so a `U` on one of them does nothing.

On a large name ruleset that is about 0.66% of the characters. The other 99.34% either uppercase with
the length preserved or have no uppercase form at all.

Scripts with no case at all, such as Arabic and Hebrew, are unaffected: there is nothing to uppercase,
and `pcfg_cracker` produces exactly the same single candidate per mask that hashcat does. If your
ruleset is mostly such a script, note that its `Capitalization` lists are doing nothing useful and
every mask beyond the all-lowercase one is a duplicate. That is a property of the trained ruleset
rather than of hashcat.

### 6.6. Several rulesets can be merged

Covered in section 5, and section 5.1 says how the merge works. `pcfg_cracker` takes one ruleset.

## 7. Things that will confuse you once

* **`--stdout` shows you the host engine.** It never starts a kernel, so it gets the host generator,
  escape and all. There is nothing it could show you of the fast path, whose candidates only ever
  exist on the card.
* **`-O` is refused rather than ignored** on a fast hash. Run without it.
* **`-i`/`--increment` and the custom charsets `-1` to `-4` are refused.** Both belong to a mask, and
  `-a 4` takes a ruleset rather than a mask. What decides the lengths here is the grammar and
  `costmax`.

* **`-S`/`--slow-candidates` and `--brain-client` move you to the host engine** as well, and the
  startup line says so. Both ask for every candidate to be built on the host, which is the one thing
  the device engine does not do.
* **`-r` and `-g` move you to the host engine** rather than being refused. The run says which engine
  it got on the line after the ruleset summary. You keep an amplifier on the card either way, because
  the rules kernel is one; it multiplies by the rule count instead of by the size of a cell.
* **The same ruleset against `-m 0` and against `-m 3200` is not the same attack.** Different
  candidates, a different keyspace and a different number in `--keyspace`. Section 6.3 says why. Both
  are correct; neither one's restore point or brain session carries over to the other, and hashcat
  knows that and will not let them.
* **The keyspace is not the grammar's keyspace.** It is however much of it `costmax` reaches. The real
  keyspace of a trained grammar is astronomically larger and there is no point enumerating all of it.
* **Progress is counted in candidates and the restore point in base words.** In the status output
  above, `Progress` is 76 billion of 1.3 quadrillion candidates while `Restore.Point` is 14 million
  base words. Both are correct and they are counting different things.
* **Startup takes a few seconds** on a large ruleset, and longer when you merge several, because every
  value file is read and indexed. It happens once.
* **Changing `scale`, `costmax`, `weights` or the ruleset invalidates a restore point.** All of them
  change which candidate sits at which position. hashcat can tell, so it will not silently resume into
  the wrong place.

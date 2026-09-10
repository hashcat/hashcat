# The Table Attack

The table attack reads a wordlist and a table file that defines token replacements. We choose a replacement independently for each token position in a word, then generate the full cross product of those choices.

```
hashcat -m 0 -a 5 hashes.txt rockyou.txt tables/leetspeak-common.table tables/toggle.table
```

The attack was available as `-a 5` in hashcat-legacy, but was removed in 3.00 because it was considered unsuitable for GPU execution. We now run it on the GPU. On a GeForce RTX 4090 against MD5, over the whole of rockyou, the same run measures 65 MH/s unamplified, 1197 MH/s through the case table, 1227 MH/s through leetspeak, 13442 MH/s through both at once, and 19687 MH/s with the extended leetspeak tier added to those.

## 1. What it is for

A leetspeak table generates candidates such as `p@ssw0rd` from `password`. A case table tries every combination of uppercase and lowercase letters. Keyboard layout tables reproduce passwords typed with the wrong layout active. Transliteration tables provide ASCII spellings for words that contain accents or use another script.

### Each position chooses for itself

A rule substitutes every occurrence at once. `ss$` turns `password` into `pa$$word` and `ss5` turns it into `pa55word`, and no rule in between produces `pa5$word` or `pa$5word`. The two positions cannot be given different replacements, because a rule has no way to name one occurrence and not the other.

```
$ cat s.rule
:
ss$
ss5
$ hashcat -a 0 --stdout words.txt -r s.rule
password
pa$$word
pa55word
```

The table attack chooses at each position separately, so the same two replacements give all 9 spellings:

```
$ cat s.table
s	$
s	5
$ hashcat -a 5 --stdout words.txt s.table
password
pas$word
pas5word
pa$sword
pa$$word
pa$5word
pa5sword
pa5$word
pa55word
```

This is the reason the attack exists. Mixed spellings are what people type, and they are the ones a ruleset skips. The gap grows with the word. A password with 4 `s` in it has 81 spellings of its `s` alone, counting the ones left as they are, and the ruleset above reaches 3 of them.

### It hardly generates duplicates

A ruleset can be written to reach some of these by naming positions, but it repeats enormous amounts of work. A generated leetspeak ruleset applies `sa4` to every word, including words with no `a` in them. Those come out unchanged and duplicate the identity rule.

Take 6 letters with 2 replacements each. As a ruleset that is 729 combinations, and as a table it is 12 lines. Over the first 10000 passwords of rockyou:

| | emitted | distinct |
|---|---|---|
| 729 rules | 7290000 | 294875 |
| 12 table lines | 1081542 | 1080795 |

96 percent of the ruleset run is duplicates, because every rule is applied to every word and `sa4` on a word with no `a` hands back the word. The table only enumerates replacements for tokens the word actually contains, so almost nothing it emits is a repeat.

The table also reaches 3.7 times as many distinct candidates as the ruleset does, which is the point rather than a side effect: `sa4` changes every `a` in a word at once, and the table changes them independently.

No word can repeat itself when the replacements are all the length of what they replace, which covers leetspeak and case toggling. The 747 repeats above are two words meeting rather than one word repeating: rockyou holds `password` and `passw0rd`, and both reach `passw0rd`. It holds `sarah1` and `sarahi`, and both reach `$4r4h1`. That is what a wordlist contains, not something the table does.

A table that changes length can repeat within one word, where a replacement runs into the token beside it: with `a` to `ab` and `bc` to `c`, the word `abc` reaches `abc` twice, once by changing nothing and once by making both changes. It takes a table written to do it, and the cost is one wasted candidate rather than the 96 percent above.

Rules also cannot replace one character with two, or match several characters at once. Neither `f` to `ph` nor `th` to `7h` can be expressed that way, whatever the size of the ruleset.

### Typed in the wrong layout

Somebody types a Russian password with a US layout active, or a boot loader offers nothing but a US layout. What reaches the hash is the US letters at those key positions, so a Russian wordlist has to be converted before it is any use. The layout tables do that conversion, and `identity=0` makes it a conversion rather than a set of variations:

```
$ cat words.txt
пароль
$ hashcat -a 5 --stdout words.txt tables/layouts/ru.table identity=0
gfhjkm
```

Each of the 6 letters is one line of the table, and the whole word converts at once:

```
п	g
а	f
р	h
о	j
л	k
ь	m
```

The reverse table takes a wordlist of what was typed back to what was meant:

```
$ hashcat -a 5 --stdout typed.txt tables/layouts/ru-reverse.table identity=0
пароль
```

This is what `--keyboard-layout-mapping` was added for, and that option reaches 30 of 595 hash modes, all of them TrueCrypt and VeraCrypt, and it is refused outright for every other mode including most of the TrueCrypt and VeraCrypt ones. The same files as a table work for every hash mode and every attack the feed serves.

Leaving the unchanged choice on is a different attack rather than a broken one. `пароль` has 6 covered letters, so the default gives 2^6 candidates with `gfhjkm` among them, which is what you want for a password where the layout was switched partway through. It is not what you want when the whole word was typed on the wrong layout.

### The wordlist as a template

Everything above changes a word a little. A table can also replace a whole word with a different one, and that turns the attack into something else.

People build a password around something they care about, and the thing itself is interchangeable while the shape around it is not. rockyou holds `football1`, `ilovefootball`, `football!`, `Football2010` and thousands more of the same shape. Somebody who follows a different sport wrote the same shapes around a different word. A table that maps each sport to every other sport reaches all of them:

```
$ hashcat -m 0 -a 5 hashes.txt rockyou.txt tables/sports.table identity=0 template=1
```

Two settings make it work. `identity=0` takes away the choice of leaving the word alone, because the original is already in the wordlist you gave and trying it again is wasted. `template=1` drops a word the table never matched, and that is what turns the wordlist into a set of patterns: without it, a word naming no sport is still worth one candidate, itself.

The difference is the whole point. Over 400000 lines of rockyou with a 20 sport table:

| | candidates |
|---|---|
| `identity=0` alone | 419727 |
| `identity=0 template=1` | 20767 |

Every one of those 20767 is in both runs: the table builds the same candidates either way. The other 398960 are the wordlist handed straight back, which is 95 percent of the first run. The second says how many words it dropped and why:

```
table: template on, 398961 of 400000 words matched no rule and were dropped
```

A word dropped for matching nothing is counted apart from a word dropped because the hash mode would take none of its candidates. They are different things to be told.

What makes this worth doing is that the patterns are real. Nobody sits down and writes `ilove<thing>` and `<thing>2010` and `<thing>!` and gets the distribution right. A cracked wordlist already has it, measured from people, and the table lifts those shapes off one subject and puts them on another.

The idea is not sports. Build the list for bands, cars, cities, football clubs, films, pets, or a company's own product names, and use a wordlist of passwords rather than a dictionary. A list of n things is n * (n - 1) lines, one per pair, and `tables/sports.table` is there as a starting shape rather than as a recommendation.

Matching is by bytes, so `football` and `Football` are two different sources. Add `tables/toggle.table` if you want the case covered as well.

## 2. The table file

Each line defines one replacement for a source token. We write the source first, followed by a tab and the replacement.

```
a	4
a	@
e	3
ss	$$
h	$HEX[]
```

To give a source several replacements, we list it on separate lines. Each line adds another choice, so `a` in this example becomes either `4` or `@`. We split each line at its tab and preserve the replacement exactly, including any spaces at the end of it.

* Source tokens and replacements can both hold several bytes and both are UTF-8. `th` to `7h` matches two characters, and `f` to `ph` produces two.
* An empty replacement deletes the source token. Write it as `$HEX[]` so it survives editors that strip trailing whitespace.
* Blank lines and lines beginning with `#` are ignored. So is any other line that does not hold exactly one tab, which is what lets a table carry a header without a comment marker.
* Either side accepts `$HEX[..]` wrapping the whole side. That is the only way to write a newline, or a `#` in the first column.
* Repeating the same source and the same replacement would generate the same candidate twice, so we discard exact duplicates.

When several source tokens match at the same position, we match **longest first** and do not try other ways to split the word. With both `s` and `ss` in a table, `ss` is always one token. To cover both readings, give the `ss` bucket the cross product of the `s` bucket with itself.

The order of entries controls the order we try replacements. The odometer starts with the first entry of each bucket, so putting the most promising replacements first gives them priority during the run.

### Leaving a token alone

Leaving a token unchanged is always one of its choices, and a table does not have to say so. A table cannot be asked to spell that out for characters nobody thought of. One that names the letters of a single language would otherwise force a substitution on every letter it happens to cover while leaving every other letter alone, and the two halves of the word would not compose. Because the unchanged choice comes first in every bucket, the first candidate for a word is the word itself, so the attack includes a straight wordlist run.

A conversion table wants the opposite. It should convert the whole word rather than try every mixture of converted and unconverted tokens, so it turns the unchanged choice off with `identity=0`. The layout tables say so in their headers. Without it, a layout table over a word of n covered letters produces 2^n candidates instead of the one conversion that was wanted.

## 3. Several tables at once

Every argument after the wordlist is a table, and we read them all into one set. Where several tables define the same source, their replacements merge in the order the tables were given and exact duplicates are dropped:

```
hashcat -m 0 -a 5 hashes.txt words.txt tables/leetspeak-common.table tables/toggle.table
```

This is how leetspeak and case are combined, rather than by shipping a table that has both merged into it already. 2 leetspeak tiers, a case table and an emoji table give 15 combinations from 4 files. The status display names the count on its `Guess.Base` line, as `Feed (words.txt + 2 tables)`.

Combining tables changes which candidates we generate, not only how many.

**Adding a table can take candidates away.** Because the longest match wins, an entry for a whole word beats the entries for its individual letters. With `leetspeak-common.table` alone, `chickenpass` produces 162 candidates, `ch1ckenpass` among them. Adding `emoji.table` brings that down to 54 and drops that candidate, because `chicken` now matches as one token instead of as seven letters.

**Mixing conversion and variation changes the attack.** A layout table with `identity=0` converts each word completely. Merged with a leetspeak table, every shared letter can now be left alone, replaced with leetspeak, or converted to the other layout. That covers a password typed with the layout switched partway through, but it is no longer the complete conversion on its own. The counts multiply rather than add. To keep conversion and variation apart, run two attacks.

## 4. The tables that ship

| table | what it does |
|---|---|
| `tables/leetspeak-common.table` | the substitutions people actually make |
| `tables/leetspeak-extended.table` | seen regularly, well behind the common set |
| `tables/toggle.table` | case, both directions, Latin, Greek and Cyrillic |
| `tables/emoji.table` | whole words as emoji |
| `tables/layouts/<lang>.table` | that keyboard layout to US, for `identity=0` |
| `tables/layouts/<lang>-reverse.table` | US to that keyboard layout, for `identity=0` |
| `tables/sports.table` | one sport for another, for `identity=0 template=1` |

The same layout tables are what `--keyboard-layout-mapping` reads. See `keyboard-layout-mapping.md`.

## 5. Settings

Settings are `key=value` arguments and go after the tables.

| setting | default | what it does |
|---|---|---|
| `maxperm` | 1048576 | how much of one word's cross product the host enumerates, 0 for no limit |
| `template` | 0 | `1` drops a word no rule matched, which reads the wordlist as a set of patterns |
| `identity` | 1 | whether leaving a token alone is one of its choices, `identity=0` for a table that converts |

### maxperm

The candidate count for a word is the product of its radices, and a radix is the number of replacement choices at one token position. That product grows exponentially with the length of the word while the likely benefit does not.

Of rockyou's 14344391 lines, 14222506 are 16 bytes or fewer and 121885 are longer, which is 0.85 percent of the file. Run through `leetspeak-common.table` and `toggle.table` together with no limit, the short ones alone are worth 2216157954021 candidates. Add the 121885 long ones and the total saturates a 64 bit counter, and hashcat says as much on startup: the widest single word wants more than 2^64 candidates by itself. Without a limit the attack never gets past the first few long words it meets.

Which candidates we give up matters as much as the limit. Simply taking the first ones favours changes at the end of a word, because the odometer advances its last position fastest. Truncating that sequence means `administratorpassword1234` never starts with a `4`, even where there is budget to spare.

So we spend the budget on **how many** substitutions a candidate makes rather than on where they fall. We try the word itself first, then every candidate that changes one token, then every candidate that changes two, and so on until the budget runs out or we reach eight changes, whichever comes first. Eight is the width of the table that counts them and it is generous: a word that wants a ninth change in the part the host walks has already spent far more budget than the default gives it. Every position stays reachable at every weight. What we leave out is the candidates that change many tokens at once, not the positions near the start of the word. A word whose full cross product fits in the budget still gets all of it.

What the budget buys is the part the host walks, not the whole word. The graphics card expands a cell of up to 8 token positions and that cell is never cut down, because cutting it down is giving up the amplification the attack exists for. So the budget is divided by the size of the cell and spent on the rest, and a word is worth at least one whole cell however small `maxperm` is set. With the shipped tables a cell reaches a few hundred thousand candidates, so `maxperm=1` and `maxperm=100000` ask for much the same thing. The setting bites on the long words it was written for, where the part in front of the cell is what runs away.

Changing `maxperm` changes the order of candidates, so it is part of the identity of the attack. A restore point taken before the change is not valid after it.

## 6. The lines it prints

```
table: device engine, 614 buckets, 9868 byte pool, mean cell 1346, entries of several lengths
table: 22494678 base words for 31362630643 candidates (x1394)
table: 1 words left out, no candidate of theirs is between the 0 and 256 bytes this hash mode accepts
table: maxperm 1048576, 22158 words held to it, the widest wanting more than 2^64
```

* **device engine.** Each base word is expanded into its candidates on the GPU, inside the hash kernel. A slow hash reports `host engine` instead and builds every candidate on the CPU.
* **mean cell 1346.** The average number of candidates the GPU makes from one base word. Expanding there is what gets past the generation speed of a single CPU core.
* **entries of several lengths.** Some replacement differs in length from its source, so a candidate cannot keep the layout of its base word. Handling that costs a little speed.
* **one pass over the wordlist.** We read it once to learn the length of the attack and where a seek lands. A pass that takes more than a second reports how long it took, on a line of its own, and the run above was quick enough not to. What the pass learned is written to `cache/feeds/table`, so a run that finds it there does not read the wordlist again and the line does not appear. A file there is described by the wordlist, the tables and the settings together, so changing any of them measures again rather than reusing the wrong answer. `--cache-path` points the directory somewhere several machines share. This cache tolerates a read only directory, since a run writes only when it had to measure and carries on from memory when the write fails, but the compiled kernels are under the same option and they do not, so a shared directory wants to be writable.

Two more lines appear when they apply. `table: identity off` says the unchanged choice was turned off, and `table: template on` counts the words that matched no rule and were dropped. A word left out for its length and a word left out for matching nothing are counted apart, because they are different things to be told.

## 7. Notes

Rules given with `-r` work with the table attack. Stacking rules gives up the feed's own kernel for the attack mode 0 one, which costs the speed the table attack gets from expanding inside the hash kernel.

The tokenizer matches bytes rather than characters, so a source that is only a UTF-8 continuation byte could match inside a character and produce invalid UTF-8. Sensible tables have no such entry. We match bytes because a character aware tokenizer would break tables written for single byte encodings.

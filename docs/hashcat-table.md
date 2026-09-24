# The Table Attack

The table attack reads a wordlist and one or more tables that define token replacements. It selects a replacement independently for each token position in a word, then generates the complete cross product of those choices.

Every argument after the wordlist is a table, and hashcat merges them into one set. Supplying a leetspeak table and a case table produces one combined attack rather than two separate runs, as shown below. Section 3 covers how lines from different tables merge.

```
hashcat -m 0 -a 5 hashes.txt rockyou.txt tables/leetspeak-common.table tables/toggle.table
```

The attack was available as `-a 5` in hashcat-legacy, but was removed in 3.00 because it was considered unsuitable for GPU execution. It now runs on the GPU. In one recorded GeForce RTX 4090 test against MD5 over the full rockyou wordlist, adding both case and leetspeak tables raised throughput from 65 MH/s unamplified to 13.4 GH/s, and the extended leetspeak tier reached 19.7 GH/s.

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

The table attack chooses independently at each position, so the same two replacements produce all nine spellings:

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

Independent replacements are the reason the attack exists. Users create mixed spellings that an ordinary substitution rule misses, and the gap grows with the number of matching positions. A password containing four instances of `s` has 81 possible spellings of those positions, including unchanged letters, while the ruleset above reaches only three.

### Few duplicate candidates

A ruleset can be written to reach some of these by naming positions, but it repeats enormous amounts of work. A generated leetspeak ruleset applies `sa4` to every word, including words with no `a` in them. Those come out unchanged and duplicate the identity rule.

Consider six letters with two replacements each. A ruleset requires 729 combinations, while a table requires 12 lines. Over the first 10,000 passwords in rockyou:

| | emitted | distinct |
|---|---|---|
| 729 rules | 7290000 | 294875 |
| 12 table lines | 1081542 | 1080795 |

The ruleset produces 96 percent duplicates because every rule applies to every word, and `sa4` returns a word without an `a` unchanged. The table enumerates replacements only for tokens present in the word, so almost every emitted candidate is distinct.

The table also reaches 3.7 times as many distinct candidates as the ruleset does, which is the point rather than a side effect: `sa4` changes every `a` in a word at once, and the table changes them independently.

A word cannot produce the same candidate twice when every replacement has the same length as its source, which covers leetspeak and case toggling. The 747 duplicates above arise when different source words converge. For example, rockyou contains both `password` and `passw0rd`, which can each produce `passw0rd`. It also contains `sarah1` and `sarahi`, which can each produce `$4r4h1`. These duplicates come from the wordlist rather than from repeated table paths.

A length-changing table can produce an internal duplicate when a replacement overlaps the result of its neighboring token. With `a` to `ab` and `bc` to `c`, the word `abc` produces `abc` both unchanged and with both substitutions. This requires a table that creates the collision and costs one candidate rather than the broad duplication of a ruleset.

Rules also cannot replace one character with two, or match several characters at once. Neither `f` to `ph` nor `th` to `7h` can be expressed that way, whatever the size of the ruleset.

### Typed in the wrong layout

A user may type a Russian password while the US layout is active, or encounter a boot loader that provides only a US layout. The resulting password contains the US characters at the corresponding key positions, so a Russian wordlist must be converted before it can match. The layout tables do that conversion, and `identity=0` makes it a conversion rather than a set of variations:

```
$ cat words.txt
пароль
$ hashcat -a 5 --stdout words.txt tables/layouts/ru.table identity=0
gfhjkm
```

Each of the six letters has one table entry, and the complete word is converted in one candidate:

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

This is what `--keyboard-layout-mapping` was added for. That option is enabled for 30 TrueCrypt and VeraCrypt modes and refused for other modes, including the remaining TrueCrypt and VeraCrypt variants. The same files as a table work for every hash mode and every attack the feed serves.

Leaving the unchanged choice on is a different attack rather than a broken one. For example, `пароль` has six covered letters, so the default gives 2^6 candidates with `gfhjkm` among them, which is what you want for a password where the layout was switched partway through. It is not what you want when the whole word was typed on the wrong layout.

### The wordlist as a template

Everything above changes a word a little. A table can also replace a whole word with a different one, and that turns the attack into something else.

People often build passwords around a subject they care about. The subject can vary while the surrounding pattern remains the same. rockyou contains `football1`, `ilovefootball`, `football!`, `Football2010` and thousands of similar patterns. A person interested in another sport may use the same patterns around a different word. A table that maps each sport to every other sport reaches those candidates:

```
$ hashcat -m 0 -a 5 hashes.txt rockyou.txt tables/sports.table identity=0 template=1
```

Two settings create the template attack. Setting `identity=0` removes the unchanged choice because the original candidate is already present in the wordlist. Setting `template=1` prevents the attack from returning any word unchanged, turning the wordlist into a collection of patterns.

Setting `template=1` applies the same rule in two situations. A word with no table match can produce only itself and is dropped entirely. A matching word also loses its unchanged candidate:

```
$ cat words.txt
footballman
$ cat t.table
football	basketball
man	woman
$ hashcat -a 5 --stdout words.txt t.table
footballman
footballwoman
basketballman
basketballwoman
$ hashcat -a 5 --stdout words.txt t.table template=1
basketballwoman
basketballman
footballwoman
```

Attack mode 0 already provides an ordinary wordlist attack. Including unchanged candidates in several separate table attacks would repeat that wordlist work once per table.

Over 400,000 lines of rockyou with a table containing 20 sports:

| | candidates |
|---|---|
| `identity=0` alone | 419727 |
| `identity=0 template=1` | 20767 |

All 20,767 transformed candidates appear in both runs. The other 398,960 are unchanged wordlist entries, accounting for 95 percent of the first run. The second run reports how many words it dropped and why:

```
table: template on, 398961 of 400000 words matched no rule and were dropped
```

hashcat reports unmatched template words separately from words whose candidates all violate the hash mode length limits because the two conditions require different corrective action.

What makes this worth doing is that the patterns are real. A manually written list of `ilove<thing>`, `<thing>2010` and `<thing>!` is unlikely to reproduce the correct distribution. A cracked wordlist already has it, measured from people, and the table lifts those shapes off one subject and puts them on another.

The same method applies to bands, cars, cities, football clubs, films, pets or a company's product names. Use a wordlist of observed passwords rather than a dictionary. A list of N subjects requires N * (N - 1) mappings, one for each ordered pair. File `tables/sports.table` provides an example structure rather than a recommended target list.

Matching is by bytes, so `football` and `Football` are two different sources. Add `tables/toggle.table` if you want the case covered as well.

## 2. The table file

Each line defines one replacement for a source token. The source comes first, followed by a tab and the replacement.

```
a	4
a	@
e	3
ss	$$
h	$HEX[]
```

List a source on several lines to give it multiple replacements. Each line adds another choice, so `a` in this example becomes either `4` or `@`. hashcat splits each line at its tab and preserves the replacement exactly, including any trailing spaces.

* Source tokens and replacements can both hold several bytes and both are UTF-8. `th` to `7h` matches two characters, and `f` to `ph` produces two.
* An empty replacement deletes the source token. Write it as `$HEX[]` so it survives editors that strip trailing whitespace.
* Blank lines and lines beginning with `#` are ignored. Any line without exactly one tab is also ignored, allowing a table to include an unmarked header.
* Either side accepts `$HEX[..]` around the complete token. Use this form to encode a newline or a `#` in the first column.
* Repeating the same source and replacement would generate the same candidate twice, so hashcat discards exact duplicates.

When several source tokens match at the same position, hashcat selects the **longest match** and does not try alternative ways to split the word. With both `s` and `ss` in a table, `ss` is always one token. To cover both readings, give the `ss` bucket the cross product of the `s` bucket with itself.

The entry order controls the replacement order. The odometer starts with the first entry in each bucket, so placing the most promising replacements first gives them priority.

### Leaving a token alone

Leaving a token unchanged is always one of its choices and does not need an explicit table entry. Requiring an identity entry would make complete coverage impossible for characters not anticipated by the table author. A table naming the letters of one language would otherwise force substitutions for every covered letter while implicitly leaving all other characters unchanged.

The unchanged choice is first in each bucket, so the first candidate for every word is the original word. A default table attack therefore includes an ordinary wordlist pass.

A conversion table requires the opposite behavior. It should transform the complete word rather than enumerate every mixture of converted and unconverted tokens, so it disables the unchanged choice with `identity=0`. The layout tables declare this setting in their headers. Without it, a layout table over a word of n covered letters produces 2^n candidates instead of the one conversion that was wanted.

## 3. Several tables at once

Every argument after the wordlist is a table, and hashcat merges all of them into one set. Where several tables define the same source, their replacements merge in the order the tables were given and exact duplicates are dropped:

```
hashcat -m 0 -a 5 hashes.txt words.txt tables/leetspeak-common.table tables/toggle.table
```

This combines leetspeak and case without requiring a premerged table. Two leetspeak tiers, one case table and one emoji table provide 15 combinations from four files. The status display names the count on its `Guess.Base` line, as `Feed (words.txt + 2 tables)`.

Combining tables changes both the candidate set and its size.

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
| `template` | 0 | `1` never hands back a word of the wordlist unchanged, which reads it as a set of patterns |
| `identity` | 1 | whether leaving a token alone is one of its choices, `identity=0` for a table that converts |
| `single` | 0 | `1` makes a candidate carry one substitution instead of the cross product of every position |
| `cap` | 0 | how many replacements one source may carry, 0 for no limit |

### maxperm

The candidate count for a word is the product of its radices, and a radix is the number of replacement choices at one token position. That product grows exponentially with the length of the word while the likely benefit does not.

Of rockyou's 14,344,391 lines, 14,222,506 are no longer than 16 bytes and 121,885 are longer, representing 0.85 percent of the file. With `leetspeak-common.table` and `toggle.table` and no limit, the shorter words alone produce 2,216,157,954,021 candidates. Adding the longer words saturates a 64-bit counter, and the widest individual word requires more than 2^64 candidates.

hashcat reports this condition at startup. Without a limit, the attack can spend effectively all of its time on the first few long words.

The choice of omitted candidates matters as much as the limit itself. Taking only the first candidates favors substitutions near the end because the odometer advances its last position fastest. A truncated sequence could therefore prevent `administratorpassword1234` from ever beginning with `4`, even when other parts of the budget remain unused.

The budget is therefore allocated by **how many** substitutions a candidate contains rather than by their positions. The original word comes first, followed by every candidate with one changed token, then every candidate with two changes, continuing until the budget is exhausted or the candidate reaches eight changes.

Eight is the width of the table used to count changes. A word requiring a ninth host-side change has already exceeded the default budget by a wide margin. Every position remains reachable at each weight, while candidates combining many simultaneous changes are omitted first. A word whose complete cross product fits within the budget still receives every candidate.

The budget limits only the portion enumerated by the host. The device expands a cell containing up to eight token positions, and that cell is never truncated because doing so would discard the amplification the attack is designed to provide. hashcat divides the budget by the cell size and spends the remainder on the host portion. Every word therefore receives at least one complete cell, regardless of how low `maxperm` is set.

With the shipped tables, one cell can represent several hundred thousand candidates. Settings `maxperm=1` and `maxperm=100000` can therefore request nearly the same work. The setting primarily affects long words whose host-side cross product grows without bound.

Changing `maxperm` changes the order of candidates, so it is part of the identity of the attack. A restore point taken before the change is not valid after it.

### single

`single=1` makes each candidate carry exactly one substitution. The word itself is still tried, once, and then every replacement of every source the table matches anywhere in it. There is no cross product, so `maxperm` has no candidate combinations to limit and is ignored.

This is a different attack rather than a cheaper one. The cross product asks what a word looks like when several letters are swapped at once. `single=1` asks what it looks like when one is, which is what a person who typed `p@ssword` actually did.

The setting also changes how overlapping sources behave. A cross product divides a word into non-overlapping tokens because two choices cannot claim the same bytes. At each position, the longest matching source wins. With both `s` and `ss` in the table, `ss` claims both letters in `password`, making `pa$sword` unreachable.

A single-substitution attack has no such conflict. Every source is offered at each matching position, including sources hidden beneath a longer match:

```
$ cat s.table
s	$
ss	5
$ hashcat -a 5 --stdout words.txt s.table
password
pa5word
$ hashcat -a 5 --stdout words.txt s.table single=1
pa5word
password
pa$sword
pas$word
```

Against 200000 rockyou words and 60000 other rockyou passwords as targets, using a harvested table of 8285769 lines over 234785 sources, `single=1` recovered 91.72 percent on 6975690596 candidates where the full cross product recovered 87.44 percent on 15016588492. More cracks for less than half the candidates.

The smaller candidate set has a generation cost. A cell covers one position instead of eight, reducing device amplification from about 73,989 to 1,852 in this test. The host must supply 3,765,707 base words instead of 205,410.

Against MD5, the single-substitution run takes 44 seconds compared with 13 seconds for the cross product. On a fast hash, `single=1` therefore performs more host work even while testing fewer candidates. On a slow hash, where candidate count dominates the cost, the smaller set is faster.

Setting `identity=0` cannot be combined with `single=1`, because one substitution needs the other positions left alone and `identity=0` is the instruction to convert them all. Setting `template=1` remains compatible and removes the one unchanged candidate.

### cap

A table file does not bound the number of replacements associated with one source. A table written by hand carries a handful. A table harvested from cracked passwords can carry thousands: the one measured above averages 35 replacements across its 234785 sources and its widest source carries 13510.

That is what makes such a table expensive, rather than the number of sources in it, and it is the part `single=1` does not reach. One substitution removes the combinations between positions and leaves the replacement lists exactly as they were.

Setting `cap=N` keeps the first N replacements of each source and drops the rest, in both attacks. The first N are the ones the table files give first, because a table line carries no count to rank them by. If your table came out of a harvest, write it in the order you want kept.

```
table: cap 8, 79149 of 234785 sources reached it and 7335944 lines were left out
```

What a cap buys depends entirely on what the hash costs. On the run above, with `single=1`:

| | candidates | recovered | on MD5 |
|---|---|---|---|
| no cap | 6975690596 | 91.72% | 44 s |
| `cap=32` | 97885487 | 61.70% | 37 s |
| `cap=16` | 51405879 | 49.41% | 34 s |
| `cap=8` | 26960600 | 36.19% | 33 s |
| `cap=4` | 14077682 | 24.62% | 32 s |

Setting `cap=32` removes 98.6 percent of the candidates while retaining two thirds of the cracks. This is a poor trade for MD5, where it saves only seven seconds from a 44-second run. Most of that time is spent reading an 8,285,769-line table and supplying 3.7 million base words rather than hashing.

The cap affects neither cost substantially. It shortens the replacement list at each matching position without reducing the number of positions, so the base-word count falls only from 3,765,707 to 3,664,044.

For a slow hash, candidate count dominates the cost and reverses the tradeoff. The same `cap=32` setting performs 71 times less work while retaining two thirds of the cracks. Choose a cap according to the cost of each candidate rather than the size of the table.

The cap changes the table, so it changes the attack's identity and its keyspace index the same way editing the table file would.

## 6. The lines it prints

```
table: device engine, 614 buckets, 9868 byte pool, mean cell 1346, entries of several lengths
table: 22494678 base words for 31362630643 candidates (x1394)
table: 1 words left out, no candidate of theirs is between the 0 and 256 bytes this hash mode accepts
table: maxperm 1048576, 22158 words held to it, the widest wanting more than 2^64
```

* The **device engine** line means that each base word is expanded inside the GPU hash kernel. A slow hash reports `host engine` and builds every candidate on the CPU instead.
* The **mean cell** value is the average number of candidates the GPU creates from one base word. Device-side expansion avoids the generation limit of a single CPU core.
* The **entries of several lengths** notice means that at least one replacement differs in length from its source. Those candidates cannot retain the memory layout of the base word and are slightly slower to process.
* The **one pass over the wordlist** notice describes the scan used to determine the attack length and seek positions. A scan longer than one second reports its duration on a separate line.

  hashcat stores the result under `cache/feeds/table`. A later run with the same wordlist, tables and settings uses the cached data without rescanning the wordlist. Changing any of those inputs creates a new measurement instead of reusing an incompatible result. Option `--cache-path` can place the cache in a directory shared by several systems.

  The table cache can operate from a read-only directory because a failed cache write leaves the measurement available in memory. Compiled kernels share the same cache path and require writes, so a shared cache should normally be writable.

Two additional lines appear when relevant. Message `table: identity off` confirms that the unchanged choice is disabled. Message `table: template on` counts words dropped because they matched no table entry. hashcat reports those separately from words excluded by hash-mode length limits.

## 7. Seeing which lines fired

Option `--debug-mode` records how each cracked candidate was constructed. Its first five modes normally report the rule responsible for a crack, but a table attack has no rules. For a feed-based attack, hashcat fills that field with information from the feed, so every debug mode can report the table entries that fired:

```
$ hashcat -m 0 -a 5 hashes.txt words.txt t.table --debug-mode 6 --debug-file fired.txt
$ cat fired.txt
footballman:football->basketball,man->woman:basketballwoman
footballman:football->basketball:basketballman
footballman:man->woman:footballwoman
sunshine::sunshine
```

The three fields are the base word, the substitutions that fired and the resulting candidate. Only substitutions that changed the word are listed. Including unchanged choices for every covered token would obscure the transformations that mattered. An empty middle field identifies an unchanged candidate.

Debug mode 6 produces the format above, using the same three fields as mode 4. The other modes pick their own: mode 1 writes the substitutions alone, mode 2 the base word alone, mode 3 both without the candidate, and mode 5 adds the wordlist position field, which an attack with a feed fills with `<generic>` rather than a number. None of them needs `-r` here.

Every debug mode requires the device engine to recover the substitutions from the cell supplied to the GPU. A slow hash using the host engine has no such cell, so the middle field remains empty.

A table too wide for one cell has its leading substitutions made on the host and carried in the base word, so those do not appear in the middle either. The base word is printed beside them, so the two together still account for the candidate.

Combining rules with a table makes this feed-specific debug information unavailable. Stacking rules gives up the feed's own kernel, so the table's candidates become the base words that the rules work on. The first five modes go back to reporting the rule, and the base word they name is the table's output rather than the wordlist entry. Mode 6 has no cell left to read, so its middle field is empty.

## 8. Notes

Rules given with `-r` work with the table attack. Stacking rules gives up the feed's own kernel for the attack mode 0 one, which costs the speed the table attack gets from expanding inside the hash kernel.

The tokenizer matches bytes rather than characters, so a source containing only a UTF-8 continuation byte could match inside a character and produce invalid UTF-8. Avoid such entries. Byte matching preserves tables written for single-byte encodings.

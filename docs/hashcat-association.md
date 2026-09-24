# The Association Attack

The association attack derives guesses for each hash from the contextual data stored with that hash. It can run with only the hash file:

```
hashcat -m 500 -a 9 users.hash
```

Every other attack tries every candidate against every hash. This one pairs them: the first word goes to the first hash and nowhere else. A hash file of a million accounts is therefore a million separate small attacks rather than one enormous one, and the cost of the run is the number of hashes times the number of guesses per hash, not times the size of a wordlist.

## 1. What it is for

People put themselves into their passwords. An account called `j.smith` has `smith123` and `Jsmith2024` in reach of a few thousand guesses, and no wordlist finds them any faster than it finds anything else, because a wordlist has no idea which line belongs to which hash.

The same attack also works with hash formats that carry context other than an account name. A WPA capture has no account names, but it does contain a user-selected network name and two MAC addresses from which a factory password may have been derived. `-m 22000` hands those over, so the same command works:

```
hashcat -m 22000 -a 9 handshakes.hc22000
```

The association attack does not replace a wordlist attack. It guesses only candidates derived from the context in the hash file. It is most useful after a targeted rule attack and before a large wordlist, or when the hashes are too slow for a broad wordlist attack.

## 2. The two forms

**Given only a hash file**, hashcat takes the words out of it. The line is split at the first separator, the part in front is the account name, and the part behind is the hash:

```
alice:1a1dc91c907325c69271ddf0c944bc72:s0
j.smith:e10adc3949ba59abbe56e057f20f883e:s1
```

Option `-p` sets a different separator. A hash mode that carries its own words, such as `-m 22000`, needs no separator and no account name.

**Given a hash file and a wordlist**, hashcat pairs them by line number instead:

```
hashcat -m 500 -a 9 hashes.txt words.txt
```

Line 3 of the wordlist is tried against line 3 of the hash file and no other. The two files have to have the same number of lines, and hashcat refuses the run if they do not.

**Every hash needs a salt of its own.** The pairing is what the attack is, and an unsalted hash mode has one salt for all of its hashes, so no pairing exists. hashcat refuses those rather than guessing what was meant.

## 3. Where the words come from

The hash-mode module selects the source because only it can interpret its salt and extended salt. A module that leaves the hook at `MODULE_DEFAULT` uses the generic fallback, which splits the account name preceding the hash into words.

`j.smith` becomes, in this order:

```
smith      the longest run of letters, which for a login is usually the surname
jsmith     every run of letters laid end to end
j.smith    the name as it was written
```

There is no `j` in that list. A piece shorter than three characters is dropped, because an initial is not a password and every hint costs a round for every account in the file rather than only for the name it came from. The floor applies to every piece a split produces, at a separator and at a case or digit boundary alike, and to the joined form.

The name as it was written is the exception, so a short account name is still usable: `jo` produces only `jo`. For example, `a.b.c` gives `abc` and `a.b.c` because the pieces are too short but the joined form is not.

A digit run such as the `2024` in `user2024` comes after the letters, and the joined form is letters only, so `user2024` gives `user` rather than `user2024`. Name `JEdgarHoover` is also split at its case boundaries, into `Edgar` and `Hoover`, and the `J` is dropped for the same reason as the `j` above. A name that falls into more pieces than the list holds keeps the ones nearest the front, and the name as it was written always has a place of its own.

The order matters because the first word is cheapest to try and each later word adds cost. The attack therefore prioritizes the word most likely to form the stem of a password. This ordering is a heuristic. Measuring it would require a corpus that pairs account names with the corresponding passwords.

`-m 22000` answers with the network name first, because it is the only one of the three that a human chose, and then both MAC addresses as the twelve hex digits they are usually written as.

A passwd file contains two additional fields that describe the person rather than the account, and the attack uses both. The gecos field provides the real name, which is often the best available hint and the source abbreviated by the login. Only the text before its first comma is used because the remaining fields usually contain an office and phone number.

For the home directory, the attack keeps only the final path component. Prefixes such as `home`, `export` and `users` are shared by many accounts and would add an unhelpful round for all of them.

```
jsmith:$1$...:1000:1000:John Smith,,,:/home/jsmith:/bin/bash
```

gives `jsmith`, `Smith`, `JohnSmith`, `John` and `John Smith`. The three fields share one list, so a home directory ending in the login, which is nearly every home directory, does not add a duplicate value. Every other hash list format carries the login alone.

A private plugin can answer for itself. See `module_hash_hints` in `docs/hashcat-plugin-development-guide.md`.

## 4. The phases

A phase is one way of turning those words into candidates. They run cheapest first, so a run stopped early has spent its time on the guesses most likely to land.

| phase | what it does | ends |
|---|---|---|
| `words` | every word as it stands | yes |
| `rules` | every word through a rule list | yes |
| `pcfg` | every word through a probability-ordered grammar | no |

**All three are enabled by default.** Each successive phase explores a broader and more expensive candidate set. If the run is stopped early, the available time has been spent on the least expensive guesses first.

**`words`** is every word of every account, unmodified, and no more than that. It is a few guesses per account and it is where a password that is just the surname falls.

**`rules`** runs the first 1000 rules of `rules/rockyou-30000.rule`, which is ordered by how often each rule won, over every word of every account. The first rule is the no-op rule, so this phase repeats the unmodified candidates from the preceding phase. For an account with eight words, this adds eight duplicates among 8,008 guesses. Avoiding them would make the contents of the rules phase depend on which other phases were selected.

Inside the rules phase the order over its two axes is a merge and not a nesting. Both axes are priced the same way, by the log of the rank, so the eighth word of a name costs what the eighth rule costs and neither axis is spent before the other is touched. Nesting would put all thousand rules on the first word before the second word was tried at all. The no-op rule is the exception: it is priced at zero on any word, which is what puts all of an account's words in the first few guesses of the run.

Rejects are what make a list that long affordable. hashcat's host side rule engine implements the whole reject set, `<6`, `>6`, `~/?u`, `~(?l` and the rest, which a `-r` file can never carry because the rule kernel has no rejection at all. A rejected word is discarded before its candidate is built, and building a candidate is what this attack spends its time on.

**`pcfg` does not end.** It takes the same words and runs them through the `hints` ruleset, which is hashcat's trained grammar with the words taken out of it, so every candidate is one of the account's own words with something around it. `smith` reaches `smith123`, `Smith2024`, `SMITH!`, `1smith` and `smithsmith`, ordered by how likely the training data ranks those shapes. Section 4 of `docs/hashcat-pcfg.md` describes that ruleset.

Because the grammar has no end, the default `-a 9` attack also runs indefinitely. Specify the desired phases when a bounded attack is required:

```
hashcat -m 500 -a 9 users.hash phases=words,rules
```

That is the bounded attack: every word, then every word through a thousand rules, then done.

**Rules supplied with `-r` apply after the active phase.** The phase builds a candidate on the host, then the rules kernel amplifies it on the device. User-supplied rules therefore multiply the candidates produced by the phase instead of replacing its transformations. This also helps fill a fast device, as described in section 8.

## 5. Settings

Settings are `key=value` arguments, the same convention every attack-mode 8 feed uses. A phase runs a feed of its own, so a setting names the phase it belongs to:

```
hashcat -m 500 -a 9 users.hash rules.rulemax=300 pcfg.hintaccount=4
```

| setting | default | what it does |
|---|---|---|
| `phases` | `words,rules,pcfg` | which phases to run, comma separated, cheapest first |
| `words.hints` | 8 | how many words of an account the words phase uses, at most |
| `rules.rulefile` | `rules/rockyou-30000.rule` | the rule list the rules phase applies, best first |
| `rules.rulemax` | `1000` | how many rules of it to use |
| `rules.hints` | 8 | the same, for the rules phase |
| `pcfg.hintaccount` | 8 | the same, for the grammar phase |

Anything else a pcfg attack takes works with the `pcfg.` prefix as well, so `pcfg.costmax=48` and `pcfg.scale=4` mean there what they mean in `docs/hashcat-pcfg.md`. The exceptions are the three that select a hint ruleset's word source. This phase obtains its hints from the hashes, so `pcfg.hintwords` and `pcfg.hintfile` are rejected and `pcfg.hintrank` has no supplied list to rank.

The words phase applies no rules, so `words.rulefile` and `words.rulemax` are refused as well rather than accepted and never read.

A setting hashcat does not recognise is reported rather than ignored, and so is one given twice, one written without the prefix that names its phase, and one prefixed for a phase this run is not doing.

## 6. The lines it prints

```
Guess.Base.......: Feed (users.hash, rules phase: rules/rockyou-30000.rule)
Guess.Queue......: 2/3 (66.66%)
Progress.........: 100000000/100000000 (100.00%)
```

The hash file is the base, because the words come out of it, and the phase is what this part of the run does to them. Status field `Guess.Queue` reports the current phase and total phase count.

`Progress` covers the complete run rather than only the current phase, while its total includes every phase sized so far. Sizing requires opening the phase, and loading the grammar takes several seconds, so the total grows as each phase begins instead of being known at startup. In return, progress never resets or moves backward.

On the grammar phase the total is astronomical and the percentage sits near zero, which is correct. Status field `Time.Estimated` reads `Next Big Bang`, which accurately describes a phase with no end.

## 7. Seeing what made a candidate

`--debug-mode` works here without `-r`, and it is how you find out which of the thousand rules is earning its place:

```
hashcat -m 500 -a 9 users.hash --debug-mode 1 --debug-file=found.rules
```

The rules phase writes the rule it applied:

```
$1 $2 $3
$1 $2
```

The grammar phase writes the shape it used instead, because a grammar has no rule to name:

```
H1D3
H1H1
```

Marker `H` represents the account's own word, while the remaining fields describe what the grammar placed around it, so `H1D3` is a word followed by three digits. Mode 4 writes the same field between the base word and the candidate, and mode 6 writes it whether or not the run has rules.

**With `-r`, the output names the user-supplied rule instead**, because the kernel records the ordinary rule it applied.

**The recorded base word is the completed candidate**, not the hint word transformed by the phase. The association attack applies its phase transformations on the host before hashcat receives the candidate. Debug modes 2 and 4 therefore repeat the candidate where another attack would show its source word.

## 8. Speed

**The salt count is what fills the card.** A round is one pass over the salts, and a launch may never straddle a round boundary, so the number of hashes in the file is the whole of what one launch has to spread across the lanes. This attack is built for a salted list, and the more salts it carries the better it runs. Four accounts measure 8 kH/s. The same attack on 20000 accounts measures 23.4 MH/s.

That is the number to check first when a run seems slow. It is a property of the hash file rather than of the hash mode, and no setting moves it.

Every candidate is built on the host, because the attack keeps the ordinary rules kernel so that `-r` works. On 20000 accounts against `-m 10`, on two RX 7900 XTX, the rules phase measures 23.4 MH/s and the grammar phase 15.8 MH/s.

On a fast hash you want `-r` as well, and it multiplies on the card rather than on the host. The same run with `-r rules/best66.rule` measures 1450.9 MH/s, which is the host producing the same candidates it produced before and the card turning each of them into sixty-odd.

On a slow hash none of this matters, because the card is the limit whatever the host does.

## 9. Notes

* **A cracked password need not appear in any file.** The words are cut out of the hash file and the phases build on them, so no file holds them to grep.

* **`--skip` and `--limit` are refused with more than one phase**, because each phase is a separate round with its own keyspace.

* **The potfile is disabled for this attack.** A password that cracked one account is not a candidate for another, so writing it to the potfile would add no candidate and reading it would match none.

* **The account name is not tried against any other hash.** That is the whole point, and it is also the limitation: if two people share a password and only one of them has it in their account name, only one of them falls.

* **Options `--stdout` and `--keyspace` cannot answer for this attack.** Both of them skip loading the hash file, and the hash file is where the candidates come from. Option `--debug-mode` shows what a run is trying.

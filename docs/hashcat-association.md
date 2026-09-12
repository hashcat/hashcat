# The Association Attack

The association attack guesses one hash at a time, from what the hash file already carries about that hash. It needs only the hash file:

```
hashcat -m 500 -a 9 users.hash
```

Every other attack tries every candidate against every hash. This one pairs them: the first word goes to the first hash and nowhere else. A hash file of a million accounts is therefore a million separate small attacks rather than one enormous one, and the cost of the run is the number of hashes times the number of guesses per hash, not times the size of a wordlist.

## 1. What it is for

People put themselves into their passwords. An account called `j.smith` has `smith123` and `Jsmith2024` in reach of a few thousand guesses, and no wordlist finds them any faster than it finds anything else, because a wordlist has no idea which line belongs to which hash.

This is also the attack for a hash that carries something other than a name. A WPA capture has no account names at all, and it does have a network name that somebody typed and two MAC addresses that a factory password may be built from. `-m 22000` hands those over, so the same command works:

```
hashcat -m 22000 -a 9 handshakes.hc22000
```

What it is not is a replacement for a wordlist. It only ever guesses things built out of what the hash file told it, so it is the attack to reach for after a targeted rule attack has failed and before a large wordlist, or when the hashes are slow enough that a large wordlist is out of the question.

## 2. The two forms

**Given only a hash file**, hashcat takes the words out of it. The line is split at the first separator, the part in front is the account name, and the part behind is the hash:

```
alice:1a1dc91c907325c69271ddf0c944bc72:s0
j.smith:e10adc3949ba59abbe56e057f20f883e:s1
```

`-p` sets a different separator. A hash mode that carries its own words, such as `-m 22000`, needs no separator and no account name.

**Given a hash file and a wordlist**, hashcat pairs them by line number instead:

```
hashcat -m 500 -a 9 hashes.txt words.txt
```

Line 3 of the wordlist is tried against line 3 of the hash file and no other. The two files have to have the same number of lines, and hashcat refuses the run if they do not.

**Every hash needs a salt of its own.** The pairing is what the attack is, and an unsalted hash mode has one salt for all of its hashes, so no pairing exists. hashcat refuses those rather than guessing what was meant.

## 3. Where the words come from

The module decides, because only the module can interpret its own salt and esalt. A module that leaves the hook at MODULE_DEFAULT gets the fallback that works for every mode: the account name in front of the hash, cut into words.

`j.smith` becomes, in this order:

```
smith      the longest run of letters, which for a login is usually the surname
jsmith     every run of letters laid end to end
j.smith    the name as it was written
```

There is no `j` in that list. A piece shorter than three characters is dropped, because an initial is not a password and every hint costs a round for every account in the file rather than only for the name it came from. The floor applies to every piece a split produces, at a separator and at a case or digit boundary alike, and to the joined form.

The name as it was written is the exception, so a short account name is still usable: `jo` gives `jo` and nothing else. `a.b.c` gives `abc` and `a.b.c`, since the pieces are too short but the joined form is not.

A digit run such as the `2024` in `user2024` comes after the letters, and the joined form is letters only, so `user2024` gives `user` rather than `user2024`. `JEdgarHoover` is cut on its case boundaries as well, into `Edgar` and `Hoover`, and the `J` is dropped for the same reason as the `j` above. A name that falls into more pieces than the list holds keeps the ones nearest the front, and the name as it was written always has a place of its own.

The order matters because the first word is the cheapest to try and each one behind it costs a little more, so the run spends most of its time on the word most likely to be the stem of a password. The ordering is a judgement rather than a measurement: measuring it needs a corpus of account names beside the passwords those people chose.

`-m 22000` answers with the network name first, because it is the only one of the three that a human chose, and then both MAC addresses as the twelve hex digits they are usually written as.

A passwd file carries two more fields that describe the person rather than the account, and both are used. The gecos field holds the real name, which is the best hint the file has and the one a login usually abbreviates, and it is cut at its first comma because what follows is an office and a phone number. The home directory keeps only its last component, since `home`, `export` and `users` are the same for every account in the file and each would cost a round for all of them.

```
jsmith:$1$...:1000:1000:John Smith,,,:/home/jsmith:/bin/bash
```

gives `jsmith`, `Smith`, `JohnSmith`, `John` and `John Smith`. The three fields share one list, so a home directory ending in the login, which is nearly every home directory, adds nothing twice. Every other hash list format carries the login alone.

A private plugin can answer for itself. See `module_hash_hints` in `docs/hashcat-plugin-development-guide.md`.

## 4. The phases

A phase is one way of turning those words into candidates. They run cheapest first, so a run stopped early has spent its time on the guesses most likely to land.

| phase | what it does | ends |
|---|---|---|
| `words` | every word as it stands | yes |
| `rules` | every word through a rule list | yes |
| `pcfg` | every word through a probability ordered grammar | no |

**All three are the default.** Each is worth more than the one in front of it and costs more, and a run stopped at any point has spent what it had on the cheapest guesses left.

**`words`** is every word of every account, unmodified, and no more than that. It is a few guesses per account and it is where a password that is just the surname falls.

**`rules`** runs the first 1000 rules of `rules/rockyou-30000.rule`, which is ordered by how often each rule won, over every word of every account. The first rule of that file is the do-nothing rule, so this phase also tries every word unmodified, which means it repeats the phase in front of it. That is eight repeats in eight thousand and eight on an eight word account, and the alternative is a phase whose content depends on which other phases you asked for.

Inside the rules phase the order over its two axes is a merge and not a nesting. Both axes are priced the same way, by the log of the rank, so the eighth word of a name costs what the eighth rule costs and neither axis is spent before the other is touched. Nesting would put all thousand rules on the first word before the second word was tried at all. The do-nothing rule is the exception: it is priced at zero on any word, which is what puts all of an account's words in the first few guesses of the run.

Rejects are what make a list that long affordable. hashcat's host side rule engine implements the whole reject set, `<6`, `>6`, `~/?u`, `~(?l` and the rest, which a `-r` file can never carry because the rule kernel has no rejection at all. A rejected word is discarded before its candidate is built, and building a candidate is what this attack spends its time on.

**`pcfg` does not end.** It takes the same words and runs them through the `hints` ruleset, which is hashcat's trained grammar with the words taken out of it, so every candidate is one of the account's own words with something around it. `smith` reaches `smith123`, `Smith2024`, `SMITH!`, `1smith` and `smithsmith`, ordered by how likely the training data ranks those shapes. Section 4 of `docs/hashcat-pcfg.md` describes that ruleset.

Because the grammar does not end, neither does `-a 9` by default. It is the part of this attack worth having, and leaving it behind a setting would give the output no sign of it. Name the phases you want if you would rather the run finished:

```
hashcat -m 500 -a 9 users.hash phases=words,rules
```

That is the bounded attack: every word, then every word through a thousand rules, then done.

**`-r` still works and stacks on top of whichever phase is running.** The phase builds a candidate on the host and the rules kernel multiplies it on the card, so the rules a phase applies and the rules you bring multiply rather than replace each other. It is also what fills a fast card: see section 8.

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

Anything else a pcfg attack takes works with the `pcfg.` prefix as well, so `pcfg.costmax=48` and `pcfg.scale=4` mean there what they mean in `docs/hashcat-pcfg.md`. The exceptions are the three that select a hint ruleset's word source. This phase takes them from the hashes, which is the whole of what it is, so `pcfg.hintwords` and `pcfg.hintfile` are refused and `pcfg.hintrank` has no supplied list to rank.

The words phase applies no rules, so `words.rulefile` and `words.rulemax` are refused as well rather than accepted and never read.

A setting hashcat does not recognise is reported rather than ignored, and so is one given twice, one written without the prefix that names its phase, and one prefixed for a phase this run is not doing.

## 6. The lines it prints

```
Guess.Base.......: Feed (users.hash, rules phase: rules/rockyou-30000.rule)
Guess.Queue......: 2/3 (66.66%)
Progress.........: 100000000/100000000 (100.00%)
```

The hash file is the base, because the words come out of it, and the phase is what this part of the run does to them. `Guess.Queue` reports which phase of how many.

`Progress` counts the whole run rather than the current phase, and the total beside it is everything hashcat has sized so far. Sizing a phase means opening it, and the grammar takes a few seconds to load, so the total grows when a phase opens rather than being known at the start. What that buys is a progress that never resets and never goes backwards.

On the grammar phase the total is astronomical and the percentage sits near zero, which is correct. `Time.Estimated` reads `Next Big Bang`, which is the honest answer for a phase with no end.

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

`H` is the account's own word and the rest is what the grammar put around it, so `H1D3` is a word followed by three digits. Mode 4 writes the same field between the base word and the candidate, and mode 6 writes it whether or not the run has rules.

Two things to know about the layout here. **With `-r`, your rule is named instead**, because then there is a rule in the ordinary sense and the kernel records which one it was. And **the base word hashcat records is the finished candidate**, not the word the rule was applied to, because this attack applies its rule on the host before hashcat ever sees the candidate. So modes 2 and 4 repeat the candidate where another attack would show you what it was built from.

## 8. Speed

**The salt count is what fills the card.** A round is one pass over the salts, and a launch may never straddle a round boundary, so the number of hashes in the file is the whole of what one launch has to spread across the lanes. This attack is built for a salted list, and the more salts it carries the better it runs. Four accounts measure 8 kH/s. The same attack on 20000 accounts measures 23.4 MH/s.

That is the number to check first when a run seems slow. It is a property of the hash file rather than of the hash mode, and no setting moves it.

Every candidate is built on the host, because the attack keeps the ordinary rules kernel so that `-r` works. On 20000 accounts against `-m 10`, on two RX 7900 XTX, the rules phase measures 23.4 MH/s and the grammar phase 15.8 MH/s.

On a fast hash you want `-r` as well, and it multiplies on the card rather than on the host. The same run with `-r rules/best66.rule` measures 1450.9 MH/s, which is the host producing the same candidates it produced before and the card turning each of them into sixty-odd.

On a slow hash none of this matters, because the card is the limit whatever the host does.

## 9. Notes

* **A cracked password need not appear in any file.** The words are cut out of the hash file and the phases build on them, so no file holds them to grep.

* **`--skip` and `--limit` are refused with more than one phase**, the same way they are refused for several wordlists.

* **The potfile is disabled for this attack.** A password that cracked one account is not a candidate for another, so writing it to the potfile would add no candidate and reading it would match none.

* **The account name is not tried against any other hash.** That is the whole point, and it is also the limitation: if two people share a password and only one of them has it in their account name, only one of them falls.

* **`--stdout` and `--keyspace` cannot answer for this attack.** Both of them skip loading the hash file, and the hash file is where the candidates come from. `--debug-mode` is the way to see what a run is trying.

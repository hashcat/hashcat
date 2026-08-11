
# Introducing Attack-Mode 8: Generic Password Candidate Generator Mode

Attack-Mode 8 is a generic interface that allows hashcat users to customize the password candidate input channel with their own code, most often to implement custom password generator logic.

Hashcat includes several embedded attack modes: 0, 1, 3, 6, 7, 9, and 12. Each attack mode represents a specific password candidate generator implementation. These embedded generators were designed primarily to run efficiently on GPUs. For example, they can read a wordlist and apply rules, generate a virtual wordlist from a mask, or combine both. The purpose of these generators is that they support a multiplier logic. Multiplier logic helps work around the PCIe bottleneck and ensures maximum performance when attacking very fast hashes.

For slow hashes, however, overcoming the PCIe bottleneck is less important, and other features become more useful. Their focus is usually not on multiplier logic but on candidate quality, and therefore they can be considered "advanced" generators. In our terminology, any generator that does not fit into the existing multiplier logic is defined as an "advanced" password generator.

Examples of advanced generators include:

- Logic based systems for contextualized passwords (too complex pattern for normal rules)
- Statistical models that adapt dynamically using feedback loops (omen, pcfg, ...)
- AI driven candidate generation (passgan, ...)
- Reading data from a network stream
- Your own ideas...

---

## 1. Usage

When starting an attack-mode 8 session, the user must specify a plugin as first parameter. This is by design to provide flexibility. Attack-mode 8 does not assign numbers to specific generators but instead lets the user name a plugin. This makes it possible to have an unlimited number of plugins, including custom plugins that are not part of hashcat's base package.

Since there are now multiple plugin types in hashcat, we need naming to distinguish them. Password generator plugins are called `feeds`, and the feeds we provide can be found in the "feeds" folder.

Typically, a feed requires a parameter to operate, and these parameters are passed from the hashcat command line to the feed. For example, the demonstration feed `feed_wordlist.so` reimplements the traditional `-a 0` attack. In classical attack-mode 0 the user specifies a path to a wordlist:

```
./hashcat -m 0 example0.hash -a 0 example.dict
```

In attack-mode 8 we always specify as first parameter the feed, and all other parameters are passed to the feed. So we need to write the command line like this:

```
./hashcat -m 0 example0.hash -a 8 wordlist example.dict
```

A feed is named, not pathed, the same way `-m 0` names a module. Hashcat looks under the `feeds/` folder of its shared directory and tries `feed_<name>`, then `rust_<name>`, then `<name>`. If none of those exist, the name is used as a path, so a feed you built yourself somewhere else still works:

```
./hashcat -m 0 example0.hash -a 8 /tmp/myfeed.so example.dict
```

In this example, the feed handles the next parameters `example.dict`. What it does with these parameters depends entirely on the feed design. In this case, the feed opens and reads the wordlist. Another feed could instead connect to a network socket and accept an IP address, for example.

The wordlist feed takes as many wordlists and directories as you give it, and lays them end to end into a single keyspace:

```
./hashcat -m 0 example0.hash -a 8 wordlist first.dict second.dict /path/to/dictdir
```

A directory contributes the files directly inside it, in name order. Because this is one keyspace rather than one attack per file, `--skip` and `--limit` keep working across the whole set. Attack-mode 0 has to refuse them as soon as it is given more than one dictionary.

The status display names the feed on the `Guess.Base` line. A feed may name what it is generating from rather than itself, so the wordlist feed shows `Guess.Base.......: Feed (example.dict)`.

Keep in mind that hashcat always parses the full command line first. All options are interpreted by hashcat's getopt process, and only the `loose parameters` are forwarded to the feed.

## 2. Main Features

### 2.1. Parallelization

We debated how useful such an interface is, given that hashcat already provides a generic `STDIN` interface for connecting custom generators. However, there are several reasons why STDIN is good but not optimal.

With STDIN, there is only one input channel feeding multiple output channels. Output channels in this context mean compute devices. Hashcat spawns a unique thread for each compute device so it can handle devices of different speeds. This requires synchronization. The same is true for attack modes 0, 1, 3, 6, 7, and 12, but the difference is that in those modes there is no single input channel.

For example, when attack-mode 0 is run on four GPUs, hashcat spawns four threads. Each thread opens its own file handle to the wordlist and reads independently. The synchronizer only tells each thread where to start and stop, so parallelization works smoothly.

With STDIN, this is not possible. A single master process must handle the file handle, reading enough entries to fill one compute device before moving on to the next. On systems with many GPUs, this leaves most GPUs idle if the generator cannot supply candidates quickly enough. In addition, STDIN requires one CPU thread to parse every line sequentially, detect line endings, and check for end of file. This creates a bottleneck and heavy pressure on a single CPU core.

Attack-mode 8 solves this problem by supporting parallelization on both the compute device side and the generator side.

### 2.2. Integration into hashcat

Embedding or shipping the candidate generator with hashcat simplifies integration with third party overlays. For example, when using Hashtopolis, distributing an external generator to agents adds extra work beyond distributing the hashcat package itself. With attack-mode 8, everything remains inside the standard hashcat .7z package.

Only one program needs to run, and no pipe is required between two processes. There is no need to monitor two programs or handle unexpected shutdowns.

Special flags such as `--skip` (-s), `--limit` (-l), `--keyspace`, `--total-candidates`, `--progress-only`, and `--speed-only` also become accessible and standardized.

## 3. Optional Features

### 3.1. Keyspace support

The STDIN support is also flexible because the generator does not need to specify keyspace size at startup. However, this disables hashcats progress reporting and ETA calculation and it complicates dispatcher scheduling. Knowing the maximum keyspace allows the dispatcher to size work packages more efficiently, especially for mixed speed devices. For this reason, generators that cannot report total keyspace have never been allowed in classic attack modes.

Attack-mode 8 allows flexibility by making keyspace `optional`. Each feed can report whether it supports keyspace, and hashcat will enable features dynamically.

### 3.2. Wordlist modifiers

When loading wordlists, hashcat applies internal modifiers `before` sending candidates to the compute device. These are:

* $HEX[] interpretation
* --rules-left (-j)
* --encoding-from and --encoding-to

These modifiers are always enabled with STDIN, but in a feed they can be disabled if not needed. For example, mask based feeds or candidates already in UTF-16BE do not require them. Disabling modifiers can significantly improve performance, especially when cracking fast hashes without amplification.

### 3.3. Restore functionality

A generator feeding candidates through STDIN may or may not support session restore.

With attack-mode 8, restore is guaranteed. Hashcat can seek directly to the needed candidate within the generator. Depending on the generator architecture, seeking may be slow, but no third program is required to emulate restore.

## 4. Interface Design

The strength of this feature lies in the simplicity of its interface. We designed it to be simple to encourage users to implement their own custom feeds.

By default, we provide skeletons for `C` and `Rust`. We also experimented with `Python` and `Lua`. Python was problematic because of the Global Interpreter Lock. Even so called non-GIL builds introduced mutex overhead that slowed threading. Once Python supports a true mutex free runtime, we may revisit it. Lua worked immediately and was enjoyable to implement, but it was too slow for our purposes. A Lua or `LuaJIT` skeleton may still be added if there is demand. Rust performs as well as C, and maximum performance is essential for this interface.

If you are interested in seeing what the interface looks like, or you want skeletons to use with AI, visit the developer documents: TBD

## 5. Benchmark

We expected a clear speed improvement compared to STDIN, but what we did not expect was a speed advantage over the traditional -a 0 attack.

To prepare both modes, replace with any large wordlist locally.

First clear caching databases for kernels and dictionary stats. Note the new `seekdbs` folder, used by feed_wordlist.so to enable fast seeks to specific offsets in the wordlist. It acts as a sparse line to byte offset database and also as a keyspace hint, similar to dictstat2.

```
rm -rf kernels hashcat.dictstat2 seekdbs
```

Next, rebuild the caching databases for both attack modes, creating a realistic environment:

```
./hashcat -m 900 --force -u 1 -n 1024 -T 32 example0.hash -d 1,2 $HOME/dict/hashmob.net_2025-07-06.found
./hashcat -m 900 --force -u 1 -n 1024 -T 32 example0.hash -d 1,2 -a8 feeds/feed_wordlist.so $HOME/dict/hashmob.net_2025-07-06.found
```

Now compare runtimes (run each command twice to account for OS-level caching):

```
time ./hashcat -m 900 --self-test-disable --force -u 1 -n 1024 -T 32 example0.hash -d 1,2 -a0 $HOME/dict/hashmob.net_2025-07-06.found

real    0m53.462s
user    1m28.619s
sys     0m6.824s

time ./hashcat -m 900 --self-test-disable --force -u 1 -n 1024 -T 32 example0.hash -d 1,2 -a8 feeds/feed_wordlist.so $HOME/dict/hashmob.net_2025-07-06.found

real    0m29.901s
user    0m48.229s
sys     0m2.284s
```

Notes:

* This is an unrealistic test, since hashcat is not normally run on raw wordlists without amplifiers for fast hashes like NTLM. Unamplified attacks are mainly practical for slow hashes. Still, this benchmark shows the impact of the new submodule.
* A multi GPU system is required for meaningful results. The more GPUs the better, as long as they are fast enough not to bottleneck. Use only fast discrete GPUs, not integrated GPUs or APUs.
* These results were produced on a system with two 7900 XTX GPUs and a Ryzen 9 7950X with AVX 512, with enough RAM to cache the full wordlist.

## 6. Amplifiers

One final note. Attack-mode 8 reuses attack-mode 0 kernels. That means you can optionally add `-r` rules, including stacked rules, exactly as in -a 0 mode.

This also makes the mode useful for `fast hashes` and allows very high speeds. Ideally a feed is designed so that it is aware that users can add rules and returns candidates with this in mind. Even better, the feed developer may publish a feed with a matching ruleset, but this is not required.


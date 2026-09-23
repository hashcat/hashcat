
# Introducing Attack-Mode 8: Generic Password Candidate Generator Mode

Attack-Mode 8 is a generic interface that allows hashcat users to customize the password candidate input channel with their own code, most often to implement custom password generator logic.

Hashcat includes several embedded attack modes: 0, 1, 3, 4, 5, 6, 7, 9, and 12. Each attack mode represents a specific password candidate generator implementation. These embedded generators were designed primarily to run efficiently on GPUs. For example, they can read a wordlist and apply rules, generate a virtual wordlist from a mask, or combine both. The purpose of these generators is that they support a multiplier logic. Multiplier logic helps work around the PCIe bottleneck and ensures maximum performance when attacking very fast hashes.

For slow hashes, however, overcoming the PCIe bottleneck is less important, and other features become more useful. Their focus is usually not on multiplier logic but on candidate quality, and therefore they can be considered "advanced" generators. In our terminology, any generator that does not fit into the existing multiplier logic is defined as an "advanced" password generator.

Examples of advanced generators include:

- Context-aware systems whose patterns do not fit ordinary rules
- Statistical models that adapt through feedback
- AI-driven candidate generation
- Data read from a network stream
- Specialized generators for a particular investigation

---

## 1. Usage

When starting an attack-mode 8 session, the user must specify a plugin as the first parameter. This is by design to provide flexibility. Attack-mode 8 itself does not assign numbers to specific generators but instead lets the user name a plugin. This makes it possible to have an unlimited number of plugins, including custom plugins that are not part of hashcat's base package.

A feed that ships with hashcat can also be given an attack-mode number of its own. The PCFG feed has one: `-a 4 hashes.txt ruleset` is rewritten into `-a 8 hashes.txt pcfg ruleset` before anything downstream reads it, so the two spellings are the same attack. The table feed has `-a 5`, which was the number hashcat-legacy used for the same attack. See `hashcat-pcfg.md` and `hashcat-table.md` for those attacks, and the section on aliases in `hashcat-generic-attack-mode-development-guide.md` for how a feed gets a number.

Since there are now multiple plugin types in hashcat, we need naming to distinguish them. Password generator plugins are called `feeds`, and the feeds we provide can be found in the "feeds" folder.

Typically, a feed requires parameters, which hashcat passes from the command line. The shipped wordlist feed is also the implementation used by ordinary `-a 0`. With that shorter form, the user specifies a wordlist directly:

```
./hashcat -m 0 example0.hash -a 0 example.dict
```

The explicit attack-mode 8 form names the feed first and passes the remaining positional arguments to it:

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

A directory contributes the files directly inside it, in name order. Because this is one keyspace rather than one attack per file, `--skip` and `--limit` work across the whole set. Ordinary `-a 0` uses the same wordlist feed and has the same multi-source behavior.

The status display names the feed on the `Guess.Base` line. A feed may name what it is generating from rather than itself, so the wordlist feed shows `Guess.Base.......: Feed (example.dict)`.

Keep in mind that hashcat always parses the full command line first. All options are interpreted by hashcat's getopt process, and only the `loose parameters` are forwarded to the feed.

## 2. Main Features

### 2.1. Parallelization

We debated how useful such an interface is, given that hashcat already provides a generic `STDIN` interface for connecting custom generators. However, there are several reasons why STDIN is good but not optimal.

Standard input is one sequential stream. Hashcat now uses one reader thread to fill large blocks and lets device threads drain different blocks in parallel, so the old per-line mutex bottleneck is gone. The stream still cannot be counted or independently seeked, however: a position has meaning only if the same input is supplied again in the same order.

A purpose-built feed can do more. A wordlist feed, for example, opens independent file handles and seeks each device directly to its assigned range. A generator can also keep separate state per device or connect each device thread to its own data source. This is where attack mode 8 gains scalability beyond what a single stream can provide.

### 2.2. Integration into hashcat

Shipping a candidate generator with hashcat simplifies integration with third-party overlays. For example, when using Hashtopolis, distributing a separate executable to agents adds work beyond distributing the hashcat package. A bundled feed remains part of that package and runs inside the hashcat process.

Only one program needs to run, and no pipe is required between two processes. There is no need to monitor two programs or handle unexpected shutdowns.

Special flags such as `--skip` (-s), `--limit` (-l), `--keyspace`, `--total-candidates`, `--progress-only`, and `--speed-only` also become accessible and standardized.

## 3. Optional Features

### 3.1. Keyspace support

A feed may return an exact keyspace or report that it is unknown. An unknown keyspace is useful for streams and open-ended generators, but it prevents an exact progress denominator and ETA and makes range scheduling less direct. The stdin and random sample feeds both use this form.

A feed with a countable source should report its keyspace. Hashcat can then divide ranges among devices and apply `--skip` and `--limit` precisely. Efficient restore also depends on how directly `thread_seek()` can reach the requested offset.

### 3.2. Wordlist modifiers

Before sending wordlist candidates to a compute device, hashcat can apply:

* `$HEX[]` interpretation
* `--rule-left` (`-j`)
* `--encoding-from` and `--encoding-to`

The stdin and wordlist feeds enable these transformations. Another feed can decline the ones that do not apply. A mask feed, for example, does not need wordlist decoding. Avoiding unnecessary transformations reduces host overhead.

### 3.3. Restore functionality

A generator feeding candidates through STDIN may or may not support session restore.

Attack mode 8 gives every feed a `thread_seek()` entry point, but direct random access is not guaranteed. A wordlist can seek through its index, a deterministic generator may replay from its seed, and a stream reaches an offset only by receiving and discarding the same earlier candidates again. Restore is reliable only when the feed can reproduce the same candidate ordering.

## 4. Interface Design

The strength of this feature lies in the simplicity of its interface. We designed it to be simple to encourage users to implement their own custom feeds.

Hashcat provides feed skeletons in C and Rust. The interface is a small shared-library ABI, so another language can be used if it can export the same C-compatible symbols and data layouts.

See `hashcat-generic-attack-mode-development-guide.md` for the complete interface and both skeletons.

## 5. The wordlist feed and attack mode 0

Ordinary `-a 0` now uses the shipped wordlist feed for normal wordlist rounds. Naming the same feed explicitly with `-a 8 wordlist` is therefore not a faster variant of the current straight attack. It exposes the same reader through the generic interface. The explicit form is mainly useful when developing or comparing feeds.

The feed builds a sparse seek database under `cache/feeds/wordlist`. It maps candidate offsets to file positions, which lets each device seek directly to its assigned range and lets several wordlists or directories form one keyspace. Option `--cache-path` moves this cache together with hashcat's compiled-kernel cache. A shared, writable cache can avoid rebuilding the same index on every host that reads identical wordlists.

Standard input uses its own stdin feed. Per-round sources such as induction and loopback still use the legacy wordlist reader because the next file does not exist when the session starts.

## 6. Amplifiers

One final note. Attack-mode 8 reuses attack-mode 0 kernels. That means you can optionally add `-r` rules, including stacked rules, exactly as in -a 0 mode.

A feed may instead provide data for a device-side amplifier. The PCFG and table feeds do this. On a fast hash, hashcat passes the feed's base candidate and amplification cell to the mode's `OpenCL/mNNNNN_a4-pure.cl` or `_a4-optimized.cl` kernel, which creates the expanded candidates in device memory. Adding `-r` is still allowed, but it selects the feed's host generator and the attack-mode 0 kernel instead. See `hashcat-pcfg.md` and `hashcat-table.md` for the two attacks.

This also makes the mode useful for `fast hashes` and allows very high speeds. Ideally a feed is designed so that it is aware that users can add rules and returns candidates with this in mind. Even better, the feed developer may publish a feed with a matching ruleset, but this is not required.


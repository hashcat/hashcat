# Hashcat PCFG Attack Mode (`-a 10`)

**Attack mode 10** (`-a 10`) is a new hashcat attack mode that generates password candidates using **PCFG (Probabilistic Context-Free Grammar)** models. Instead of generating combinations blindly (like brute-force `-a 3`) or reading from a file (like dictionary `-a 0`), it learns the patterns and building blocks of real passwords from training data, then generates candidates that follow those patterns.

## Table of Contents

1. **Key Concepts** — Structures, terminals, keyspace, probability, burst, OMEN cost, AHF, and the full terminal types reference
2. **Command Line Options** — Complete reference of all `--pcfg-*` parameters: model management, generation control, AHF settings, encoding, and filters
3. **Internals** — How the model, training, statistics (`--pcfg-model-info`), and generation engine work. Detailed description of all 8 generation modes (0-7), OMEN types, interactive commands, cross-mode consistency, performance thresholds, PCFG loopback, session/restore/skip/keyspace, encoding support, and status display (PCFG.Settings)
4. **Source Architecture** — Map of source files and their responsibilities
5. **Usage Examples** — Ready-to-use command lines for training, cracking, merging, GPU modes, AHF, filters, loopback, encoding, and `--stdout`
6. **Limitations** — Known constraints and unsupported feature combinations

## Quick Start

```bash
# 1. Train a model from a wordlist (displays statistics and exits)
hashcat -a 10 --pcfg-train example.dict --pcfg-model-save example.dict.pcfg --pcfg-model-info

# 2. Crack hashes using the trained model
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg

# 3. (Optional) Preview generated passwords without cracking
hashcat -a 10 --pcfg-model example.dict.pcfg --stdout | head -100

# 4. (Optional) Inspect model statistics
hashcat -a 10 --pcfg-model example.dict.pcfg --pcfg-model-info
```

The PCFG engine provides 8 generation modes (`--pcfg-mode 0` to `7`), both CPU and GPU-accelerated, with different trade-offs between speed, ordering, and exploration. By default, mode 0 (Weighted Random) is used.

## Overview

The training module implements multiple normalization paths to handle malformed training data, aiming to produce the most accurate model possible.

The PCFG engine also supports different **OMEN** generation types, called **Interleaved** and **Classic**, and multiple generation modes (`--pcfg-mode`), allowing candidates to be generated weighted randomly, by probability, or following OMEN-specific ordering. These options provide finer control over how structures are enumerated and prioritized during the attack.

Both **CPU-based** and **GPU-accelerated** generators are available. GPU generators offload candidate production to CUDA/HIP/Metal/OpenCL kernels, providing significantly higher throughput on supported hardware. Two GPU-specific OMEN strategies are provided: **OMEN by Cost** (cost-first iteration, analogous to CPU OMEN) and **OMEN by Structure** (structure-first iteration, exhausting each structure across all costs before moving on). CPU modes use a linear iteration order with per-generator work-stealing for efficient thread synchronization.

A dedicated mode, called **Adaptive Hybrid-Fuzzing**, can also be enabled. In this mode, structures are generated either via second-order Markov chains (AHF Markov mode) or weighted random selection (AHF Random mode), using the terminals defined in the model. If the terminals selected to build a new structure are already present in the model but lack complete combinations for a given length, second-order Markov or weighted random generation is applied to those terminals as well.

This approach allows exploration of both structural and terminal spaces that are not represented in the original training set.

---

## 1. Key Concepts

### Structures, Terminals, and Keyspace

A **structure** describes the pattern of a password by breaking it into typed tokens. For example, the password `Password123!` is decomposed into the structure `C8 D3 S1`:

| Token | Type | Length | Meaning |
| :--- | :---: | :---: | :--- |
| `Password` | C (Capitalized) | 8 | Capitalized alphabetic word |
| `123` | D (Digits) | 3 | Numeric sequence |
| `!` | S (Special) | 1 | Special character |

Each token slot has a set of **terminals**: the actual values observed during training. For example, the D3 slot might contain terminals `123`, `456`, `789`, `000`, etc. The total number of unique terminal values in a slot is the **terminal count**.

The **keyspace** of a structure is the total number of password candidates it can produce, calculated as the product of terminal counts across all its token slots. For example, if C8 has 500 terminals, D3 has 200, and S1 has 30, the keyspace is 500 x 200 x 30 = 3,000,000.

The **probability** of a structure represents how frequently that pattern appears in the training data relative to all observed patterns.

### Burst, OMEN, and AHF

A **burst** controls how many candidates are generated before a mode-specific transition occurs. The burst size (`--pcfg-burst-size`, default 50000) has different semantics depending on the generation mode:

- **Modes 0, 1** (Weighted Random, AHF): burst defines how many terminals of a single token slot are iterated before re-evaluating the priority heap. AHF defaults to 25000 instead of 50000.
- **Modes 4, 6** (OMEN CPU): burst defines the maximum candidates per structure per loop iteration — used to chunk keyspace across threads.
- **Modes 5, 7** (OMEN GPU): burst defines the GPU dispatch batch window size.
- **Modes 2, 3** (Probability): burst has no effect — these modes use direct global indexing.

**OMEN** (Ordered Markov ENumeration) is an alternative generation strategy where each structure is assigned a **cost** representing how unlikely its terminal combination is. Lower cost = higher probability. The generator iterates from low to high cost, ensuring the most probable candidates across all structures are tried first.

**AHF** (Adaptive Hybrid-Fuzzing, `--pcfg-mode 1`) generates structures at runtime instead of using pre-computed ones from the model. It creates **synthetic terminals** — new values not seen in training — to explore beyond the original training set.

### Terminal Types Reference

Each token in a structure has a **type** that describes its character class. These IDs are used with the `--pcfg-token-types` filter.

| ID | Description | Example |
| :---: | :--- | :--- |
| **L** | Lowercase Alpha | `password` |
| **U** | Uppercase Alpha | `PASSWORD` |
| **M** | Mixed Case Alpha | `iPhONE` |
| **C** | Capitalized Alpha | `Password` |
| **D** | Digits | `123456` |
| **S** | Special | `!@#$%€` |
| **P** | Punctuation | `.,:;` |
| **W** | Whitespace / Separators | `_ -` |
| **Y** | Year (Range 1900-2050) | `2023` |
| **E** | Email Provider | `@gmail.com` |
| **K** | Keyboard Walk (Patterns) | `qwerty` |
| **R** | Character Repetitions | `111111` |
| **Q** | Logical Sequences | `abcdef` |
| **J** | Emoji | `🔥😎👽` |
| **A** | Latin Extended / Accents | `àêòèâàöèè` |
| **I** | Cyrillic | `солнышко` |
| **B** | Arabic / Persian | `١٢٣٤٥٦٧٨٩٠` |
| **H** | Asian / Hindi | `๑้นะทฟรสใแนท` |
| **G** | Greek | `διμιτρισ` |
| **V** | Hebrew | `המלצותוטיפים` |
| **X** | Generic Unicode | `ܛܣܕܗܣ` |

---

## 2. Command Line Options

### Model Management & Training

| Option                       | Type   | Description |
| :--------------------------- | :----: | :--- |
| `--pcfg-model`               | `File` | Path to a pre-trained PCFG model file (`.pcfg`). |
| `--pcfg-model-diff`          | `File` | Compare the model loaded with `--pcfg-model` against this second model and show differences, then exit. |
| `--pcfg-model-info`          | `-`    | Display detailed statistics about the loaded model and exit. |
| `--pcfg-model-save`          | `File` | Save the trained, merged or updated model to a specific file. |
| `--pcfg-model-update`        | `-`    | Update an existing model with new training data (requires both `--pcfg-model` and `--pcfg-train`). |
| `--pcfg-models-merge`        | `File` | Merge multiple model files into a single master model. |
| `--pcfg-train`               | `File` | Path to a dictionary file to train a new model. |
| `--pcfg-train-af-disable`    | `-`    | Disable the Admission Filter (used during training to filter out terminals that do not appear at least twice by default). |
| `--pcfg-train-af-threshold`  | `Num`  | Set the admission filter threshold (must be greater than 1, default: 2). |
| `--pcfg-train-df-disable`    | `-`    | Disable the Data Filters (used during training to trying to cleanup training data before add into model). |
| `--pcfg-train-format`        | `Num`  | Set train input format: Simple wordlist (0, default) or Weighted wordlist (1). |

### Generation Control

| Option                       | Type   | Applies to               | Description |
| :--------------------------- | :----: | :----------------------: | :--- |
| `--pcfg-burst-first`         | `-`    | Modes 0, 1               | Burst iterates on first token slot instead of last (default: last). |
| `--pcfg-burst-size`          | `Num`  | Modes 0, 1, 4-7          | Number of candidates per burst (default: `50000`, AHF default: `25000`). Semantic varies by mode (see Key Concepts). No effect on Probability (2, 3) modes. |
| `--pcfg-loopback`            | `-`    | `-a 0` only              | After the dictionary/wordlist attack completes, train a PCFG model from cracked passwords and run iterative PCFG attacks (see section 3, PCFG Loopback). |
| `--pcfg-mode`                | `Num`  | -                        | Select the candidate generation mode (see section 3 for details). |
| `--pcfg-omen-keyspace-max`   | `Num`  | Modes 4-7                | Skip structures with a keyspace exceeding NUM to prevent OMEN stalls. |
| `--pcfg-omen-cost-max`       | `Num`  | Modes 4-7                | Set the OMEN end cost (default: 100). |
| `--pcfg-omen-cost-min`       | `Num`  | Modes 4-7                | Set the OMEN start cost (default: 0). |
| `--pcfg-omen-max-alloc-perc` | `Num`  | Modes 5, 7               | Limit GPU large buffer allocation to this percentage of available memory (default: 100). |
| `--pcfg-omen-stats`          | `-`    | Modes 4-7                | Show detailed OMEN stats live and at session end. |
| `--pcfg-omen-type`           | `Num`  | Modes 4-7                | Set the OMEN type: Interleaved (0, default) or Classic (1). |
| `--pcfg-perf-threshold`      | `Str`  | Modes 2-7                | Automatically skip underperforming structures/costs/loops (see section 3 for format). |
| `--pcfg-shuffle`             | `-`    | Mode 0                   | Shuffle token order within structures (e.g., `C8D3S1` could become `D3C8S1`, generating different passwords). |
| `--pcfg-token-types`         | `Str`  | All                      | Filter structures by token types (e.g., `CD` only includes structures containing Capitalized and Digit tokens). |

### Adaptive Hybrid-Fuzzing Generation Control (`--pcfg-mode 1`)

| Option                       | Type   | Description |
| :--------------------------- | :----: | :--- |
| `--pcfg-ahf-terminals-min`   | `Num`  | Filter out AHF terminal types when the total number of terminals is below the specified threshold (NUM). |
| `--pcfg-ahf-type`            | `Num`  | Switch between Markov (0, default) and Random (1) AHF modes. |

### Additional filters (all generation modes)

| Option                       | Type   | Description |
| :--------------------------- | :----: | :--- |
| `--pcfg-keyspace-max`        | `Num`  | Skip structures with a per-structure keyspace exceeding NUM (also skips on overflow). Not applied in AHF mode. |
| `--pcfg-pw-complex`          | `-`    | Enforce Microsoft password complexity policy. |
| `--pcfg-pw-len-max`          | `Num`  | Skip structures generating passwords longer than NUM. |
| `--pcfg-pw-len-min`          | `Num`  | Skip structures generating passwords shorter than NUM. |
| `--pcfg-struct-prob-max`     | `Num`  | Skip structures with probability higher than NUM% (e.g., `0.8`). |
| `--pcfg-struct-prob-min`     | `Num`  | Skip structures with probability lower than NUM% (e.g., `0.1`). |
| `--pcfg-terminal-count-min`  | `Num`  | Skip terminals that appeared fewer than NUM times (filtered at model load time, not during training). |
| `--pcfg-token-count-max`     | `Num`  | Skip structures composed of more than NUM tokens. |
| `--pcfg-token-count-min`     | `Num`  | Skip structures composed of fewer than NUM tokens. |
| `--pcfg-token-len-max`       | `Num`  | Skip structures where any token is longer than NUM characters. |
| `--pcfg-token-len-min`       | `Num`  | Skip structures where any token is shorter than NUM characters. |

### Encoding Support

| Option                       | Type   | Description |
| :--------------------------- | :----: | :--- |
| `--encoding-from`            | `Code` | Specify the character encoding of the training input file. The trainer converts every line from this encoding to UTF-8 before inserting it into the model. The encoding name is stored inside the model file so that `--pcfg-model-info` and `--pcfg-model-diff` can display it. If not specified, the default is `utf-8` (no conversion). Example: `--encoding-from=iso-8859-1`. |
| `--encoding-to`              | `Code` | Convert generated candidates from UTF-8 to the specified encoding before sending them to the cracking engine or `--stdout`. Only supported on CPU modes (0, 1, 2, 4, 6); GPU modes (3, 5, 7) reject this option because candidates are built on-device. Example: `--encoding-to=iso-8859-1`. |

---

## 3. Internals

### Model

The model is the heart of this system. It stores all the information needed to reuse it even in machines other than those where it was created.
It contains all the Structures, Terminals, Markov training data, etc.

You can train a model, update an existing model using new training input (`--pcfg-model-update`), merge multiple models togheter by specifing many `--pcfg-models-merge` parameter as you need (es.: if you have 3 models to merge you need specify `--pcfg-models-merge model1.pcfg --pcfg-models-merge model2.pcfg --pcfg-models-merge model3.pcfg`), or compare two models side-by-side using `--pcfg-model-diff` to understand what changed between them. Remember to set also the output model file (using `--pcfg-model-save`) or the default name is used: hashcat.model.pcfg

**Update properties:** Updating a model with new data produces the same result as training from scratch on the combined dataset (base + new data). The updated model will have more terminals and potentially more structures than the base model alone.

**Merge properties:** Merging models A and B produces a superset model where: the total trained count equals A + B, the terminal count is greater than either individual model, and the structure count is at least as large as the largest individual model.

#### Statistics (`--pcfg-model-info`)

The `--pcfg-model-info` parameter displays detailed statistics about the loaded model and exits. These statistics can be used to understand model quality, identify attack patterns, and decide how to use filters to focus the keyspace. Adding `--quiet` produces a compact output (header only). Adding `--pcfg-token-types` filters the view to specific token types.

The output contains the following sections:

**Header** — Model overview at a glance:

| Field | Description |
| :--- | :--- |
| Model | Model filename |
| Quality | Score 0-100 with rating (Minimal / Limited / Moderate / Good / Excellent) |
| Trained | Total passwords used for training (with human-readable count, e.g., "2.50 Million") |
| Encoding | Source encoding of the training data. Shows `RAW` when training was done without `--encoding-from` (input assumed UTF-8), otherwise shows the encoding name (e.g., `iso-8859-1`). |
| Structs | Active (keyspace > 0) / loaded (after filtering) / total (in model file) |
| Terminals | Total unique terminal values, total instances, average tokens per password |
| Entropy | Estimated bits of entropy and approximate keyspace (e.g., "42.3 bits (2^42.3 combinations)") |

**Terminal Distribution** — Breakdown of terminal types with count and ratio:

```text
Type | Name               |      Count |  Ratio
-----+--------------------+------------+--------
L    | Lower Alpha        |      12543 |  45.2%
D    | Digits             |       8921 |  32.1%
...
```

**Top 25 Weakest Passwords** — Highest-probability passwords reconstructed from the model, showing structure pattern, probability, and example:

```text
  # | Pattern        |       Prob | Password
----+----------------+------------+-----------------------
  1 | L8             |     0.042% | password
  2 | D6             |     0.038% | 123456
...
```

A coverage summary shows how much of the total probability the top passwords represent.

**Top 30 Structures** — Highest-probability structures with keyspace, example, count, and a visual probability bar:

```text
  # | Pattern        |   Keyspace | Example               |      Count |##################|    Prob
----+----------------+------------+-----------------------+------------+------------------+--------
  1 | L8             |      5.2K  | password              |      15234 | ████████████████ |  2.34%
...
```

**Password Length Distribution** — Probability distribution of password lengths with visual bars, marking the peak length.

**Markov Engine Health** — Health status of each Markov table (Lower Alpha, Upper Alpha, Digits, Latin Ext, Cyrillic, Arabic, Asian, Greek, Hebrew, Catch-all, Structures). Shows active states, average density, and a status rating (Excellent / Good / OK / Limited / Sparse / Minimal).

**Structure by Token Type** — For each token type present in the model, shows the top structure containing that type, its count, keyspace, and an example password.

**Verbose sections** (shown without `--quiet`):

- **Top 10 Password Lengths** — Ranked by probability with visual bars
- **Starting Token Types** — Which token types appear first in structures, ranked by probability
- **First Order Transitions** (T1 -> T2) — Most common two-token-type sequences
- **Second Order Transitions** (T1 + T2 -> T3) — Most common three-token-type sequences
- **Script Cohesion (Sandwich Pattern)** — How often a script type wraps around digits (e.g., `L + D -> L`)
- **Top 10 Alpha Starting Bigrams** — Most common first two characters in alphabetic tokens
- **Top Trigram Transitions** — Most common character-level Markov transitions
- **Markov Transitions by Letter (a-z)** — Per-letter Markov transition probabilities
- **Top 3 Terminal Examples** — For each token type, shows terminal lengths with count, coverage, and example values

#### Model Diff (`--pcfg-model-diff`)

The `--pcfg-model-diff` parameter compares the model loaded with `--pcfg-model` (Model A) against a second model (Model B) and shows differences, then exits. This is useful for understanding how a model changes after training with new data, merging, or filtering.

Usage:

```bash
./hashcat -a10 --pcfg-model base.pcfg --pcfg-model-diff updated.pcfg
```

The output contains the following sections:

**Header** — Side-by-side comparison of key metrics:

```text
  Metric     |              Model A |              Model B |         Delta
  -----------+----------------------+----------------------+---------------
  Passwords  |         1.50 Million |         2.00 Million |   +500.00 K
  Encoding   |          iso-8859-1  |          iso-8859-1  |          same
  Structs    |                12543 |                14201 |        +1658
  Terminals  |                98234 |               112456 |       +14222
  Entropy    |           42.3 bits  |           43.1 bits  |   +0.80 bits
  Quality    |   90/100 (EXCELLENT) |   92/100 (EXCELLENT) |           +2
```

**Terminal Distribution Diff** — For each terminal type where the unique count differs between models:

```text
  Type | Name               |    Model A |    Model B |      Delta |  Change
  -----+--------------------+------------+------------+------------+--------
  L    | Lower Alpha        |      12543 |      14201 |      +1658 |  +13.2%
  D    | Digits             |       8921 |       9102 |       +181 |   +2.0%
  ...
```

**Structure Changes** (conditional) — Top 20 structures present in both models with probability or count differences, sorted by largest absolute probability delta:

```text
    # | Pattern              |   Prob A |   Prob B | Prob Delta |     Count A |     Count B | Count Delta
  ----+----------------------+----------+----------+------------+-------------+-------------+------------
    1 | L8                   |   2.340% |   1.980% |    -0.360% |       15234 |       18921 |      +24.2%
  ...
```

**Structures Only in Model A/B** (conditional) — Structures that exist in one model but not the other, shown only when present. Top 20 of total are displayed:

```text
    # | Pattern              |    Prob |      Count
  ----+----------------------+---------+-----------
    1 | U1L5D4S1             |  0.012% |        84
  ...
```

**Summary** — Overall counts:

```text
  Matched structures  : 12000
  Structure changes   : 4523
  Only in Model A     : 543
  Only in Model B     : 1658
```

#### OMEN Statistics (`--pcfg-omen-stats`)

When OMEN modes (4-7) are used, live statistics can be enabled with `--pcfg-omen-stats`. These are displayed during the cracking session (when a generator moves to the next cost or loop) and at the end (showing general OMEN statistics for each active generator).

### Training

This is the brain of the PCFG. it was designed to be as fast as possible, despite not using multithreading.

During the Training phase, if user don't specify `--pcfg-model-save` the engine save the trained model into specific file inside the hashcat folder: hashcat.model.pcfg
The file will be overwritten if another training session is started without specify how to save the model.
This phase consume a lot of RAM if the input file is bigger but by default the Admission Filter is enabled with a Threshold of 2 (don't add a parsed Terminal into the model if is not seed for almost 2 time).
If you have enough RAM you can disable the Admission Filter using `--pcfg-train-af-disable`. Don't worry about the OOM message because the PCFG engine monitor the memory used during the Training and if exceed the limit (pre-calculated before start using the number of lines of the input file as base metric) the trainer stop insert new Terminals but still update the counter for statistics purpose and also notify the user about this.
By default the Trainer using functions to cleanup input data to trying limit the 'noise' produced from bad constructed input file. Some of these functions can be disabled by using `--pcfg-train-df-disable` but is not raccomended.

#### Interrupting Training

During training, you can press **`q`** to gracefully stop the process. The progress line shows `[q]uit` as a reminder. When interrupted, the trainer saves a valid model built from all passwords processed up to that point — effectively the same as training on a shorter input file. The model is exported normally and can be used for cracking right away.

#### Input Type

You can specify the type of input that the trainer expects using the `--pcfg-train-format` parameter. Currently, two types are supported.

1. Wordlist (`--pcfg-train-format 0`)
Just a list of strings, nothing special. Each line read from the input file is classified and inserted into the model with a weight of 1.

1. Weigthed Wordlist (`--pcfg-train-format 1`)
By specifying this type of input, the trainer expects the file to have the format "counter:string".
In this way, it is possible to load into the model, for example, a specific word that has a weight defined by the counter that precedes it. If the trainer reads "1024:password," it is as if it were reading the string "password" 1024 times in Wordlist mode.

Currently, a logic has been implemented whereby, regardless of the weight set by the input list, if a terminal is classified as Mixed and has a length greater than 16, its weight is reset to 1.
This is because in this type of terminal, random strings/hashes/cryptographic keys/etc are often collected at these lengths, which can often be found in public leaks (which can be used to train a model) and can therefore corrupt the password generation logic.
Perhaps in the future it will be possible to configure extra rules so that you can customize the weights as you wish without modifying the source code.

#### Specific Parameters/Filters

- AF (Admission Filter) with Threshold
The admission filter is a way to limit the inclusion of rare "tokens" within a model, as well as a method to limit RAM usage as much as possible.
The threshold is used to define at will when a token should be considered 'rare', or rather how many times it must be seen before being included in the trainer's hash table.
Note: the AF only activates when the input file exceeds 5 million lines or when RAM pressure is detected. For smaller files, the AF has no effect regardless of the threshold setting.

- DF (Data Filters)
When testing different wordlists and password collections, a lot of junk was found inside (json, URL, base64, hex, hashes, etc.). To try to limit all this junk, filters are present at various points in the training logic. DF is enabled by default; disabling it with `--pcfg-train-df-disable` causes the trainer to use the original input as-is, without any filtering.

#### Encoding Support (`--encoding-from`)

PCFG models store all terminals in UTF-8. When the training input file uses a different encoding (e.g., ISO-8859-1, Windows-1252, ISO-8859-15), the `--encoding-from` parameter tells the trainer to convert every line from the specified encoding to UTF-8 before processing it. The conversion is performed using `iconv` on each line; lines that fail to convert are silently skipped.

The source encoding name is stored inside the model file header and displayed by `--pcfg-model-info` (field `Encoding`) and `--pcfg-model-diff`. When `--encoding-from` is not specified (or is explicitly set to `utf-8`), the model records `RAW`, meaning no conversion was applied and the input was assumed to be valid UTF-8.

This design ensures that models are always UTF-8 internally, regardless of the original training data encoding. The encoding metadata is informational only — it has no effect on password generation at cracking time.

#### Model Versioning

Each model file stores the format version used when it was created. The current version is defined by `PCFG_VERSION` in `include/pcfg.h`. When a new release changes the internal model format (e.g., new fields, different binary layout), this constant must be updated accordingly.

If you try to load a model trained with an older version, hashcat will refuse to load it and display:

```text
PCFG: Model version too old. Please retrain.
```

In that case, you must retrain the model from the original wordlist using the new version of hashcat. There is no automatic migration between model versions.

### Generation

Unlike the Trainer, the Generator was designed to dedicate one thread for each active device (CPU or GPU) as well as to be as fast as possible, despite being CPU-based. In almost all available modes, filters are applied during model loading so they have zero runtime cost:

- **Probability** (`--pcfg-struct-prob-min/max`): skip structures outside a probability range
- **Terminal Count** (`--pcfg-terminal-count-min`): skip terminals seen fewer than N times in training
- **Password Complexity** (`--pcfg-pw-complex`): enforce 3-of-4 character class policy
- **Password Length** (`--pcfg-pw-len-min/max`): skip structures producing passwords outside a length range
- **Token Count** (`--pcfg-token-count-min/max`): skip structures with too few or too many tokens
- **Token Length** (`--pcfg-token-len-min/max`): skip structures where any individual token is too short or too long
- **Terminal Types** (`--pcfg-token-types`): only include structures composed of specific token types
- **Keyspace** (`--pcfg-keyspace-max`): skip structures whose keyspace (total combinations) exceeds a limit

#### Output Encoding (`--encoding-to`)

Since PCFG models store all terminals in UTF-8, the generator always produces UTF-8 candidates. When the target hash was generated from passwords in a non-UTF-8 encoding (e.g., NTLM with Latin-1 input, or legacy systems using Windows-1252), the `--encoding-to` parameter converts every generated candidate from UTF-8 to the specified encoding before sending it to the cracking engine or `--stdout`. The conversion is performed using `iconv` on each candidate; candidates that fail to convert are silently skipped.

This option is **only supported on CPU modes** (0, 1, 2, 4, 6). GPU modes (3, 5, 7) reject `--encoding-to` with an error because candidates are assembled on-device and conversion would require moving them back to the CPU, negating the GPU performance advantage.

#### Generation Modes (`--pcfg-mode`)

The `--pcfg-mode` parameter selects which generation algorithm to use: Weighted Random, Probability, OMEN, GPU Probability, GPU OMEN (by Structure or by Cost), and AHF (Adaptive Hybrid-Fuzzing).
The `--pcfg-shuffle` parameter (mode 0 only) randomly reorders the tokens within each structure, producing novel password patterns not seen in training (e.g., `C8D3S1` could become `S1C8D3`).

| ID | Name | Executor | Description |
| :---: | :--- | :---: | :--- |
| 0 | Weighted Random | CPU | Probability-weighted priority heap (default) |
| 1 | AHF (Adaptive Hybrid-Fuzzing) | CPU | Runtime structure generation with synthetic terminals |
| 2 | Probability | CPU | Structures ordered by decreasing probability |
| 3 | Probability (GPU) | GPU | GPU-accelerated probability mode |
| 4 | OMEN by Cost | CPU | Cost-based iteration with OMEN ordering |
| 5 | OMEN by Cost (GPU) | GPU | GPU OMEN: iterates cost-first, then structure |
| 6 | OMEN by Structure | CPU | Structure-first iteration, then cost |
| 7 | OMEN by Structure (GPU) | GPU | GPU OMEN: iterates structure-first, then cost |

##### Weighted Random (mode 0)

Generates passwords using a probability-weighted priority heap. Structures are selected by probability, and for each structure, a **burst** of candidates is generated: the generator fixes all token slots except one and iterates through all terminals of that slot before re-evaluating the heap. This burst mechanism (controlled by `--pcfg-burst-size`, default 50000) avoids redundant heap operations and improves throughput. In this mode, burst means "terminals iterated for one token slot before heap re-evaluation."

By default, the burst iterates on the **last** token slot. With `--pcfg-burst-first`, it iterates on the **first** slot instead, producing a different enumeration order within each structure.

This mode is **non-deterministic**: the RNG is seeded from `time()`, thread ID, and memory address, so consecutive runs produce different output sequences. This is the only mode that supports `--pcfg-shuffle` (token reordering within structures).

**Status Display (PCFG.Info):**

```text
PCFG.Info.#01....: L4D4 (Prob:1.5076%, Count:1935, Len:8)
```

- **Pattern** (`L4D4`): current structure being processed
- **Prob**: structure probability in the model (%)
- **Count**: times this structure appeared in training
- **Len**: password length

##### AHF — Adaptive Hybrid-Fuzzing (mode 1)

The AHF mode implements a dynamic approach to password generation, distinguishing itself from the static OMEN and Probability modes.
Instead of using structures pre-calculated offline by the model, AHF generates structures at runtime to populate batches of structures for each generator. AHF uses the same burst mechanism as mode 0 (token-level iteration) but with a default burst size of 25000 instead of 50000.

AHF introduces the concept of **synthetic terminals**: instead of selecting terminal values from those observed during training, the generator creates new terminal values dynamically. This allows AHF to explore password candidates that were never seen in the training set.

Each synthetic token generates up to 100 candidate values per structure, balancing search-space coverage and runtime performance.

It is possible to select two sub-types of AHF operation via `--pcfg-ahf-type`: Markov and Random.

1. Markov (`--pcfg-ahf-type 0`, default)
In Markov mode, the generator uses second-order Markov chains to produce Structures and Terminals that are statistically consistent with the training set.

Token type selection follows a progressively conditioned Markov process: the first token is sampled from the initial distribution, the second token is selected using a first-order transition and all subsequent tokens are generated via second-order transitions indexed by the combined state.
The target password length is independently sampled, a distribution derived from observed training data, ensuring realistic length characteristics rather than uniform sampling.
To avoid overfitting and promote exploration of low-probability structures, a fixed noise injection mechanism is applied: with a probability of 25%, token type selection bypasses the Markov transition tables and randomly selects valid tokens, balancing statistical fidelity with combinatorial diversity.

1. Random (`--pcfg-ahf-type 1`)
In Random mode, token types are selected uniformly from valid types without considering statistical correlations, while additional constraints are applied to ensure realistic structures.
Once a token of a specific Unicode script (e.g., Cyrillic, Arabic, Asian) is selected, subsequent tokens are constrained to the same script, preventing improbable mixtures of scripts.
The system also attempts to avoid consecutive tokens of the same type when alternatives exist, promoting structural variety.
Password length is sampled uniformly within the range defined first by the selected algorithm and then refined if user specify the pw len min/max using specific arguments.
For terminal generation, random characters are produced according with the same token type.
This approach is computationally fast but does not account for correlations between adjacent characters, as the Markov mode does.

**Status Display (PCFG.Info):**

```text
PCFG.Info.#01....: U4A2K3 (Len:9)
```

- **Pattern** (`U4A2K3`): dynamically generated structure
- **Len**: password length

Since structures are generated at runtime (not from the model), probability and count are not available.

##### Probability (mode 2)

Generates passwords by iterating over structures ordered by decreasing probability.
For each structure, all derivable password candidates are fully enumerated before proceeding to the next structure.
This mode uses a linear iteration order designed for GPU-friendly access patterns, making it the fastest CPU generation mode.
This mode is fully **deterministic**. Options like `--pcfg-burst-size`, `--pcfg-burst-first`, and `--pcfg-shuffle` have no effect on this mode.

**Status Display (PCFG.Info):**

```text
PCFG.Info.#01....: L5D4 (Prob:0.6303%, Struct:27/2233, Progress:3592900/46195512, Len:9)
```

- **Pattern** (`L5D4`): current structure being processed
- **Prob**: structure probability in the model (%)
- **Struct**: current structure index / total structures
- **Progress**: candidates generated / structure keyspace
- **Len**: password length

##### Probability GPU (mode 3)

GPU-accelerated version of Probability mode. Candidate generation is offloaded to OpenCL/CUDA/Metal/HIP kernels, providing significantly higher throughput on supported hardware. The iteration order is the same as CPU Probability mode: structures are processed in order of decreasing probability, fully enumerating all candidates for each structure before moving to the next.

**Status Display (PCFG.Info):**

```text
PCFG.Info.#01....: L3D2L3 (Prob:0.4521%, Struct:49/2233, Progress:326252105/2683240000, Len:8)
```

- **Pattern** (`L3D2L3`): current structure being processed
- **Prob**: structure probability in the model (%)
- **Struct**: current structure index / total structures
- **Progress**: candidates generated / structure keyspace assigned to this device
- **Len**: password length

##### OMEN by Cost (mode 4)

All structures and terminals are sorted by probability (as in Probability mode).
Each structure is assigned a **cost** which represents how "unlikely" its combination of terminals is — lower cost means higher probability. The OMEN generator then iterates from low to high cost, ensuring that the most probable password candidates across all structures are tried first. Within each cost, the `--pcfg-burst-size` parameter controls how many candidates are generated per structure before moving to the next.
How the keyspace is explored across costs and structures is defined by the type of OMEN that is chosen (see OMEN Types below).
Uses per-generator work-stealing for thread synchronization.

**Status Display (PCFG.Info):**

The display format depends on the OMEN type selected (`--pcfg-omen-type`).

Interleaved (default):

```text
PCFG.Info.#01....: D2L5 (Loop:1/231408254, Chunk:18/63 [Cost 28-28], Cost:28/73, Struct:93, Len:7)
```

Classic:

```text
PCFG.Info.#01....: D2L5 (Chunk:18/63 [Cost 28-28], Cost:28/73, Struct:60, Len:7)
```

- **Pattern** (`D2L5`): current structure being processed
- **Loop** (Interleaved only): current loop iteration / maximum loops
- **Chunk**: current chunk index / total chunks [cost range covered by this chunk]
- **Cost**: current OMEN cost / maximum cost
- **Struct**: current structure index
- **Len**: password length

##### OMEN by Cost GPU (mode 5)

GPU-accelerated OMEN variant that iterates **cost-first, then structure**. All structures at the current cost are processed before advancing to the next cost. This is the GPU equivalent of CPU OMEN mode 4, and it is more likely to find high-probability passwords across all structures first.

When this type is used, the hashcat status bar is modified and additional commands are available depending on the OMEN type selected.

**Status Display (PCFG.Info):**

The display format depends on the OMEN type selected (`--pcfg-omen-type`).

Interleaved (default):

```text
PCFG.Info.#01....: L4Q3D1 (Loop:1/231408254, Chunk:1/1 [Cost11-100], Cost:31/73, Struct:215, Len:8)
```

Classic:

```text
PCFG.Info.#01....: L4Q3D1 (Chunk:1/1 [Cost11-100], Cost:31/73, Struct:215, Len:8)
```

- **Pattern** (`L4Q3D1`): current structure being processed
- **Loop** (Interleaved only): current loop iteration / maximum loops
- **Chunk**: current chunk index / total chunks [cost range]
- **Cost**: current OMEN cost / maximum cost
- **Struct**: current structure index within the GPU batch
- **Len**: password length

##### OMEN by Structure (mode 6)

CPU-based OMEN variant that iterates **structure-first, then cost**. For each structure, all OMEN costs are exhausted before moving to the next structure. Uses per-generator work-stealing for thread synchronization. This mode is useful when you want to fully explore one structure's keyspace across all costs before trying others.

**Status Display (PCFG.Info):**

The display format depends on the OMEN type selected (`--pcfg-omen-type`).

Interleaved (default):

```text
PCFG.Info.#01....: L3D1L2 (Loop:1/231408254, Chunk:1/1 [Cost 11-100], Cost:30/73, Struct:79, Len:6)
```

Classic (multi-device, struct-based split):

```text
PCFG.Info.#01....: L3D1L2 (Chunk:1/3 [Struct 0-165], Cost:30/73, Struct:42, Len:6)
```

Classic (single chunk):

```text
PCFG.Info.#01....: L3D1L2 (Chunk:1/1 [Cost 11-100], Cost:30/73, Struct:23, Len:6)
```

- **Pattern** (`L3D1L2`): current structure being processed
- **Loop** (Interleaved only): current loop iteration / maximum loops
- **Chunk**: current chunk index / total chunks [cost range or struct range covered by this chunk]
- **Cost**: current OMEN cost / maximum cost
- **Struct**: current structure index
- **Len**: password length

##### OMEN by Structure GPU (mode 7)

GPU-accelerated OMEN variant that iterates **structure-first, then cost**. This is the GPU counterpart of mode 6.

**Status Display (PCFG.Info):**

The display format depends on the OMEN type selected (`--pcfg-omen-type`).

Interleaved (default):

```text
PCFG.Info.#01....: D3L1D4 (Loop:1/231408254, Chunk:1/1 [Cost11-100], Cost:26/73, Struct:510, Len:8)
```

Classic:

```text
PCFG.Info.#01....: D3L1D4 (Chunk:1/1 [Cost11-100], Cost:26/73, Struct:510, Len:8)
```

- **Pattern** (`D3L1D4`): current structure being processed
- **Loop** (Interleaved only): current loop iteration / maximum loops
- **Chunk**: current chunk index / total chunks [cost range]
- **Cost**: current OMEN cost / maximum cost
- **Struct**: current structure index within the GPU batch
- **Len**: password length

##### OMEN Types

There are two types of OMEN implemented: Classic and Interleaved!
Sorting by efficiency, Interleaved mode is the one that hashcat will choose by default (`--pcfg-omen-type 0`).
Classic mode can be selected using `--pcfg-omen-type 1`.

1. Interleaved (`--pcfg-omen-type 0`, default)
In Interleaved mode, hashcat will go through Structure by Structure, completing a batch (with a size that can be changed by the `--pcfg-burst-size` parameter) for each one, scanning horizontally all structures for each OMEN cost.
At the end of all costs, it will repeat the process, but instead of starting from the beginning of each structure, it will use an offset to skip the batches processed in previous rounds.
Using this technique, it will be possible to first consume all candidates with a high probability for each structure and each possible OMEN cost, and repeat this round until the keyspaces present in the structures are exhausted.

When this type is used, the hashcat status bar is modified and additional commands will be available:
Using `[C]ost` it will be possible to jump to the next OMEN Cost (modes 4, 5, 6 only — not mode 7)
Using `[L]oop` it will be possible to jump to the next OMEN Loop

1. Classic (`--pcfg-omen-type 1`)
In Classic mode, hashcat will iterate structure by structure until the keyspace is exhausted before moving on to the next OMEN cost.

When this type is used, the hashcat status bar is modified and additional commands will be available:
Using `[S]truct` it will be possible to jump to the next Structure within the same OMEN Cost
Using `[C]ost` it will be possible to jump to the next OMEN Cost

##### Interactive Commands Summary

| Mode | OMEN Type | Available Commands |
| :--- | :--- | :--- |
| Probability CPU/GPU (2, 3) | - | `[S]truct` skip to next structure |
| OMEN (4, 5, 6, 7) | Classic (1) | `[S]truct` skip to next structure, `[C]ost` skip to next cost |
| OMEN (4, 5, 6) | Interleaved (0) | `[C]ost` skip to next cost, `[L]oop` skip to next loop |
| OMEN by Structure GPU (7) | Interleaved (0) | `[L]oop` skip to next loop |

Modes 0 and 1 have no interactive commands.

##### OMEN-Specific Parameters

- **OMEN Cost Range** (`--pcfg-omen-cost-min/max`): restrict which costs are explored (default: 0 to 100). Higher costs contain less probable candidates, so limiting the range focuses the attack.
- **OMEN Max Keyspace** (`--pcfg-omen-keyspace-max`): skip structures whose per-cost keyspace exceeds this limit, preventing stalls on extremely large structures.
- **OMEN Stats** (`--pcfg-omen-stats`): display detailed per-cost statistics during and after the session.
- **OMEN Max Alloc** (`--pcfg-omen-max-alloc-perc`): limit GPU memory allocation for large buffers (GPU modes 5, 7 only).
- **Burst Size** (`--pcfg-burst-size`): in all OMEN modes (4-7) with Interleaved type, defines the interleaved loop window size (default: 50000). In GPU OMEN modes (5, 7), also defines the dispatch batch window size. In OMEN Classic type, burst size is effectively unlimited.

##### Cross-Mode Consistency

Different modes that implement the same algorithm produce the **same set of passwords** (when compared sorted). This property is verified by the test suite:

- Probability modes: 2 == 3 (CPU Prob == GPU Prob)
- OMEN by Cost modes: 4 == 5 (CPU OMEN by Cost == GPU OMEN by Cost)
- OMEN by Structure modes: 6 == 7 (CPU OMEN by Struct == GPU OMEN by Struct)
- OMEN Classic vs Interleaved: same password set for each mode
- BY_STRUCT modes (6, 7) use a different iteration order from BY_COST modes (4, 5), so skip/limit windows differ between the two groups, but the full keyspace is identical.

Note: Mode 0 (Weighted Random) and mode 1 (AHF) are non-deterministic and cannot be compared with other modes. All structure/terminal filters (`--pcfg-token-types`, `--pcfg-struct-prob-min/max`, `--pcfg-terminal-count-min`, etc.) apply to all modes, while `--pcfg-burst-size` only affects modes 0, 1, 4-7 (not Probability modes 2, 3).

---

##### Performance Threshold (`--pcfg-perf-threshold`)

This parameter allows you to automatically skip PCFG structures, costs, or loops that are not producing enough recovered passwords within a specified time window.

The format is `<type>:<count>:<time>` where type can be `struct`, `cost`, or `loop`, count is the minimum number of passwords to recover, and time is the time window with units `s` for seconds, `m` for minutes, `h` for hours, or `d` for days. You can specify multiple types by separating them with commas, for example `loop:100:1h,cost:10:5m`.

The available types depend on the mode and OMEN type:

| Mode | OMEN Type | Available skip types |
| :--- | :--- | :--- |
| Probability (2, 3) | - | `struct` |
| OMEN by Cost (4, 5) | Classic (1) | `cost` only |
| OMEN by Struct CPU (6) | Classic (1) | `cost` only |
| OMEN by Struct GPU (7) | Classic (1) | `struct`, `cost` |
| OMEN by Cost (4, 5) | Interleaved (0) | `cost`, `loop` |
| OMEN by Struct CPU (6) | Interleaved (0) | `cost`, `loop` |
| OMEN by Struct GPU (7) | Interleaved (0) | `loop` only |

When combining multiple types, it is not possible to have the same count and the same time for two different types. In addition, timers must respect the hierarchy: the struct timer must be less than or equal to the cost timer, which in turn must be less than or equal to the loop timer.
When the timer expires and the passwords recovered are below the threshold, the generator skips to the next element and the counters are reset. If a higher tier in the hierarchy is skipped, the counters of the lower tiers are also reset.

A dedicated performance monitor thread runs in the background, checking thresholds every second and triggering automatic skips when conditions are met.

---

##### PCFG Loopback (`--pcfg-loopback`)

The `--pcfg-loopback` flag enables an automated feedback loop that combines a standard dictionary attack (`-a 0`) with iterative PCFG attacks. It is only allowed with attack mode 0 (straight).

**How it works:**

1. **Phase 1 — Dictionary attack (`-a 0`)**: hashcat runs the normal wordlist attack. Every cracked password is captured to a temporary file in the session directory.
2. **Phase 2 — Model training**: after the dictionary attack completes (or is bypassed), the collected cracked passwords are used to train a PCFG model. If a base model was provided via `--pcfg-model`, it is updated with the new data; otherwise a fresh model is trained from scratch.
3. **Phase 3 — PCFG attack loop**: the engine switches to `-a 10` and runs the PCFG attack using the trained model. During this attack, any newly cracked passwords are again captured.
4. **Phase 4 — Iterate**: after each PCFG generation exhausts or is bypassed, if new passwords were cracked, the model is updated with the new data and a new PCFG generation starts. The loop stops when no new passwords are cracked, all hashes are recovered, or the session is aborted.

Each iteration of the loop is identified by a **Loopback ID** (generation counter), visible in the `PCFG.Settings` status line during the PCFG phase.

**Default mode**: if `--pcfg-mode` is not explicitly set, loopback defaults to mode 5 (GPU OMEN by Cost). Any `--pcfg-*` options (filters, OMEN cost range, burst size, etc.) apply to the PCFG phase.

**Example:**

```bash
# Run dictionary attack, then auto-train and loop PCFG
hashcat -a 0 -m 0 example0.hash example.dict --pcfg-loopback

# With a base model to update
hashcat -a 0 -m 0 example0.hash example.dict --pcfg-loopback --pcfg-model example.dict.pcfg

# With explicit PCFG mode and filters
hashcat -a 0 -m 0 example0.hash example.dict --pcfg-loopback --pcfg-mode 5 --pcfg-pw-len-max 16
```

---

##### Session, Restore, Skip and Keyspace

PCFG attack mode (`-a 10`) supports `--session`, `--restore`, `--skip`, `--limit`, and `--keyspace` with the same semantics as other attack modes, with the following notes:

**Session and Restore (`--session`, `--restore`)**

Sessions work with all deterministic modes (0, 2-7). The restore point tracks absolute positions in the keyspace across single and multi-device configurations. After a restore, generators fast-forward to the saved position and resume producing candidates from where they left off.

Mode 1 (AHF) does **not** support `--restore` because its keyspace is non-deterministic — structures and terminals are generated dynamically at runtime, so there is no reproducible position to resume from. Creating a session with mode 1 is allowed (for status tracking), but attempting `--restore` on a mode 1 session produces an error.

**Skip and Limit (`--skip`, `--limit`)**

`--skip N` fast-forwards the generators past the first N candidates. `--limit N` stops after generating N candidates (starting from the skip offset if both are used). These parameters work with all deterministic modes (0, 2-10). Mode 1 (AHF) accepts them but operates on a best-effort basis since its keyspace is non-deterministic.

When `--skip` is used, the status display shows the absolute position in the total keyspace (e.g., `Restore.Point: N/total`), consistent with the behavior of `-a 0 --skip`.

**Keyspace (`--keyspace`)**

`--keyspace` computes and displays the total number of candidates the model would produce, then exits without cracking. It works with all deterministic modes (0, 2-10). Mode 1 (AHF) rejects `--keyspace` because its keyspace is dynamic and cannot be pre-computed.

---

##### Status Display (PCFG.Settings)

During a PCFG attack (`-a 10` or `--pcfg-loopback`), the status screen shows a `PCFG.Settings` line summarizing the active configuration. This line is displayed for all modes and includes the following fields:

**Format:**

```text
PCFG.Settings....: Mode:<mode_name>, [Burst:<N>, ][Types:<types>, ][Struct Shuffle:Yes, ]
                   [Prob Min/Max:<N>%/<N>%, ][Tokens Min/Max:<N>/<N>, ]
                   [Token Len Min/Max:<N>/<N>, ][Pwd Len Min/Max:<N>/<N>, ]
                   [OMEN Cost Min/Max:<N>/<N>, ][Pwd Complex:Yes, ][Loopback ID:<N>]
```

**Fields:**

| Field | When shown | Description |
| :--- | :--- | :--- |
| `Mode:<name>` | Always | The active generation mode name and executor (e.g., `OMEN By Cost Interleaved (GPU)`) |
| `Burst:<N>` | Modes 0, 5, 7 (Interleaved only) | The configured burst size |
| `Types:<types>` | When `--pcfg-token-types` is set | Active token type filter (e.g., `CD`) |
| `Struct Shuffle:Yes` | When `--pcfg-shuffle` is set | Structure token shuffling is enabled |
| `Prob Min:<N>%` | When `--pcfg-struct-prob-min` is set | Minimum structure probability filter |
| `Prob Max:<N>%` | When `--pcfg-struct-prob-max` is set | Maximum structure probability filter |
| `Prob Min/Max:<N>%/<N>%` | When both are set | Combined probability range filter |
| `Tokens Min:<N>` | When `--pcfg-token-count-min` is set | Minimum token count filter |
| `Tokens Max:<N>` | When `--pcfg-token-count-max` is set | Maximum token count filter |
| `Tokens Min/Max:<N>/<N>` | When both are set | Combined token count range |
| `Token Len Min:<N>` | When `--pcfg-token-len-min` is set | Minimum individual token length filter |
| `Token Len Max:<N>` | When `--pcfg-token-len-max` is set | Maximum individual token length filter |
| `Token Len Min/Max:<N>/<N>` | When both are set | Combined token length range |
| `Pwd Len Min:<N>` | When `--pcfg-pw-len-min` is set | Minimum password length filter |
| `Pwd Len Max:<N>` | When `--pcfg-pw-len-max` is set | Maximum password length filter |
| `Pwd Len Min/Max:<N>/<N>` | When both are set | Combined password length range |
| `OMEN Cost Min:<N>` | Modes 4-10, when `--pcfg-omen-cost-min` is set | Minimum OMEN cost |
| `OMEN Cost Max:<N>` | Modes 4-10, when `--pcfg-omen-cost-max` is set | Maximum OMEN cost |
| `OMEN Cost Min/Max:<N>/<N>` | When both are set | Combined OMEN cost range |
| `Pwd Complex:Yes` | When `--pcfg-pw-complex` is set | Microsoft password complexity enforcement |
| `Loopback ID:<N>` | During `--pcfg-loopback` PCFG phase | Current loopback generation number (increments each iteration) |

**Example (basic):**

```text
PCFG.Settings....: Mode:OMEN By Cost Interleaved (GPU), Burst:50000
```

**Example (with filters):**

```text
PCFG.Settings....: Mode:Prob (CPU), Prob Min/Max:0.0100%/5.0000%, Pwd Len Min/Max:6/16
```

**Example (loopback session, generation 3):**

```text
PCFG.Settings....: Mode:OMEN By Cost Interleaved (GPU), Burst:50000, Loopback ID:3
```

---

## 4. Source Architecture

The PCFG codebase is organized into domain-specific modules:

| File | Description |
| :--- | :--- |
| `src/pcfg.c` | Core engine: model loading, model inspector, generator lifecycle, OMEN cost calculation, status display |
| `src/pcfg_trainer.c` | Training pipeline: tokenization, model building, sorting, import/export, statistics |
| `src/pcfg_trainer_utils.c` | Low-level parsing utilities used by the trainer (hex, email, base64, unicode, garbage detection) |
| `src/pcfg_common.c` | Shared functions: fast division, reciprocal math, OMEN analysis, keyspace calculation, user option sanity checks |
| `src/pcfg_cpu_random.c` | CPU Weighted Random generator (mode 0): heap operations, skip logic |
| `src/pcfg_cpu_prob.c` | CPU Probability (mode 2) generator |
| `src/pcfg_cpu_omen.c` | CPU OMEN by Cost (mode 4) and OMEN by Structure (mode 6) generators |
| `src/pcfg_gpu_prob.c` | GPU Probability generator (mode 3): kernel dispatch, buffer management |
| `src/pcfg_gpu_omen.c` | GPU OMEN generators (modes 5, 7): structure/cost partitioning, kernel dispatch |
| `src/pcfg_perf.c` | Performance threshold monitor: background thread, skip logic for struct/cost/loop |
| `src/pcfg_omen_analysis.c` | OMEN architecture analysis: GPU memory planning, chunk partitioning |
| `src/pcfg_omen_stats.c` | OMEN statistics collection: per-cost counters, session summary output |
| `src/pcfg_model.c` | Model I/O: serialization, deserialization, merge, update, filtered loading |
| `src/pcfg_backend.c` | GPU backend integration: kernel compilation, buffer allocation, memory management |
| `src/pcfg_dispatch.c` | Dispatch layer: generator-to-device scheduling, keyspace distribution |
| `src/pcfg_loopback.c` | PCFG loopback: trains model from cracked passwords, runs PCFG attack after wordlist phase |
| `OpenCL/pcfg_gpu_prob.cl` | GPU Probability kernel (OpenCL/CUDA/Metal/HIP) |
| `OpenCL/pcfg_gpu_omen.cl` | GPU OMEN kernel (OpenCL/CUDA/Metal/HIP) |

---

## 5. Usage Examples

### Training a new model

Train a model using the official dictionary example.dict, keeping the admission filter disabled, save it in example.dict.pcfg and start the password cracking session:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-train example.dict --pcfg-model-save example.dict.pcfg --pcfg-train-af-disable
```

### Show stats for a pre-trained model

Load the pre-trained model example.dict.pcfg, display statistics and exit:

```bash
hashcat -a 10 --pcfg-model example.dict.pcfg --pcfg-model-info
```

Show stats with compact output:

```bash
hashcat -a 10 --pcfg-model example.dict.pcfg --pcfg-model-info --quiet
```

Show stats for a filtered view (only structures containing Lowercase and Digits):

```bash
hashcat -a 10 --pcfg-model example.dict.pcfg --pcfg-model-info --pcfg-token-types LD
```

### Loading a pre-trained model

Load the pre-trained model example.dict.pcfg and start the password cracking session:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg
```

### Update an existing model using new training data

Update the pre-trained model example.dict.pcfg using the same wordlist as additional training data, save the updated model and start the password cracking session:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-train example.dict --pcfg-model-update --pcfg-model-save example.dict.updated.pcfg
```

### Merge multiple models into one

Merge two copies of the same model (in practice you would use different models), save the merged result and start the password cracking session:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-models-merge example.dict.pcfg --pcfg-models-merge example.dict.pcfg --pcfg-model-save example.dict.merged.pcfg
```

### Using GPU Probability mode

Use GPU-accelerated Probability mode for maximum throughput:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 3
```

### Using GPU OMEN by Cost mode

Use GPU-accelerated OMEN with cost-first iteration (equivalent to CPU OMEN by Cost mode 4, but faster):

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 5
```

### Using GPU OMEN by Structure mode

Use GPU-accelerated OMEN with structure-first iteration, exhausting each structure across all costs:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 7
```

### Using CPU deterministic modes

Use the fastest CPU-based deterministic modes:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 2
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 4
```

### Using AHF mode (Adaptive Hybrid-Fuzzing)

Run the Adaptive Hybrid-Fuzzing engine with default Markov sub-type:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 1
```

### Using AHF mode with Random sub-type

Run AHF using Random mode instead of Markov mode:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 1 --pcfg-ahf-type 1
```

### Using performance threshold

Automatically skip underperforming elements during the attack:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --pcfg-mode 5 --pcfg-perf-threshold loop:100:1h,cost:10:5m
```

### Using `--stdout`

You can also use stdout

```bash
hashcat -a 10 --pcfg-model example.dict.pcfg --pcfg-mode 1 --stdout
```

### Using PCFG loopback

Run a dictionary attack first, then automatically train a PCFG model from cracked passwords and iterate:

```bash
# Basic loopback (defaults to GPU OMEN by Cost, mode 5)
hashcat -a 0 -m 0 example0.hash example.dict --pcfg-loopback

# Loopback with a base model to update with cracked passwords
hashcat -a 0 -m 0 example0.hash example.dict --pcfg-loopback --pcfg-model example.dict.pcfg

# Loopback with explicit mode and filters
hashcat -a 0 -m 0 example0.hash example.dict --pcfg-loopback --pcfg-mode 5 --pcfg-pw-len-max 16
```

### Training with non-UTF-8 input (`--encoding-from`)

Train a model from an ISO-8859-1 encoded wordlist. The trainer converts every line to UTF-8 before inserting it into the model:

```bash
hashcat -a 10 --pcfg-train latin1_wordlist.txt --encoding-from iso-8859-1 --pcfg-model-save latin1.pcfg --pcfg-model-info
```

Verify that the model recorded the encoding:

```bash
hashcat -a 10 --pcfg-model latin1.pcfg --pcfg-model-info --quiet
# Output includes: Encoding : iso-8859-1
```

### Cracking with output encoding conversion (`--encoding-to`)

When the target hashes were generated from Latin-1 passwords, convert the UTF-8 candidates to Latin-1 before hashing (CPU modes only):

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model latin1.pcfg --pcfg-mode 2 --encoding-to iso-8859-1
```

Preview the converted output with `--stdout`:

```bash
hashcat -a 10 --pcfg-model latin1.pcfg --pcfg-mode 0 --encoding-to iso-8859-1 --stdout --limit 100
```

### Using session, restore and skip

Start a named session that can be restored later:

```bash
hashcat -a 10 -m 0 example0.hash --pcfg-model example.dict.pcfg --session mypcfg
```

Resume from where the session left off:

```bash
hashcat --session mypcfg --restore
```

Skip the first 500 million candidates and generate the next 10 million:

```bash
hashcat -a 10 --pcfg-model example.dict.pcfg --stdout --skip 500000000 --limit 10000000
```

Display the total keyspace of a model:

```bash
hashcat -a 10 --pcfg-model example.dict.pcfg --keyspace
```

---

## 6. Limitations

### AHF Mode (mode 1)

Mode 1 generates structures and terminals dynamically at runtime, making its keyspace non-deterministic. As a consequence:

- `--restore` is not supported — attempting to restore a mode 1 session produces an error
- `--keyspace` is not supported — the total keyspace cannot be pre-computed
- `--pcfg-shuffle` is not supported — produces an error if combined with mode 1
- `--skip` and `--limit` are accepted but operate on a best-effort basis since there is no deterministic keyspace

Creating a session with `--session` is allowed for status tracking purposes, but the session cannot be resumed.

### Performance Threshold — Not Available in Modes 0 and 1

The `--pcfg-perf-threshold` parameter is not supported in modes 0 (Weighted Random) and 1 (AHF).

### Output Encoding — CPU Only

The `--encoding-to` parameter is only supported on CPU modes (0, 1, 2, 4, 6). GPU modes (3, 5, 7) reject this option because candidates are assembled on-device and converting them would require transferring data back to the CPU, negating the GPU performance advantage.

### Structure Shuffle (`--pcfg-shuffle`)

The `--pcfg-shuffle` parameter is only supported in mode 0 (Weighted Random). Mode 1 (AHF) produces an explicit error if combined with `--pcfg-shuffle`. All other modes silently ignore it.

### Interactive Commands

Interactive prompt commands are available in the following modes:

| Command | Modes | Description |
| :--- | :--- | :--- |
| `[S]truct` | 2, 3 (Probability CPU/GPU), 4-7 Classic | Skip to next structure |
| `[C]ost` | 4-7 Classic, 4-6 Interleaved | Skip to next OMEN cost |
| `[L]oop` | 4-7 Interleaved | Skip to next OMEN loop |

Modes 0 and 1 have no interactive commands.

### Non-Deterministic Modes

Modes 0 (Weighted Random) and 1 (AHF) are non-deterministic — consecutive runs produce different output sequences. Their output cannot be compared cross-mode for consistency verification. The RNG is seeded from wall-clock time, thread ID, and heap address.

### Loopback — Attack Mode 0 Only

The `--pcfg-loopback` flag is only allowed with attack mode 0 (`-a 0`). It cannot be used directly with `-a 10`.

### Burst Size (`--pcfg-burst-size`)

The `--pcfg-burst-size` parameter has no effect on Probability modes (2, 3). All other modes use it: modes 0 and 1 for terminal iteration batching, OMEN modes (4-7) for interleaved loop windowing. In OMEN Classic type, burst size is effectively unlimited.

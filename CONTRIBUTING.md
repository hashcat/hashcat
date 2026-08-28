# Contributing to hashcat

Contributions are welcome and encouraged, provided your code is of sufficient quality. This file is what a reviewer will hold your pull request against.

If you use an AI coding agent, that is welcome too. [AGENTS.md](AGENTS.md) is written for the agent and adds a few things on top of this file. Everything here applies to agent written code unchanged.

## One problem per pull request

Solve only one problem in each pull request. If you are fixing a bug and adding a feature, that is two pull requests. Three bugs is three pull requests. Four features is four pull requests.

If your patch fixes a bug, open an [issue](https://github.com/hashcat/hashcat/issues) for the bug first. If your patch aims to improve performance or optimize an algorithm, quantify the improvement, document the trade-offs, and back the claim with benchmarks.

Whatever the size of the patch, describe what prompted the change. A one line diff still needs a reason.

## Requirements

1. Licensed under the MIT license, or dedicated to the public domain. BSD and GPL code is incompatible.
2. Adheres to the gnu99 standard.
3. Compiles cleanly with no warnings under `-W -Wall -std=gnu99`.

## Code style

Match the code around you. The rules below are what that code already does, and a reviewer will ask for them.

### Layout

* 2 spaces for indentation. A tab only where the format demands one, such as a Makefile.
* [Allman braces](https://en.wikipedia.org/wiki/Indent_style#Allman_style). The opening brace goes on its own line, for functions and for `if`, `else`, `for`, `while` and `switch`.
* Omit the braces when the body is a single statement that fits on one line: `if (rc == -1) return -1;`
* Two or more statements, or any nested block, always gets braces.
* A space before the parenthesis in a call and in control flow: `hc_strtoull (s, NULL, 10)`, `if (x == 0)`, `for (u32 i = 0; i < len; i++)`.
* No space just inside the parentheses.
* The return type and the function name stay on one line, however long the signature runs.

### Blank lines and alignment

Blank lines separate groups of related statements, the way paragraphs separate sentences. Column alignment applies inside a group only, and a blank line ends an alignment group. Never pad a line out to hold an alignment across unrelated code, start a new group instead.

```c
salt_t *salt = hash_info->salt;

salt->salt_iter = iter - 1;
salt->salt_len  = salt_len;
salt->salt_repeats = 0;
```

Where two lines are a pair, add the no-op that keeps them aligned. The compiler drops it and the reader gains a column:

```c
digest[0] = hex_to_u32 (&hash_pos[ 0]);
digest[1] = hex_to_u32 (&hash_pos[ 8]);
```

```c
u8 hi = (code >> 8) & 0xF;
u8 lo = (code >> 0) & 0xF;
```

### Naming and types

* Lower case function and variable names.
* Explicit width types: `u8`, `u32`, `u64`, `bool`. Not `int`, not `unsigned`.
* `const` on every parameter, local and return that is not written to.
* The `*` binds to the name, not the type: `char *buf`, not `char* buf`.
* Initialise a pointer declaration to `NULL`.
* `typedef struct name { ... } name_t;`, with the `_t` suffix.

### Statements

* Declare a variable immediately before its first use, not in a block at the top. Do not split a coherent group of statements to do it, declare what the group needs before the group starts.
* Compare explicitly: `if (found == true)`, `if (len == 0)`. Never `if (!found)`.
* Never use `!` on a boolean. Rewrite as `== false` or `== 0`.
* An implicit pointer test is fine: `while (e)`, `if (prev)`.
* Guard clauses over nesting. `if (user_options->quiet == true) return;` on one line, and `continue` or `break` to keep a loop body flat.
* In an `if` and `else` pair, put the `>=` or `>` case first rather than the `<` case. This does not apply to a `for` condition, where `i < len` is correct.
* Parenthesise each operand of `||` and `&&` separately: `if ((a == 0) || (b == 0))`. Better still, split it into two guard clauses.
* Never wrap a condition across lines.
* No computation in a `return`. Assign to a named variable, then return it.
* No pointer arithmetic. Use `p[i]`, not `*(p + i)` or `*p++`.
* Write `array[index + 0]` when you also write `array[index + 1]`.

### Comments and includes

* `//` for a comment. `/** ... */` only for the file header.
* A comment goes on its own line above the code it describes, not trailing it.
* Project includes first, then system includes, separated by a blank line.
* Every source file opens with:

```c
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
```

## Comments and documentation are plain ASCII

Every comment and every line of Markdown you add must be plain ASCII. Precisely: every byte is in the range 0x20 to 0x7E, plus tab and newline. Nothing else. No en dashes, em dashes, curly quotes, arrows or ellipsis characters. Write `->` for an arrow, `...` for an ellipsis, and `'` or `"` for quotes.

The rule is about punctuation, not about data. A proper name that genuinely carries an accent keeps it, and so does text that is the subject of the example, such as a password in a script other than Latin. Everything else is ASCII.

Do not use `--` as punctuation. A double hyphen reads as the start of a long option, which is confusing in a project where real long options are discussed in the surrounding text. Use a comma, a colon, or two sentences. A double hyphen inside an actual flag name, such as `--potfile-path`, is fine and must be left alone.

Do not join two clauses with a semicolon. Split them into two sentences. Short sentences, one idea each, read better than long ones. A semicolon inside a code expression is a different thing and is fine.

Check the lines your branch adds before you push:

    git diff -U0 master...HEAD | grep '^+' | grep -nP '[^\x09\x20-\x7E]'

## Commits

Set `user.name` and `user.email` before your first commit, so the history carries your name rather than a default:

    git config user.name  "your name"
    git config user.email "you@example.com"

GitHub gives every account a `users.noreply.github.com` address if you would rather not publish a real one.

Pull requests are merged with a merge commit, so every commit message on your branch survives into master. Write them for that.

## What a pull request has to contain

Keep the description short. The reader wants to reproduce the problem before reading a word about its cause.

1. One or two sentences of summary.
2. The reproduction command, in full, with the result before and after the change.
3. The explanation, once the reader can already see the failure.
4. The `tools/test_edge.sh` output for every mode you touched.

A claim that something is broken carries the command that shows it. Not a description of the command, the command itself:

* the whole command line, copy and paste ready, with no placeholders and no files for the reader to create first
* the whole hash inline as an argument, not truncated and not attached
* the whole password inline as an argument
* the result on both sides, with the exit code and the line of output that shows the difference

So this, and nothing shorter:

    $ ./hashcat -m 17010 -a 3 -D 1 --force --potfile-disable '$gpg$*1*320*...*1112131415161718' 'AAAA...'

    before: Recovered 0/1, Status Exhausted, rc=1
    after:  Recovered 1/1, Status Cracked,   rc=0

Attack mode 3, with the password as a literal mask, is usually the shortest route because it needs no wordlist file. Say what else has to be true for the run to mean anything. `rm -rf kernels/` between two kernel versions is the usual one, because hashcat caches compiled kernels and will otherwise reuse the old binary.

For step 4, run the suite yourself and paste what it printed:

    ./tools/test_edge.sh -m 0

With only `-m`, the suite covers every attack type, kernel type, target type and vector width for that mode, and it clears the kernel cache before it starts. Add `-D 1 -f` on a machine with no GPU, where hashcat runs on the CPU backend and needs `--force`. `./tools/test_edge.sh -h` lists the rest.

Paste the tail of the run, down to and including the line that reports how many errors were detected. That line is the one a reviewer looks for.

If a mode you touched cannot be tested on your hardware, say so. Leaving the output out without saying why is what a reviewer will ask about first.

## A new hash mode should come with a test module

A mode is only covered by the test suites once a test module exists at `tools/test_modules/mXXXXX.pm`. That is what lets them generate fresh hashes and check that hashcat cracks them, instead of the mode resting on one self-test vector forever. See [tools/test_modules/README.md](tools/test_modules/README.md) for the functions it has to provide, and the [plugin development guide](docs/hashcat-plugin-development-guide.md) for how it fits into the rest of a plugin.

Writing it is not a hard requirement, and a mode with a good proof of concept behind it is still worth having without one. Writing it first tends to pay for itself, because it doubles as the proof of concept you need while developing the kernel.

## Review

The [project lead](https://github.com/jsteube) has the ultimate authority in deciding whether to accept or reject a pull request. Do not be discouraged if your pull request is rejected.

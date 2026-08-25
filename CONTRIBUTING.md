# Contributing to hashcat

This file has two parts, and they are addressed to different readers.

**Part 1 is for human contributors.** It is the code style and pull request
policy that used to live in `README.md`, plus the conventions that keep coming
up in review.

**Part 2 is for AI coding agents.** It starts at
[Part 2](#part-2-instructions-for-ai-coding-agents), and it is additional and
stricter. If you are an agent, all of part 1 binds you too. Part 2 in short,
with the reasoning for each in the section itself:

1. Do not sign commits as an AI. Commit as the human you are working for.
2. If you add a hash mode, add its `tools/test_modules/mXXXXX.pm` in the same
   pull request, and run it.
3. Never present output you did not actually run and read back. If you could
   not run something, say which thing and why.
4. Verify instead of asserting. Run both sides of the change and read the exit
   code before you call anything fixed.
5. Stay inside the change you were asked for. One problem per pull request.
6. Actually run the non-ASCII check. Do not eyeball the diff for it.

---

# Part 1: for human contributors

## Code quality and pull request policy

Contributions are welcome and encouraged, provided your code is of sufficient
quality. Before submitting a pull request, please ensure your code adheres to
the following requirements:

1. Licensed under MIT license, or dedicated to the public domain (BSD, GPL, etc. code is incompatible)
2. Adheres to gnu99 standard
3. Compiles cleanly with no warnings when compiled with `-W -Wall -std=gnu99`
4. Uses [Allman-style](https://en.wikipedia.org/wiki/Indent_style#Allman_style) code blocks & indentation
5. Uses 2-spaces as the indentation or a tab if it's required (for example: Makefiles)
6. Uses lower-case function and variable names
7. Avoids the use of `!` and uses positive conditionals wherever possible (e.g., `if (foo == 0)` instead of `if (!foo)`, and `if (foo)` instead of `if (foo != 0)`)
8. Use code like array[index + 0] if you also need to do array[index + 1], to keep it aligned

You can use GNU Indent to help assist you with the style requirements:

```
indent -st -bad -bap -sc -bl -bli0 -ncdw -nce -cli0 -cbi0 -pcs -cs -npsl -bs -nbc -bls -blf -lp -i2 -ts2 -nut -l1024 -nbbo -fca -lc1024 -fc1
```

Your pull request should fully describe the functionality you are adding/removing or the problem you are solving. Regardless of whether your patch modifies one line or one thousand lines, you must describe what has prompted and/or motivated the change.

Solve only one problem in each pull request. If you're fixing a bug and adding a new feature, you need to make two separate pull requests. If you're fixing three bugs, you need to make three separate pull requests. If you're adding four new features, you need to make four separate pull requests. So on, and so forth.

If your patch fixes a bug, please be sure there is an [issue](https://github.com/hashcat/hashcat/issues) open for the bug before submitting a pull request. If your patch aims to improve performance or optimize an algorithm, be sure to quantify your optimizations and document the trade-offs, and back up your claims with benchmarks and metrics.

In order to maintain the quality and integrity of the **hashcat** source tree, all pull requests must be reviewed and signed off by at least two [board members](https://github.com/orgs/hashcat/people) before being merged. The [project lead](https://github.com/jsteube) has the ultimate authority in deciding whether to accept or reject a pull request. Do not be discouraged if your pull request is rejected!

## Comments and documentation are plain ASCII

Every comment, and every line of Markdown, must be plain ASCII. No en dashes,
em dashes, curly quotes, arrows, ellipsis characters, or any other non-ASCII
byte. Use `->` for an arrow, `...` for an ellipsis, and `'` or `"` for quotes.

Do not use `--` as punctuation. A double hyphen reads as the start of a long
option, which is confusing in a codebase where real long options are discussed
in the surrounding lines. Rewrite with a comma, a colon, a semicolon, or two
sentences, whichever is grammatical. A double hyphen that is part of an actual
flag name, such as `--potfile-path` or `--strip-components`, is fine and must be
left alone.

Before you push, check the lines your branch adds:

    git diff -U0 <base>...HEAD | grep '^+' | grep -nP '[^\x00-\x7F]'

and read through the added comments for a double hyphen used as an em dash.

## Commit identity

Set `user.name` and `user.email` before your first commit, so your history
carries your name rather than a default:

    git config user.name  "your name"
    git config user.email "you@example.com"

If you would rather not publish an address, GitHub gives every account a
`users.noreply.github.com` one.

If an AI assistant helped you, see [part 2](#do-not-sign-commits-as-an-ai) for
what must not end up in the commit message.

## Every claim that something is broken carries the command that shows it

A bug report, a commit message and a pull request description that say something
is broken have to carry a command that shows it. Not a description of one, the
command itself, in full:

* the whole command line, copy and paste ready, with no placeholders and no
  files for the reader to create first
* the whole hash, inline as an argument, not truncated and not in an attachment
* the whole password, inline as an argument
* the result before the change and the result after it, with the exit code and
  whatever line of hashcat output actually shows the difference

So this, and nothing shorter:

    ./hashcat -m 17010 -a 3 -D 1 --force --potfile-disable '$gpg$*1*320*...*1112131415161718' 'AAAA...'

    before: Recovered 0/1, Status Exhausted, rc=1
    after:  Recovered 1/1, Status Cracked,   rc=0

Attack mode 3 with the password as a literal mask is usually the shortest way to
get there, because it needs no wordlist file. Say what else has to be true for
the run to mean anything. `rm -rf kernels/` between two kernel versions is the
usual one, because hashcat caches compiled kernels and will happily reuse the
old binary.

## A new hash mode should come with a test module

A hash mode is only covered by `tools/test.sh` once there is a test module at
`tools/test_modules/mXXXXX.pm`. That is what lets the suite generate fresh
hashes for the mode and check that hashcat cracks them, instead of the mode
resting on a single self-test vector forever. See
[tools/test_modules/README.md](tools/test_modules/README.md) for the three
functions it has to provide, and
[docs/hashcat-plugin-development-guide.md](docs/hashcat-plugin-development-guide.md)
for how it fits into the rest of a plugin.

Writing it by hand is optional, and it stays optional. It is real work, and a
mode with a good proof of concept behind it is still worth having without one.
Writing it first does pay for itself, because it doubles as the proof of concept
you need while developing the kernel, so you do not write the same code twice.

An agent writing the plugin for you does not get that exemption. See
[part 2](#write-the-test-module-you-have-no-excuse).

## Pull request descriptions

Keep them short. The reader wants to reproduce the problem before they read a
word about its cause.

1. One or two sentences of summary, no more.
2. The reproduction command, in full, as described above, with the before and
   after result. This comes before any explanation of what causes the bug.
3. The explanation, once the reader can already see the failure for themselves.
4. The `tools/test.sh` output for every mode you touched, as the last thing in
   the description.

For step 4, run the suite yourself and paste what it printed:

    $ ./tools/test.sh -m 0 -a 0 -t single -D 1 -f
    [ test_1787634759 ] > Init test for hash type 0.
    [ test_1787634759 ] [ Type 0, Attack 0, Mode single, Device-Type Cpu, Kernel-Type Optimized, Vector-Width 1 ] > OK : 0/8 not found, 0/8 not matched, 0/8 timeout, 0/8 skipped
    [ test_1787634759 ] [ Type 0, Attack 0, Mode single, Device-Type Cpu, Kernel-Type Optimized, Vector-Width 4 ] > OK : 0/8 not found, 0/8 not matched, 0/8 timeout, 0/8 skipped

`-D 1 -f` is for a machine with no GPU, where hashcat runs on the CPU backend
and needs `--force`. Drop both on a machine with a real device. Run the vector
widths the suite offers, not just the first one: a bug in a kernel often shows
up at width 4 and not at width 1.

If a mode you touched cannot be tested on your hardware, say so explicitly
rather than leaving the output out.

---

# Part 2: instructions for AI coding agents

**Everything above this line applies to you unchanged.** This part does not
replace part 1, it adds to it. Where part 1 says something is optional or
recommended for a human, and this part says it is required, this part wins.

The reason for the difference is not distrust. It is that the work part 1 leaves
optional is work a human has to pay for in hours and you do not. A human who
skips the test module has made a reasonable trade. You have not made a trade at
all, you have just left it out.

## Do not sign commits as an AI

No `Co-Authored-By:` trailer naming a model or an assistant, and no "Generated
with" line either. Pull requests to this repository are squash merged, which
concatenates every commit message on the branch, so one trailer per commit
becomes a wall of trailers in master.

Leave it out when the commit is written. Stripping it afterwards means a force
push on a branch that is already under review, which is worse for everyone than
never adding it.

Commit as the human you are working for, using the `user.name` and `user.email`
they have configured. Do not set an identity of your own.

## Write the test module, you have no excuse

If the change adds a hash mode, add `tools/test_modules/mXXXXX.pm` in the same
pull request. The kernel and `src/modules/module_XXXXX.c` you just wrote already
contain everything the test module needs to know, so producing one costs you
almost nothing, and without it the mode ships with no test coverage at all.

Then run it, and put the output in the pull request. A test module you wrote but
never executed is worth less than none, because it looks like coverage.

## Never invent output

Every command, every hash, every exit code and every line of hashcat or
`tools/test.sh` output in a commit message, a pull request or an issue must be
something you actually ran and actually read back.

Do not reconstruct plausible output from memory of what the format looks like.
Do not paste the before result from one run and the after result from a
different build. Do not write "this should now crack" where the reader is
expecting "this cracks, here is the run".

If you could not run something, say which thing and why, in the pull request,
in a sentence. That is an acceptable outcome. Presented output that never
happened is not, and it is the single fastest way to make a reviewer distrust
every other number in the patch.

## Verify, do not assert

Before you claim a fix works, run the reproduction command on both sides of the
change, with `rm -rf kernels/` in between if a kernel changed, and read the exit
code. Before you claim nothing else regressed, run `tools/test.sh` for the modes
you touched and for the modes that share the code you edited.

A kernel that compiles is not a kernel that works. A self-test vector that
passes is not a mode that cracks real hashes: a self-test vector is one input,
often a degenerate one, and it is entirely normal for it to pass while the mode
is broken for everything else.

## Stay inside the change you were asked for

Part 1 asks for one problem per pull request, and that is easy for you to
violate by accident, because you can see the other problems while you are in
there. Note them for the human, in the pull request or separately. Do not fix
them in the same branch.

The same applies to reformatting, renaming and tidying code you happened to
read. If it is not the problem being solved, leave it alone.

## Run the ASCII check, do not eyeball it

Actually run

    git diff -U0 <base>...HEAD | grep '^+' | grep -nP '[^\x00-\x7F]'

and read the result. Models emit en dashes, em dashes and curly quotes without
intending to, in prose and in code comments alike, and they are invisible in a
diff. This check is cheap and it is not optional for you.

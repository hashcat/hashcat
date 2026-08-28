# Notes for AI coding agents

Contributions written with an AI coding agent are welcome. This file is the part an agent needs that a human contributor already knows.

[CONTRIBUTING.md](CONTRIBUTING.md) is the policy, including the code style, and every sentence of it binds you. Read it before you touch anything.

## Build and test

    make                       # builds ./hashcat and libhashcat.so
    ./tools/test_edge.sh -m 0  # unit test for one mode
    ./tools/test_edge.sh -h    # all options

With only `-m`, the suite covers every attack type, kernel type, target type and vector width for that mode. Add `-D 1 -f` on a machine with no GPU, where hashcat runs on the CPU backend and needs `--force`.

Hashcat caches compiled kernels. `test_edge.sh` clears that cache itself. When you run hashcat directly after a change under `OpenCL/`, run `rm -rf kernels/` first, or you will measure the old binary and conclude the change did nothing.

## A build is not a result

A kernel that compiles is not a kernel that works, and a self-test vector that passes is not a mode that cracks. A self-test vector is one input, often a degenerate one. It is entirely normal for it to pass while the mode is broken for everything else.

Before you report a fix, run the reproduction command on both sides of the change, with `rm -rf kernels/` in between if a kernel moved, and read the exit code. Before you report that nothing regressed, run `test_edge.sh` for the modes you touched and for the modes that share the code you edited.

## Never present output you did not run

Every command, hash, exit code and line of output in a commit message, a pull request or an issue has to be something you actually ran and read back.

Do not reconstruct plausible output from memory of the format. Do not pair a before result from one run with an after result from a different build. Do not write "this should now crack" where the reader expects "this cracks, here is the run".

If you could not run something, name the thing and say why, in one sentence. That is a fine outcome. Invented output is not, and it is the fastest way to make a reviewer distrust every other number in the patch.

## Write less

Agent written pull requests are usually two or three times longer than they need to be, and so are the comments they add to code.

For the pull request, follow the order in CONTRIBUTING.md and stop when the reader can reproduce the problem and knows what caused it. One or two sentences of summary, the command, the explanation. Nothing about how the work went.

For comments in code, match the density of the code around you. Hashcat sources carry few comments, and the ones they carry say why something is done, not what the next line does. A comment restating the code is worse than no comment.

## Leave your session out of the patch

The pull request carries commands and their output. It does not carry a report on your working process.

Take out the scratch paths, the machine names, the names of harnesses you wrote for yourself, and every sentence that is a status update rather than a result. "All checks are passing now" and "the fix is complete and verified" tell the reviewer nothing they cannot see from the run you pasted, and they read as filler. Paste the run instead.

## Say where you deviate

If you cannot follow something in CONTRIBUTING.md, say so in the pull request: which rule, and why. One sentence.

A stated deviation gets discussed. A silent one gets found in review and costs everybody a round trip.

## Review your own pull request at full strength

Pull requests here are checked with an AI agent of our own, run at the highest reasoning and effort setting available to it. Do the same to your own patch before you send it.

The setting is the whole point. A patch written and checked at a low setting, then reviewed at a high one, comes back with findings you could have found yourself. That gap costs you a review cycle and costs us one, for work neither side needed to do. Run the strongest check your tool offers, act on what it reports, and send the result.

## Run the ASCII check, do not eyeball it

    git diff -U0 master...HEAD | grep '^+' | grep -nP '[^\x09\x20-\x7E]'

Models emit en dashes, em dashes and curly quotes without intending to, in prose and in code comments alike, and they are invisible in a diff. CONTRIBUTING.md has the rule. This is how you check it.

## Write the test module

If the change adds a hash mode, add `tools/test_modules/mXXXXX.pm` in the same pull request, and run it. The kernel and `src/modules/module_XXXXX.c` you just wrote already contain everything the test module needs to know.

CONTRIBUTING.md leaves this optional, because for a human it is hours of work against a mode that may be worth having either way. It costs you almost nothing, so write it. A test module you wrote but never executed is worth less than none, because it looks like coverage.

## Stay inside the change you were asked for

One problem per pull request, and you can violate that by accident, because you can see the other problems while you are in there. Note them for the human, separately. Do not fix them on the same branch.

The same goes for reformatting, renaming and tidying code you happened to read. If it is not the problem being solved, leave it alone.

## Attribution

Commit as the human you are working for, using the `user.name` and `user.email` they have configured. Do not invent an identity of your own.

Whether an AI assistant is credited in the commit message is the human's call, not yours. A `Co-Authored-By:` trailer naming a model is accepted here, and leaving it out is accepted.

What we ask is that it appears once. Pull requests are merged with a merge commit, so every commit message on the branch survives into master. A branch of 100 commits that each carry the trailer puts 100 copies of it in the log. Put it on one commit of the pull request, or in the pull request description, or leave it out entirely.

# Attack order

Large hash lists today mostly contain salted hashes, usually with one hash per salt. The order in which hashcat pairs candidates with salts therefore determines how soon a salt is cracked. Once a salt is cracked, hashcat skips it for the rest of the run.

This document describes that order. It is the same for every attack and every hash-mode.

## Every uncracked salt sees a part before the next one

Hashcat assigns each device a chunk of base words, such as wordlist lines. The device generates candidates from those base words using rules, a mask or a second wordlist, one amplifier part at a time.

Hashcat prepares each part once and tests it against every uncracked salt before it prepares the next part. Cracked salts are skipped from then on.

A slow hash runs separate init, loop and comp kernels. For a slow hash, preparing a part means generating its candidates, which includes running the amplifier kernel and performing the UTF-16 conversion required by some hash-modes. Both operations run once for all salts rather than once per salt. A fast hash generates its candidates inside its kernel, so what its salts share is the part's slice of the rules, the mask or the second wordlist.

## Which attacks use it

This order applies to fast and slow hashes, to straight, combinator, mask, hybrid and PCFG attacks, and to the benchmark and `--speed-only`.

A chunk whose candidates are already complete, as they are with `-S`, has a single part, so it is tested against one salt after another as a whole. The order then cracks no salt sooner, but the chunk is still prepared once for all salts.

Attack mode 9 pairs each base word with one salt and tests all of those pairs in the same launch, so its salts need no order. A cracked salt is not skipped there, because the same launch carries the words of the other salts.

## What the order does not change

The order does not reduce the work needed to exhaust a keyspace. Each salt is cracked by the same candidate after the same number of launches for that salt. The order determines when those cracks occur, which matters for any run that is stopped before it finishes.

# Attack order for slow hashes

For slow hashes, almost all of the runtime is spent computing the hash for each combination of candidate and salt. Large hash lists today mostly contain salted hashes, usually with one hash per salt. The order in which hashcat pairs candidates with salts therefore determines how soon a salt is cracked. Once a salt is cracked, hashcat skips it for the rest of the run.

This document describes the two orders and which attacks use each one. It applies to slow hashes, which are hash-modes that run separate init, loop and comp kernels. For fast hashes, candidates are processed in a single kernel, so there is no choice between these two orders.

## The two orders

Hashcat assigns each device a chunk of base words, such as wordlist lines. The device generates candidates from those base words using rules, a mask or a second wordlist, one amplifier part at a time.

In the salt outer order, hashcat tests all candidates in a chunk against the first salt, then against the second salt, and so on.

In the salt inner order, hashcat generates one part of the chunk's candidates and tests those candidates against every uncracked salt before generating the next part. Cracked salts are skipped from then on. Generating a part includes running the amplifier kernel and performing the UTF-16 conversion required by some hash-modes, so both operations run once for all salts rather than once per salt.

## Which attacks use each order

For slow hashes, hashcat uses the salt inner order for straight, combinator, mask and hybrid attacks, and for attacks whose candidates are generated on the host, such as PCFG.

A chunk whose candidates are already complete, as they are with `-S`, has a single part. Its launches run one per salt in the same sequence as in the salt outer order, so no salt is cracked sooner. With the salt inner order, the chunk is prepared once for all salts.

Attack mode 9 has its own pairing of each base word with one salt. Hashcat uses the salt outer order for fast hashes, the benchmark and `--speed-only`. The benchmark and `--speed-only` measure a single launch.

## What neither order changes

Neither order reduces the work needed to exhaust a keyspace. Under either order, each salt is cracked by the same candidate after the same number of launches for that salt. The order determines when those cracks occur, which matters for any run that is stopped before it finishes.

## Generic password candidate interface, aka "slow candidates" mode ##

Option `-S`/`--slow-candidates` makes hashcat generate complete password candidates on the host before sending them to a compute device. It is available with attack modes 0, 1, 3, 4, 5, 6, 7, 8 and 12, and it forces the backend vector width to 1. It cannot be combined with `--stdout`, benchmark mode, or candidates read from stdin.

For the PCFG attack (`-a 4`), the option also selects the host generator instead of the feed's device-side generator. See `hashcat-pcfg.md`. A brain client enables slow-candidates mode automatically and accepts the same attack modes: 0, 1, 3, 4, 5, 6, 7, 8 and 12.

Generating candidates on the host is useful for slow hashes, fast hashes with many salts, and attacks whose small base wordlist is expanded by a large ruleset. In those cases the device often needs fewer candidates per second than the host can prepare, while fully expanded candidates give hashcat enough independent work to keep every device busy.

A traditional workaround is to pipe hashcat's `--stdout` output into another hashcat process. That loses an exact ETA and straightforward keyspace distribution, and makes integration with overlays such as Hashtopolis harder. Slow-candidates mode keeps the generator inside the same session.

For example, consider one word expanded by a large ruleset:

```
$ wc -l wordlist.txt
1 wordlist.txt
$ wc -l pattern.rule
99092 pattern.rule
```

Without `-S`, the small base wordlist can leave the device underused:

```
$ ./hashcat -m 400 example400.hash wordlist.txt -r pattern.rule --speed-only
...
Speed.#2.........:      145 H/s (0.07ms)
```

With `-S`, hashcat applies the rules on the host and sends the expanded candidates to the device:

```
$ ./hashcat -m 400 example400.hash wordlist.txt -r pattern.rule --speed-only -S
...
Speed.#2.........:   361.3 kH/s (3.54ms)
```

The host-to-device transfer still has a cost, so `-S` is not automatically faster. It is most useful when candidate generation or a lack of independent base words would otherwise leave the compute device idle.

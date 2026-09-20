# The hashcat tuning database

Autotune measures your device on every run and picks a launch size for it. The tuning database is
how you overrule that measurement, either because you know better or because autotune cannot see
what you are after.

This document explains what the database is, how hashcat picks a row out of it, and how to write a
row of your own. The format reference lives beside the files, in `tunings/README.md`. This is the
part that tells you why you would want to.

## What it is

Every file ending in `.hctune` under the `tunings` folder is read at startup. There is no single
database file. hashcat loads all of them, in whatever order the directory hands them over, and the
rows go into one table. A shipped release carries 322 rows across 14 files, plus 329 alias
definitions.

The split into files is for the people maintaining them, not for hashcat. `Modules_default.hctune`
holds rows that apply broadly, `Module_09300.hctune` holds the rows for scrypt, `Device_GB10.hctune`
holds the rows for one GPU. Your own file sits beside them and is read the same way.

The database is skipped entirely for `--help`, `-I`, `--hash-info`, `--keyspace`, `--left`,
`--show`, `--version` and `--identify`, because none of those launch a kernel.

## What a row says

Six columns. The first three decide whether the row applies, the last three are what it sets.

```
#Device                    Attack  Hash    Vector  Kernel  Kernel
#Name                      Kern    Type    Width   Accel   Loops

DEVICE_TYPE_CPU            *       6100    1       A       A
ALIAS_nv_sm50_or_higher    1       1000    1       128     A
```

- **Device-Name** is the device name hashcat prints at startup, with every space replaced by an
  underscore. It can also be an alias, one of the two device type names, or `*` for every device.
- **Attack-Kern** is 0 for a wordlist attack, 1 for the combinator kernel, which attack modes 6 and
  7 also use, 3 for a mask attack, or `*`.
- **Hash-Type** is a mode number or `*`.
- **Vector-Width** is 1, 2, 4, 8, or `N` for whatever the device reports as native.
- **Kernel-Accel** and **Kernel-Loops** are 1 to 1024, `A` to leave that one to autotune, or `M` for
  the largest value that fits.

A row that sets `A` in both of the last two columns is still worth writing, because it pins the
vector width while leaving the launch size measured.

## How a device finds its row

hashcat asks for the most specific row first and gives up detail one step at a time. For a device
named `NVIDIA GeForce RTX 4090` running `-m 1000 -a 0`, the order is:

1. The name with the vendor prefix stripped, `GeForce_RTX_4090`, then the full name. A row written
   either way matches.
2. For each name, the file's own alias for it, from `Alias.hctune`.
3. Then the vendor alias hashcat derives for the device, `ALIAS_NV` here.
4. Then `DEVICE_TYPE_GPU` or `DEVICE_TYPE_CPU`.
5. Then `*`.

Each of those is tried with the exact attack mode and hash mode, then with the hash mode relaxed to
`*`, then with the attack mode relaxed, then with both. The closer a row is to your device and your
attack, the more likely it wins. If nothing matches, autotune decides and the database has had no
effect on the run.

## Vendor aliases

Two kinds of alias exist and they work differently.

`Alias.hctune` maps a card name to a name a group of rows is written under. `Tesla_K20` maps to
`ALIAS_nv_real_simd`, and so do 32 other cards. This is a list, maintained by hand, and a card that
did not exist when the list was written is not in it.

A vendor alias is derived instead of looked up. hashcat takes the vendor id the backend already
recorded when it enumerated the device, and turns it into `ALIAS_NV`, `ALIAS_AMD` or `ALIAS_INTEL`.
CUDA, HIP and Metal each hardcode that id, and an OpenCL device gets one from its vendor string, so
one field answers for every backend. A card released tomorrow gets its vendor's rows without anyone
editing a file.

Three cases are deliberately left out, because the id does not say whose silicon is underneath.
Metal reports Apple for every device it drives, including an AMD card in an Intel Mac. Mesa reports
itself. The id AMD's runtime uses for an Intel CPU is the string `GenuineIntel`, which means the
opposite of what it looks like. For those, hashcat falls back to the vendor prefix in the device
name, which covers `NVIDIA `, `AMD `, `Intel` and `Apple M`.

Vendor aliases apply to GPUs only. An AMD or Intel CPU reports its maker's vendor id exactly as that
maker's GPUs do, and without that gate a Ryzen would start taking tuning measured on a Radeon.

A vendor alias is tried after the file's own alias, so a row written for a narrower group still
beats the vendor row.

## Writing your own row

Put a file ending in `.hctune` in the `tunings` folder. Nothing else is needed. A row that gets the
device name wrong is ignored rather than reported, so check the name against what hashcat prints at
startup, and remember the underscores.

To find a Kernel-Accel value worth pinning, sweep `-n` against a hash of the mode you care about and
read the speed back. The comment block at the top of `Module_09300.hctune` walks through it for
scrypt, which is the case where it matters most.

Kernel-Accel is a multiplier on the work item count, not the work item count itself, and Kernel-Loops
is the number of iterations for a slow hash or the number of mutations for a fast one. Neither is an
OpenCL thread count. hashcat maintains that itself and there is no column for it.

## What changed in this release

Rows now match on the backend vendor id rather than on a list of 75 AMD and Intel card names. A
device whose name no file mentions receives its vendor's tunings, where before it fell through to
`DEVICE_TYPE_GPU` or to autotune.

The database also carries 13 measured Kernel-Accel rows. Before this release the column existed and
no shipped row used it, so every launch size in the database came from autotune no matter what the
row said. Those 13 rows are the ones where a measured value beats what autotune arrives at on its
own.

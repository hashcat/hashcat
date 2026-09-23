# The hashcat tuning database

Autotune measures your device on every run and picks a launch size for it. The tuning database is how you overrule that measurement, either because you know better or because autotune cannot see what you are after.

This document explains what the database is, how hashcat picks a row out of it, and how to write a row of your own. The format reference lives beside the files, in `tunings/README.md`. This is the part that tells you why you would want to.

## What it is

Every file ending in `.hctune` under the `tunings` folder is read at startup. There is no single database file. hashcat loads all of them, in whatever order the directory hands them over, and the rows go into one table. The current tree carries 322 tuning rows across 12 files, plus 329 alias definitions in `Alias.hctune`.

The split into files is for the people maintaining them, not for hashcat. `Modules_default.hctune` holds broadly applicable rows and `Device_GB10.hctune` holds rows for one GPU family. Several module files contain measurement instructions but no rows. `Module_09300.hctune` is the scrypt example. Your own file sits beside them and is read the same way.

The database is skipped entirely for `--help`, `-I`, `--hash-info`, `--keyspace`, `--left`, `--show`, `--version` and `--identify`, because none of those launch a kernel.

## What a row says

Six columns. The first three decide whether the row applies, the last three are what it sets.

```
#Device                    Attack  Hash    Vector  Kernel  Kernel
#Name                      Kern    Type    Width   Accel   Loops

DEVICE_TYPE_CPU            *       6100    1       A       A
ALIAS_nv_sm50_or_higher    1       1000    1       128     A
```

- **Device-Name** is the device name hashcat prints at startup, with every space replaced by an underscore. It can also be an alias, one of the two device type names, or `*` for every device.
- **Attack-Kern** is 0 for a wordlist kernel, 1 for the combinator kernel also used by attack modes 6 and 7, 3 for a mask kernel, 4 for a feed-owned device kernel used by PCFG and table attacks, or `*`.
- **Hash-Type** is a mode number or `*`.
- **Vector-Width** is 1, 2, 4, 8, or `N` for whatever the device reports as native.
- **Kernel-Accel** is 1 to 1024, `A` for autotune, `M` for 1024, or `N` for the device processor count.
- **Kernel-Loops** is a positive number or `A`. For attack kernels 0, 1 and 3, `M` selects that kernel's maximum. A fixed value is used only when it fits the runtime limits of the selected mode.

A row that sets `A` in both of the last two columns is still worth writing, because it pins the vector width while leaving the launch size measured.

## How a device finds its row

The lookup has two nested kinds of fallback, and their order matters. First hashcat performs the full search with the artificial name `MODULE_<device id>_<device name>`, which is where a module can register generated rows. It then searches a vendor-prefix-stripped name, where applicable, followed by the full device name.

For each name, these attack and hash combinations are tried in order:

1. Exact attack kernel and exact hash mode.
2. Any attack kernel and the exact hash mode.
3. The exact attack kernel and any hash mode.
4. Any attack kernel and any hash mode.

Within each combination, hashcat tries the device name, its `Alias.hctune` alias, the derived vendor alias, `DEVICE_TYPE_GPU` or `DEVICE_TYPE_CPU`, and finally the global `*` device row. Consequently, a global row for an exact attack and hash can beat a device-specific row whose attack or hash column is a wildcard. The artificial module-name search uses the same fallbacks and can therefore finish on a device-type or global row before ordinary device names are searched. If no row matches, autotune decides.

## Vendor aliases

Two kinds of alias exist and they work differently.

`Alias.hctune` maps a card name to a name a group of rows is written under. `Tesla_K20` maps to `ALIAS_nv_real_simd`, and so do 32 other cards. This is a list, maintained by hand, and a card that did not exist when the list was written is not in it.

A vendor alias is derived instead of looked up. hashcat takes the vendor id the backend already recorded when it enumerated the device, and turns it into `ALIAS_NV`, `ALIAS_AMD` or `ALIAS_INTEL`. CUDA, HIP and Metal each hardcode that id, and an OpenCL device gets one from its vendor string, so one field answers for every backend. A card released tomorrow gets its vendor's rows without anyone editing a file.

Three cases are deliberately left out, because the id does not say whose silicon is underneath. Metal reports Apple for every device it drives, including an AMD card in an Intel Mac. Mesa reports itself. The id AMD's runtime uses for an Intel CPU is the string `GenuineIntel`, which means the opposite of what it looks like. For those, hashcat falls back to the vendor prefix in the device name, which covers `NVIDIA `, `AMD `, `Intel` and `Apple M`.

Vendor aliases apply to GPUs only. An AMD or Intel CPU reports its maker's vendor id exactly as that maker's GPUs do, and without that gate a Ryzen would start taking tuning measured on a Radeon.

A vendor alias is tried after the file's own alias, so a row written for a narrower group still beats the vendor row.

## Writing your own row

Put a file ending in `.hctune` in the `tunings` folder. Nothing else is needed. A row that gets the device name wrong is ignored rather than reported, so check the name against what hashcat prints at startup, and remember the underscores.

To find a Kernel-Accel value worth pinning, sweep `-n` against a hash of the mode you care about and read the speed back. The comment block at the top of `Module_09300.hctune` walks through it for scrypt, which is the case where it matters most.

Kernel-Accel is a multiplier on the work item count, not the work item count itself, and Kernel-Loops is the number of iterations for a slow hash or the number of mutations for a fast one. Neither is an OpenCL thread count. hashcat maintains that itself and there is no column for it.

## What changed in this release

Rows now match on the backend vendor id rather than on a list of 75 AMD and Intel card names. A device whose name no file mentions receives its vendor's tunings, where before it fell through to `DEVICE_TYPE_GPU` or to autotune.

The database also carries 13 measured numeric Kernel-Accel rows for modes where a fixed value beats what autotune selects on the reference devices. Nine CPU bcrypt rows use `N` instead, setting the acceleration to the device processor count. Other rows leave acceleration on automatic.

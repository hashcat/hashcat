# test.sh usage

Hashcat's unit tests. Full background in
[docs/hashcat-plugin-development-guide.md](../docs/hashcat-plugin-development-guide.md).

### Install

```
cd tools
./install_dependencies.sh   # system packages, cpanm, pyenv, and the -g tools
exec "${SHELL}"             # pick up the PATH lines the above appended
./install_modules.sh        # perl and python modules the test.pl oracles need
```

### Run

```
cd ..
make -j"$(nproc)"           # test.sh runs the hashcat in the repo root
./tools/test.sh -m 0 -t all
./tools/test.sh --help      # all options
```

With `-g`, which builds a real container and cracks that as well as the oracle:

```
./tools/test.sh -g              # every mode it can build one for
./tools/test.sh -g -m 17200     # just that mode
./tools/test.sh -g -m 17010 -a all -t all -V all
```

Run it as yourself, never under `sudo`. Where a generator needs root it asks per
command, for that command only.

### What `-g` builds

`-g` builds a real encrypted container and cracks that as well as the mode's
normal `test.pl` oracle, never instead of it. On its own it runs every mode
below; with a `-m` outside them it says so and stops. A missing tool is a skip
that names it, for that format only, repeated in a summary at the end.

| Format | Modes | Tools | Without them |
|---|---|---|---|
| GPG | 17010, 17020, 17030, 17040, 17050 | `gpg2`, `gpg1`, `gpg2john` | No `gpg1`: only what `gpg2` writes by default is covered, which drops the classic S2K combinations and the AES-128 (aux1) path. A note, not a skip. No `gpg2john`: skipped. |
| PKZIP | 17200, 17210, 17220, 17225, 17230 | `zip`, `zip2john` | Skipped. |
| RAR | 12500, 13000, 23700, 23800 | `rar` 6.x or older, `rar2john` | Only RAR5 (13000) is built, the RAR3 modes are skipped. 23800 has no `test.pl` oracle at all, so without `-g` it is skipped whatever is installed. |
| LUKS2 | 34100 | `cryptsetup`, `sudo` | Skipped. |

`install_dependencies.sh` installs all of it, including the three that are easy
to get wrong:

* **John jumbo** for `zip2john`, `gpg2john` and `rar2john`. No package has them:
  `apt install john` is core John and ships none of them, so the script builds
  jumbo in `$HOME/john`. Override with `ZIP2JOHN=`, `GPG2JOHN=`, `RAR2JOHN=`;
  otherwise `PATH` then `$HOME/john/run/`.
* **rar 6.12** for the RAR3 modes. No package either: `apt install rar` is 7.x,
  which writes RAR5 only, so the script fetches RARLAB's static build into
  `$HOME/rar-old`. Override with `RAR_BIN=`.
* **gpg1** is the separate `gnupg1` package, installed alongside `gnupg` rather
  than instead of it. Override with `GPG1_BIN=`.

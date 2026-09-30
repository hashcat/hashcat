# test.py usage

Hashcat's unit tests. Full background in
[docs/hashcat-plugin-development-guide.md](../docs/hashcat-plugin-development-guide.md).

### Install

```
cd tools
./install_dependencies.sh   # system packages, pyenv, and the -g tools
exec "${SHELL}"             # pick up the PATH lines the above appended
./install_modules.sh        # the python modules the .py oracles need
```

The oracles are python (`tools/test_module_runner.py` plus the per-mode
`test_modules/mXXXXX.py`), so a plain run needs only the python modules
`install_modules.sh` sets up. The perl and container tools
`install_dependencies.sh` also installs are for `-g` alone.

### Run

```
cd ..
make -j"$(nproc)"           # test.py runs the hashcat in the repo root
./tools/test.py -m 0 -t all
./tools/test.py --help      # all options
```

A plain run needs no root. Related entry points:

```
./tools/test.py --edge -m 0     # boundary cases for one mode (was test_edge.sh)
./tools/test.py --test-coverage # every mode has a runnable oracle (was test_coverage.sh)
```

With `-g`, which builds a real container and cracks that:

```
./tools/test.py -g              # every mode it can build one for
./tools/test.py -g -m 17200     # just that mode
./tools/test.py -g -m 17010 -a all -t all -V all
```

Run it as yourself, never under `sudo`. Where a generator needs root (LUKS and
TrueCrypt) it asks once at the start and keeps that grant alive for the run;
everything else builds as you.

### What `-g` builds

`-g` builds a real encrypted container or archive. For the archive formats it
cracks that in addition to the mode's normal `test_module_runner.py` oracle,
never instead of it; for the container formats (LUKS, TrueCrypt, VeraCrypt) it
cracks the freshly built container in place of the shipped one. On its own it
runs every mode below; with a `-m` outside them it says so and stops. A missing
tool is a skip that names it, for that format only, repeated in a summary at the
end.

| Format | Modes | Tools | Without them |
|---|---|---|---|
| GPG | 17010, 17020, 17030, 17040, 17050 | `gpg2`, `gpg1`, `gpg2john` | No `gpg1`: only what `gpg2` writes by default is covered, which drops the classic S2K combinations and the AES-128 (aux1) path. A note, not a skip. No `gpg2john`: skipped. |
| PKZIP | 17200, 17210, 17220, 17225, 17230 | `zip`, `zip2john` | Skipped. |
| RAR | 12500, 13000, 23700, 23800 | `rar` 6.x or older, `rar2john` | Only RAR5 (13000) is built, the RAR3 modes are skipped. 23800 has no `test_module_runner.py` oracle at all, so without `-g` it is skipped whatever is installed. |
| 7-Zip | 11600 | `7z`, `7z2john.pl`, `Compress::Raw::Lzma` | Skipped. |
| WinZip AES | 13600 | `7z`, `zip2john` | Skipped. |
| PDF | 10400, 10500, 10700 | `qpdf`, `gs`, `pdf2john.pl` | Skipped. `gs` writes the plain PDF that `qpdf` then encrypts. |
| OpenSSH key | 22931 | `ssh-keygen`, `ssh2john.py` | Skipped. |
| LUKS1 | 29511 to 29543 | `cryptsetup`, `sudo` | Skipped. |
| LUKS2 | 34100 | `cryptsetup`, `sudo` | Skipped. |
| TrueCrypt | 6211 to 6243, 29311 to 29343 | `tcplay`, `expect`, `sudo` | Skipped. The boot (system-encryption) modes are always skipped, since tcplay cannot write them. |
| VeraCrypt | 13711 to 13783, 29411 to 29483 | `veracrypt` console build | No veracrypt: skipped. At 1.26 or newer: the RIPEMD-160 modes are skipped, since 1.26 dropped them. The boot modes are always skipped, since `veracrypt --create` only writes normal volumes. |

`install_dependencies.sh` installs all of it, including the ones that are easy
to get wrong:

* **John jumbo** for `zip2john`, `gpg2john`, `rar2john`, `7z2john.pl`,
  `pdf2john.pl` and `ssh2john.py`. No package has them:
  `apt install john` is core John and ships none of them, so the script builds
  jumbo in `$HOME/john`. Override with `ZIP2JOHN=`, `GPG2JOHN=`, `RAR2JOHN=`,
  `SEVENZIP2JOHN=`, `PDF2JOHN=`, `SSH2JOHN=`; otherwise `PATH` then
  `$HOME/john/run/`.
* **rar 6.12** for the RAR3 modes. No package either: `apt install rar` is 7.x,
  which writes RAR5 only, so the script fetches RARLAB's static build into
  `$HOME/rar-old`. Override with `RAR_BIN=`.
* **gpg1** is the separate `gnupg1` package, installed alongside `gnupg` rather
  than instead of it. Override with `GPG1_BIN=`.
* **veracrypt 1.25.9** for the RIPEMD-160 modes, which 1.26 dropped and no
  distribution still carries. The script unpacks the console `.deb` into
  `$HOME/veracrypt-1.25.9` rather than installing it, because it shares a
  package name with a system veracrypt and would downgrade it. Override with
  `VERACRYPT_BIN=`.

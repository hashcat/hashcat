# test.sh usage

Hashcat's unit tests: full background in [docs/hashcat-plugin-development-guide.md](docs/hashcat-plugin-development-guide.md).
Small summary on how to use:

### Install pre-requisites

One paste, run from anywhere inside the hashcat checkout. Steps 1 to 3 are what
every run needs. Step 4 is only for `-g`, and every part of it is optional: skip
one and `-g` records a skip that names the missing tool, for that format alone.

```
# The steps below move around, so remember where hashcat is first
HASHCAT_DIR="$(git rev-parse --show-toplevel)"

#
# 1. System packages
#
#    Three groups in one call: what pyenv needs to build a Python, what John the
#    Ripper jumbo needs to build, and the container tools -g drives. The last
#    group is what install_modules.sh installs for you in step 5, listed here so
#    one apt call covers everything.
#
sudo apt update
sudo apt install -y \
    build-essential curl git wget pkg-config yasm \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev libxml2-dev \
    libxmlsec1-dev libgmp-dev libpcap-dev libnss3-dev libkrb5-dev \
    zip gnupg gnupg1 cryptsetup

#
# 2. Perl modules, under $HOME so that none of this needs root
#    https://gwcbi.github.io/HPC/perl.html
#
mkdir -p "$HOME/.perl"
wget -O- http://cpanmin.us | perl - -l "$HOME/.perl5" App::cpanminus local::lib
eval "$(perl -I "$HOME/.perl5/lib/perl5" -Mlocal::lib="$HOME/.perl5")"
echo 'eval $(perl -I $HOME/.perl5/lib/perl5 -Mlocal::lib=$HOME/.perl5)' >> "$HOME/.bashrc"
echo 'export MANPATH=$HOME/.perl5/man:$MANPATH' >> "$HOME/.bashrc"

#
# 3. Python, through pyenv
#    https://github.com/pyenv/pyenv
#
curl https://pyenv.run | bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
PY_LATEST="$(pyenv install --list | grep -E '^\s*3\.[0-9]+\.[0-9]$' | tail -n 1 | tr -d '[:space:]')"
pyenv install -s "$PY_LATEST"
cd "$HASHCAT_DIR" && pyenv local "$PY_LATEST"
pip install --upgrade pip

#
# 4. The -g tools that no package manager has. Skip this whole step if you do
#    not use -g.
#
#    4a. John the Ripper jumbo, for zip2john, gpg2john and rar2john. Note that
#        apt install john is core John and ships none of them.
#
[ -d "$HOME/john" ] || git clone --depth 1 https://github.com/openwall/john "$HOME/john"
(cd "$HOME/john/src" && ./configure && make -sj"$(nproc)")
echo 'export PATH="$HOME/john/run:$PATH"' >> "$HOME/.bashrc"
export PATH="$HOME/john/run:$PATH"

#    4b. rar 6.12, for the RAR3 modes. apt install rar is 7.x, which can only
#        write RAR5. Static binary, no root, and test.sh looks here by default.
#
curl -sSLo /tmp/rar.tar.gz https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
mkdir -p "$HOME/rar-old"
tar xzf /tmp/rar.tar.gz -C "$HOME/rar-old" --strip-components=1
rm /tmp/rar.tar.gz

#
# 5. Perl and python modules for the test.pl oracles
#
cd "$HASHCAT_DIR/tools"
./install_modules.sh
```
# Allow local installation of perl modules (such that we don't need root)
#  https://gwcbi.github.io/HPC/perl.html
cd $HOME
mkdir .perl
wget -O- http://cpanmin.us | perl - -l $HOME/.perl5 App::cpanminus local::lib
eval $(perl -I $HOME/.perl5/lib/perl5 -Mlocal::lib=$HOME/.perl5)
echo 'eval $(perl -I $HOME/.perl5/lib/perl5 -Mlocal::lib=$HOME/.perl5)' >> .bashrc
echo 'export MANPATH=$HOME/.perl5/man:$MANPATH' >> .bashrc

# Required for installing recent Python
sudo apt update
sudo apt install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libffi-dev \
    liblzma-dev \
    libxml2-dev \
    libxmlsec1-dev \
    curl

# Install pyenv
#  https://github.com/pyenv/pyenv
curl https://pyenv.run | bash
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
pyenv install $(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1) # install latest python
pyenv local $(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1) # enable latest python
pip install --upgrade pip

# Enable LUKS2 on-the-fly crypto-container generation
sudo apt install cryptsetup

./install_modules.sh
```


### Generating real containers with `-g`

`./test.sh -g` builds a real encrypted container for the formats below and cracks
that as well as the mode's normal `test.pl` oracle, never instead of it. Every
generator is optional. When a tool is missing, the mode records a skip that names
the tool, the run carries on, and every skip is listed again in a summary at the
end, so a run that could not cover something says so rather than passing silently.

`./install_modules.sh` installs the ones a package manager can give you. Only
LUKS2 needs `sudo`. Nothing else here does.

| Format | Modes | Tools | Where to get them | Without them |
|---|---|---|---|---|
| GPG | 17010, 17020, 17030, 17040, 17050 | `gpg2`, `gpg1`, `gpg2john` | `sudo apt install gnupg gnupg1`, plus John jumbo | No `gpg1`: the classic S2K digest and cipher combinations and the AES-128 (aux1) path drop out, and only what `gpg2` produces by default is covered. This is a note, not a skip. No `gpg2john`: skipped. |
| PKZIP | 17200, 17210, 17220, 17225, 17230 | `zip`, `zip2john` | `sudo apt install zip`, plus John jumbo | Skipped. |
| RAR | 12500, 13000, 23700, 23800 | `rar`, `rar2john` | `rarlinux-x64-612.tar.gz` from rarlab.com, plus John jumbo | No `rar` at 6.x or older: only RAR5 (13000) is built and the three RAR3 modes are skipped. 23800 cannot have a `test.pl` oracle at all, so without `-g` it is skipped whatever else is installed. |
| LUKS2 | 34100 | `cryptsetup`, `sudo` | `sudo apt install cryptsetup` | Skipped. |

#### The 2john tools

`zip2john`, `gpg2john` and `rar2john` come from **John the Ripper jumbo**, which
is not what `apt install john` gives you: that is core John, and it does not ship
them. Build jumbo from https://github.com/openwall/john and either put its `run`
directory on `PATH` or point at each tool directly:

```
export ZIP2JOHN=/path/to/john/run/zip2john
export GPG2JOHN=/path/to/john/run/gpg2john
export RAR2JOHN=/path/to/john/run/rar2john
```

With no override, each one is looked up on `PATH` and then at `$HOME/john/run/`.

#### rar has to be 6.x or older

`apt install rar` installs rar 7.x, which can only create RAR5. The RAR3 modes
(12500, 23700, 23800) need the `-ma4` switch, which RARLAB dropped after 6.x, so
fetch `rarlinux-x64-612.tar.gz` from rarlab.com and set `RAR_BIN=/path/to/rar`.
`rar_test()` checks for `-ma4` itself and falls back to RAR5 only, with a skip
that says why, rather than producing archives of the wrong format.

#### gpg1 is a separate package

The classic S2K variants come from GnuPG 1.4, which Debian and Ubuntu ship as
`gnupg1` alongside `gnupg`, not instead of it. Installing it adds a `gpg1`
binary; set `GPG1_BIN=/path/to/gpg1` if yours lives somewhere else.

### Example usage
```
./test.sh -m 0 -t all
```
All options: `./test.sh --help`

Run it as yourself, never under `sudo`. Where a generator needs root it asks per
command, for that command only. Running the whole script as root moves `$HOME`,
so the perl modules `install_modules.sh` put in your `~/.perl5` are no longer on
`@INC`, `test.pl` cannot load a module for any mode, and the run reports
`Error : 0/0 not found` for all of them. test.sh stops with a message rather than
let that happen.

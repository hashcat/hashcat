#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Test suite dependency installer.
##
## Everything the suite needs that is not a perl or python module: the system
## packages, the cpanm and pyenv bootstraps that install_modules.sh builds on,
## and the three -g generator tools that no package manager carries. Run this
## first, then ./install_modules.sh.
##
## Safe to run again. Every step checks for what it installs and skips it.

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

IS_APPLE=0

if [ "$(uname -s)" = "Darwin" ]; then
  IS_APPLE=1
fi

# Names of everything that did not install, so the summary says which rather than how many.

FAILED=""

note_failure ()
{
  FAILED="${FAILED} $1"
}

# System packages, in one call.
#
# Three groups: what pyenv needs to build a Python, what John the Ripper jumbo needs to build, and
# the container tools -g drives. g++ is called out because Digest::MurmurHash3 is the one C++ module
# install_modules.sh builds, so without it that module alone fails, with "cannot execute cc1plus".

APT_PACKAGES="build-essential g++ curl git wget pkg-config yasm
libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libncursesw5-dev
xz-utils tk-dev libffi-dev liblzma-dev libxml2-dev libxmlsec1-dev
libgmp-dev libpcap-dev libnss3-dev libkrb5-dev
zip gnupg gnupg1 cryptsetup tcplay expect"

install_packages ()
{
  echo "> System packages ..."

  if [ ${IS_APPLE} -eq 1 ]; then
    echo "  skipped, this script only knows apt. Install the equivalents of:"
    echo "  $(echo ${APT_PACKAGES} | tr '\n' ' ')"
    return
  fi

  if ! command -v apt-get > /dev/null 2>&1; then
    echo "  skipped, no apt-get. Install the equivalents of:"
    echo "  $(echo ${APT_PACKAGES} | tr '\n' ' ')"
    return
  fi

  local sudo_cmd=""

  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo > /dev/null 2>&1; then
      sudo_cmd="sudo"
    else
      echo "  skipped, not root and no sudo. Run:"
      echo "    apt-get install -y $(echo ${APT_PACKAGES} | tr '\n' ' ')"
      note_failure "system-packages"
      return
    fi
  fi

  ${sudo_cmd} apt-get update > /dev/null 2>&1

  if ${sudo_cmd} apt-get install -y ${APT_PACKAGES} > /dev/null 2>&1; then
    echo "  ok"
  else
    echo "  FAILED. Run by hand to see why:"
    echo "    ${sudo_cmd} apt-get install $(echo ${APT_PACKAGES} | tr '\n' ' ')"
    note_failure "system-packages"
  fi
}

# cpanm and local::lib, into ${HOME}, so that install_modules.sh needs no root either.

install_cpanm ()
{
  echo "> cpanm and local::lib ..."

  if [ -x "${HOME}/.perl5/bin/cpanm" ] || command -v cpanm > /dev/null 2>&1; then
    echo "  already present"
  elif wget -qO- http://cpanmin.us | perl - -l "${HOME}/.perl5" App::cpanminus local::lib > /dev/null 2>&1; then
    echo "  ok"
  else
    echo "  FAILED"
    note_failure "cpanm"
    return
  fi

  # local::lib has to be in the environment of every later shell, not only this one.

  if ! grep -q 'local::lib' "${HOME}/.bashrc" 2> /dev/null; then
    echo 'eval $(perl -I $HOME/.perl5/lib/perl5 -Mlocal::lib=$HOME/.perl5)' >> "${HOME}/.bashrc"
    echo 'export MANPATH=$HOME/.perl5/man:$MANPATH' >> "${HOME}/.bashrc"
  fi
}

# pyenv, so install_modules.sh has a Python it can install into. It installs the interpreter itself.

install_pyenv ()
{
  echo "> pyenv ..."

  if [ -d "${HOME}/.pyenv" ] || command -v pyenv > /dev/null 2>&1; then
    echo "  already present"
  elif curl -sS https://pyenv.run | bash > /dev/null 2>&1; then
    echo "  ok"
  else
    echo "  FAILED"
    note_failure "pyenv"
    return
  fi

  # pyenv's own installer writes to .bashrc on some versions and not on others, and the line it
  # writes is not character for character the one below, so match on the variable name rather than
  # on the whole line. Otherwise a second run leaves two of them.

  if ! grep -q 'PYENV_ROOT' "${HOME}/.bashrc" 2> /dev/null; then
    {
      echo 'export PYENV_ROOT="$HOME/.pyenv"'
      echo '[ -d "$PYENV_ROOT/bin" ] && export PATH="$PYENV_ROOT/bin:$PATH"'
      echo 'eval "$(pyenv init - bash)"'
    } >> "${HOME}/.bashrc"
  fi
}

# The -g tools with no package. Everything below is optional: without one, -g records a skip that
# names it and carries on, for that format only.

# John the Ripper jumbo, for zip2john, gpg2john and rar2john. Note that apt install john is core
# John, which ships none of them. test.sh looks on PATH and then at ${HOME}/john/run.

install_john ()
{
  echo "> John the Ripper jumbo ..."

  if command -v zip2john > /dev/null 2>&1 || [ -x "${HOME}/john/run/zip2john" ]; then
    echo "  already present"
    return
  fi

  if [ ! -d "${HOME}/john" ]; then
    if ! git clone --depth 1 https://github.com/openwall/john "${HOME}/john" > /dev/null 2>&1; then
      echo "  FAILED to clone"
      note_failure "john-jumbo"
      return
    fi
  fi

  if ( cd "${HOME}/john/src" && ./configure > /dev/null 2>&1 && make -sj"$(nproc)" > /dev/null 2>&1 ); then
    echo "  ok, ${HOME}/john/run"
  else
    echo "  FAILED to build. Build it by hand in ${HOME}/john/src to see why."
    note_failure "john-jumbo"
    return
  fi

  if ! grep -q 'john/run' "${HOME}/.bashrc" 2> /dev/null; then
    echo 'export PATH="$HOME/john/run:$PATH"' >> "${HOME}/.bashrc"
  fi
}

# rar 6.12, for the RAR3 modes. apt install rar is 7.x, which can only write RAR5, so the -ma4
# switch the RAR3 modes need is gone. This is a static binary and needs no root, and test.sh looks
# at ${HOME}/rar-old by default.

install_rar ()
{
  echo "> rar 6.12 ..."

  if [ -x "${HOME}/rar-old/rar" ]; then
    echo "  already present"
    return
  fi

  local tarball="${HOME}/rarlinux-x64-612.tar.gz"

  if ! curl -sSLo "${tarball}" https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz; then
    echo "  FAILED to download"
    note_failure "rar"
    return
  fi

  mkdir -p "${HOME}/rar-old"

  if tar xzf "${tarball}" -C "${HOME}/rar-old" --strip-components=1; then
    echo "  ok, ${HOME}/rar-old/rar"
  else
    echo "  FAILED to extract"
    note_failure "rar"
  fi

  rm -f "${tarball}"
}

# veracrypt 1.25.9, for the RIPEMD-160 modes. 1.26 dropped them, and no distribution carries an
# older one, so take the console .deb and unpack it rather than install it: it has the same package
# name as a system veracrypt and installing it would downgrade that.

install_veracrypt ()
{
  echo "> veracrypt 1.25.9 console ..."

  if [ -x "${HOME}/veracrypt-1.25.9/usr/bin/veracrypt" ]; then
    echo "  already present"
    return
  fi

  if ! command -v dpkg-deb > /dev/null 2>&1; then
    echo "  skipped, no dpkg-deb to unpack it with"
    note_failure "veracrypt"
    return
  fi

  local deb="${HOME}/veracrypt-console.deb"
  local url="https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_1.25.9/veracrypt-console-1.25.9-Ubuntu-23.04-amd64.deb"

  if ! curl -sSLo "${deb}" "${url}"; then
    echo "  FAILED to download"
    note_failure "veracrypt"
    return
  fi

  mkdir -p "${HOME}/veracrypt-1.25.9"

  if dpkg-deb -x "${deb}" "${HOME}/veracrypt-1.25.9"; then
    echo "  ok, ${HOME}/veracrypt-1.25.9/usr/bin/veracrypt"
  else
    echo "  FAILED to unpack"
    note_failure "veracrypt"
  fi

  rm -f "${deb}"

  # test.sh looks for veracrypt on PATH, so it has to be told where this one is.

  if ! grep -q 'VERACRYPT_BIN' "${HOME}/.bashrc" 2> /dev/null; then
    echo 'export VERACRYPT_BIN="$HOME/veracrypt-1.25.9/usr/bin/veracrypt"' >> "${HOME}/.bashrc"
  fi
}

install_packages
install_cpanm
install_pyenv
install_john
install_rar
install_veracrypt

echo

if [ -n "${FAILED}" ]; then
  echo "> These did not install:"

  for item in ${FAILED}; do
    echo "    ${item}"
  done

  echo
  echo "  The suite still runs. Each missing tool is reported again, by name, by the run"
  echo "  that wanted it."
  echo
fi

echo "> Now run ${TDIR}/install_modules.sh for the perl and python modules."
echo "  Open a new shell first, or source ${HOME}/.bashrc, so cpanm and pyenv are on PATH."

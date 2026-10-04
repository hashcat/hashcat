#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Test suite installation helper script

IS_APPLE=0
IS_APPLE_SILICON=0

UNAME=$(uname -s)
if [ "${UNAME}" == "Darwin" ]; then
  IS_APPLE=1
fi

if [ ${IS_APPLE} -eq 1 ]; then
  if [ "$(sysctl -in hw.optional.arm64 2>/dev/null)" == "1" ]; then
    IS_APPLE_SILICON=1
  fi
fi

# Sum of all exit codes
ERRORS=0

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Names of everything that did not install, so the summary can say which rather than how many.

FAILED_MODULES=""

# checks for pyenv

pyenv_enabled=0

which pyenv &>/dev/null
if [ $? -eq 0 ]; then

  if [[ $(pyenv version-name) != "system" ]]; then

    # active session detected
    pyenv_enabled=1

  else

    # The newest final 3.x release pyenv offers. The patch number needs more than one digit: with a
    # single [0-9] the pattern skips 3.14.10 and settles on 3.14.7, quietly installing an older python
    # than the one asked for. The suffixed builds, 3.13.3t and the release candidates, stay out because
    # they carry something after the patch number.

    latest=$(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]+$" | tail -n 1)

    if [ $IS_APPLE -eq 1 ]; then
      if [ $IS_APPLE_SILICON -eq 0 ]; then
        # workaround but with pyenv and Apple Intel with brew binutils in path
        remove_path="$(brew --prefix)/opt/binutils/bin"
        PATH=$(echo "$PATH" | tr ':' '\n' | awk '$0 != "${remove_path}"' | xargs | sed 's/ /:/g')
        export $PATH
      fi
    fi

    # install the latest version or skip it if it is already present
    pyenv install -s ${latest}

    # Enable it where the suite actually runs, which is the repository root, not wherever this
    # script was started from. pyenv local writes .python-version into the current directory and
    # applies to that directory and below, so a pin written in tools/ leaves test.py, which runs
    # from the root, on the system python. The oracles then shell out to a bare python3 and get
    # one without pycryptodome:
    #
    #   ModuleNotFoundError: No module named 'Crypto'
    #
    # A pin at the root covers tools/ as well, so this is the one place to put it.

    ( cd "${TOOLS_DIR}/.." && pyenv local ${latest} )
    if [ $? -eq 0 ]; then
      pyenv_enabled=1
    fi

  fi
fi

# Without pyenv there is no interpreter this script is allowed to install into, so there is nothing
# left for it to do. It used to carry on to the check at the end, which runs under whatever python3 is
# on PATH. That check passes wherever the system python happens to carry pycryptodome already, so the
# script could report the suite as usable and exit 0 having installed none of the pinned packages.

if [ ${pyenv_enabled} -eq 0 ]; then

  echo "! pyenv is not usable, so there is nothing to install into. Nothing was installed."
  echo
  echo "  tools/install_dependencies.sh installs pyenv. Run it, then open a new shell so the lines it"
  echo "  appends to .bashrc take effect. Sourcing .bashrc from a script will not do, because the stock"
  echo "  one returns before those lines when the shell is not interactive."

  exit 1

fi

echo "> Installing python3 deps ..."

# One file lists what the test modules import, so a contributor writing a module has one place
# to read and one place to add to.

pip3 install -r "${TOOLS_DIR}/requirements.txt"
ERRORS=$((ERRORS+$?))

# A python import that fails inside a test module is invisible from here. The module shells out
# to python3 and reads stdout only, so a dead dependency produces a wrong hash rather than an
# error. Import each one now, while the cause is still in front of you.

PYTHON_MODULES="Crypto cryptography argon2 gostcrypto crypt_r"

for python_module in ${PYTHON_MODULES}; do

  if python3 -c "import ${python_module}" > /dev/null 2>&1; then
    echo "  ok      ${python_module}"
  else
    echo "  FAILED  ${python_module}"
    FAILED_MODULES="${FAILED_MODULES} ${python_module}"
  fi

done

echo

if [ -n "${FAILED_MODULES}" ]; then

  echo "> These did not install:"

  for python_module in ${FAILED_MODULES}; do
    echo "    ${python_module}"
  done

  echo

fi

# The check that actually matters. tools/test_module_runner.py loads only the module for the mode it
# is asked for, so a missing dependency costs the modes that need it and nothing else. What this
# catches is the case where the python environment itself is unusable, which makes the suite report
# "Error : 0/0 not found" on every mode and reads as hashcat failing rather than as a setup problem.

if python3 "${TOOLS_DIR}/test_module_runner.py" single 1000 2> /dev/null | grep -q hashcat; then

  # pip failing is a setup failure even when mode 1000 still works, because the suite would then run
  # against whatever versions are already installed rather than against the pinned ones.

  if [ ${ERRORS} -ne 0 ]; then

    echo "[ FAIL ] tools/test_module_runner.py can generate hashes, but pip did not install the pinned set"
    echo "         in tools/requirements.txt. The suite would run against whatever versions are already"
    echo "         there. Read the pip output above and run this script again."

    exit 1

  fi

  echo "[  OK  ] tools/test_module_runner.py can generate hashes, the suite is usable"

  if [ -n "${FAILED_MODULES}" ]; then
    echo "         The modules above only affect the hash modes that need them."
  fi

  exit 0

fi

echo "[ FAIL ] tools/test_module_runner.py cannot generate hashes. The suite would report 'Error : 0/0' on"
echo "         every mode, which is a setup failure and not a hashcat one."

if [ -n "${FAILED_MODULES}" ]; then
  echo "         Fix the modules above and run this script again."
else
  echo "         Every package imported, so run the check by hand to see what it says:"
  echo "         python3 tools/test_module_runner.py single 1000"
fi

exit 1

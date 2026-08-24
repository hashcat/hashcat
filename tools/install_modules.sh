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

# Perl prints a warning block to stderr whenever LC_* names a locale the system does not have.
# Several module test suites capture the output of a subprocess and compare it, so that injected
# text makes them fail. The module is fine, the environment is not. Pin a locale that always exists.

export LC_ALL=C.UTF-8

# gcc 14 made an implicit function declaration an error rather than a warning. Some old XS modules
# still rely on one and no longer compile, Crypt::DES among them, which alone takes Crypt::DES_EDE3
# and every Authen::Passphrase variant down with it. ExtUtils::MakeMaker ignores CFLAGS, so the flag
# has to travel in PERL_MM_OPT. Anything local::lib already put there has to be kept.

CCFLAGS_COMPAT="CCFLAGS=-Wno-implicit-function-declaration"

if [ -n "${PERL_MM_OPT:-}" ]; then
  export PERL_MM_OPT="${PERL_MM_OPT} ${CCFLAGS_COMPAT}"
else
  export PERL_MM_OPT="${CCFLAGS_COMPAT}"
fi

# Names of everything that did not install, so the summary can say which rather than how many.

FAILED_MODULES=""

install_module ()
{
  local module="$1"

  if cpanm "${module}" > /dev/null 2>&1; then
    echo "  ok      ${module}"
    return 0
  fi

  echo "  FAILED  ${module}"

  FAILED_MODULES="${FAILED_MODULES} ${module}"

  return 1
}

echo "> Installing perl deps ..."

if [ ${IS_APPLE} -eq 1 ]; then
  # workaround for test failed with Net::SSLeay on Apple
  cpanm --notest Net::SSLeay
else
  cpanm Net::SSLeay
fi

ERRORS=$((ERRORS+$?))

PERL_MODULES="
Authen::Passphrase::LANManager
Authen::Passphrase::MySQL323
Authen::Passphrase::NTHash
Authen::Passphrase::PHPass
Bitcoin::Crypto
Bitcoin::Crypto::Base58
Compress::Zlib
Convert::EBCDIC
Crypt::Argon2
Crypt::AuthEnc::GCM
Crypt::Blowfish
Crypt::Camellia
Crypt::CBC
Crypt::Cipher::Serpent
Crypt::DES
Crypt::DES_EDE3
Crypt::Digest::BLAKE2s_256
Crypt::Digest::RIPEMD160
Crypt::Digest::RIPEMD320
Crypt::Digest::Whirlpool
Crypt::ECB
Crypt::Eksblowfish::Bcrypt
Crypt::Mode::CBC
Crypt::Mode::CFB
Crypt::Mode::ECB
Crypt::MySQL
Crypt::OpenSSH::ChachaPoly
Crypt::OpenSSL::Bignum::CTX
Crypt::Passwd::XS
Crypt::PBKDF2
Crypt::RC4
Crypt::Rijndael
Crypt::ScryptKDF
Crypt::Skip32
Crypt::Twofish
Crypt::UnixCrypt_XS
CryptX
Data::Types
Digest::CMAC
Digest::CRC
Digest::HMAC
Digest::HMAC_MD5
Digest::Keccak
Digest::MD4
Digest::MD5
Digest::MurmurHash3
Digest::Perl::MD5
Digest::SHA
Digest::SHA1
Digest::SHA3
Digest::SipHash
Encode
JSON
LWP::Simple
Math::BigInt
MIME::Base64
Module::Build
Module::Build::Pluggable::XSUtil
Net::DNS::RR::NSEC3
Net::DNS::SEC
POSIX
"

for perl_module in ${PERL_MODULES}; do
  install_module "${perl_module}"
done

install_module "https://github.com/matrix/p5-Digest-BLAKE2.git"

install_module "https://github.com/matrix/digest-gost.git"

install_module "https://github.com/matrix/perl-Crypt-OpenSSL-EC.git"

install_module "https://github.com/matrix/Digest--MD6.git"

# checks for pyenv

pyenv_enabled=0

which pyenv &>/dev/null
if [ $? -eq 0 ]; then

  if [[ $(pyenv version-name) != "system" ]]; then

    # active session detected
    pyenv_enabled=1

  else

    # enum last version available
    latest=$(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1)

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

    # enable
    pyenv local $latest
    if [ $? -eq 0 ]; then
      pyenv_enabled=1
    fi

  fi
fi

if [ ${pyenv_enabled} -eq 0 ]; then

  echo "! something is wrong with pyenv. Please setup latest version manually and re-run this script."
  (( ERRORS++ ))

else

  echo "> Installing python3 deps ..."

  pip3 install git+https://github.com/matrix/pygost
  ERRORS=$((ERRORS+$?))

  pip3 install pycryptoplus
  ERRORS=$((ERRORS+$?))

  pip3 install pycryptodome
  ERRORS=$((ERRORS+$?))

  pip3 install cryptography
  ERRORS=$((ERRORS+$?))

  pip3 install setuptools
  ERRORS=$((ERRORS+$?))

  pip3 install argon2-cffi
  ERRORS=$((ERRORS+$?))

fi

# test.sh -g builds real crypto-containers, and those need ordinary command line tools rather
# than perl or python modules, so they are not in the lists above. Install what the package
# manager can give us. This is best effort on purpose: a run without them still works, it just
# records a skip naming the tool for every format it could not build.
#
# Three of them no package manager here can provide, and tools/README.md says where to get them:
# John jumbo for the 2john tools, a RARLAB rar 6.x or older for the RAR3 modes, and a veracrypt
# console build.

GEN_PACKAGES="zip gnupg gnupg1 cryptsetup"

install_gen_tools ()
{
  if [ ${IS_APPLE} -eq 1 ]; then
    echo "> Skipping the test.sh -g tools, this script only knows how to install them with apt."
    echo "  See tools/README.md for what each format needs."
    return
  fi

  if ! command -v apt-get > /dev/null 2>&1; then
    echo "> No apt-get, so the test.sh -g tools are not installed. On this system, install the"
    echo "  equivalents of: ${GEN_PACKAGES}"
    echo "  See tools/README.md for what each one is for."
    return
  fi

  local sudo_cmd=""

  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo > /dev/null 2>&1; then
      sudo_cmd="sudo"
    else
      echo "> Not root and no sudo, so the test.sh -g tools are not installed. Run:"
      echo "    apt-get install -y ${GEN_PACKAGES}"
      return
    fi
  fi

  echo "> Installing the test.sh -g tools (${GEN_PACKAGES}) ..."

  if ${sudo_cmd} apt-get install -y ${GEN_PACKAGES} > /dev/null 2>&1; then
    echo "  ok"
  else
    # Not an error for this script: -g is optional and every missing tool is reported again, by
    # name, in the run that wanted it.
    echo "  FAILED, so -g will skip the formats whose tools are missing. Run by hand:"
    echo "    ${sudo_cmd} apt-get install ${GEN_PACKAGES}"
  fi
}

install_gen_tools

echo

if [ -n "${FAILED_MODULES}" ]; then

  echo "> These did not install:"

  for perl_module in ${FAILED_MODULES}; do
    echo "    ${perl_module}"
  done

  echo

fi

# The check that actually matters. tools/test.pl loads every module under tools/test_modules no
# matter which hash mode is asked for, so a single missing one makes the suite report
# "Error : 0/0 not found" on every mode, which reads as hashcat failing rather than as a setup
# problem. Catching it here, where the cause is still in front of you, is the whole point.

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if perl "${TOOLS_DIR}/test.pl" single 0 2> /dev/null | grep -q hashcat; then

  echo "[  OK  ] tools/test.pl can generate hashes, the suite is usable"

  if [ -n "${FAILED_MODULES}" ]; then
    echo "         The modules above only affect the hash modes that need them."
  fi

  exit 0

fi

echo "[ FAIL ] tools/test.pl cannot generate hashes. The suite would report 'Error : 0/0' on"
echo "         every mode, which is a setup failure and not a hashcat one. Fix the modules above"
echo "         and run this script again."

exit 1

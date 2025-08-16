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

if ! command -v cpanm >/dev/null 2>&1; then
    echo "We need cpanm, it is not installed, use:"
    echo "sudo apt install cpanminus"
    exit 1
fi


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
  echo "! something is wrong with pyenv. Please install latest pyenv version and re-run this script:"
  echo "curl https://pyenv.run | bash"
  echo 'pyenv install $(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1)'
  echo 'pyenv local $(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1)'
  echo 'pip install --upgrade pip'
  exit 1
fi

# Sum of all exit codes
ERRORS=0

echo "> Installing perl deps ... (we need root for that)"

if [ ${IS_APPLE} -eq 1 ]; then
  # workaround for test failed with Net::SSLeay on Apple
  sudo cpanm --notest Net::SSLeay
else
  sudo cpanm Net::SSLeay
fi

ERRORS=$((ERRORS+$?))

sudo cpanm Authen::Passphrase::LANManager   \
      Authen::Passphrase::MySQL323     \
      Authen::Passphrase::NTHash       \
      Authen::Passphrase::PHPass       \
      Bitcoin::Crypto                  \
      Bitcoin::Crypto::Base58          \
      Compress::Zlib                   \
      Convert::EBCDIC                  \
      Crypt::Argon2                    \
      Crypt::AuthEnc::GCM              \
      Crypt::Blowfish                  \
      Crypt::Camellia                  \
      Crypt::CBC                       \
      Crypt::Cipher::Serpent           \
      Crypt::DES                       \
      Crypt::DES_EDE3                  \
      Crypt::Digest::BLAKE2s_256       \
      Crypt::Digest::RIPEMD160         \
      Crypt::Digest::RIPEMD320         \
      Crypt::Digest::Whirlpool         \
      Crypt::ECB                       \
      Crypt::Eksblowfish::Bcrypt       \
      Crypt::Mode::CBC                 \
      Crypt::Mode::CFB                 \
      Crypt::Mode::ECB                 \
      Crypt::MySQL                     \
      Crypt::OpenSSH::ChachaPoly       \
      Crypt::OpenSSL::Bignum::CTX      \
      Crypt::Passwd::XS                \
      Crypt::PBKDF2                    \
      Crypt::RC4                       \
      Crypt::Rijndael                  \
      Crypt::ScryptKDF                 \
      Crypt::Skip32                    \
      Crypt::Twofish                   \
      Crypt::UnixCrypt_XS              \
      CryptX                           \
      Data::Types                      \
      Digest::CMAC                     \
      Digest::CRC                      \
      Digest::HMAC                     \
      Digest::HMAC_MD5                 \
      Digest::Keccak                   \
      Digest::MD4                      \
      Digest::MD5                      \
      Digest::MD6                      \
      Digest::MurmurHash3              \
      Digest::Perl::MD5                \
      Digest::SHA                      \
      Digest::SHA1                     \
      Digest::SHA3                     \
      Digest::SipHash                  \
      Encode                           \
      JSON                             \
      Math::BigInt                     \
      MIME::Base64                     \
      Module::Build                    \
      Module::Build::Pluggable::XSUtil \
      Net::DNS::RR::NSEC3              \
      Net::DNS::SEC                    \
      POSIX                            \
      ;

ERRORS=$((ERRORS+$?))

sudo cpanm https://github.com/matrix/p5-Digest-BLAKE2.git
ERRORS=$((ERRORS+$?))

sudo cpanm https://github.com/matrix/digest-gost.git
ERRORS=$((ERRORS+$?))

sudo cpanm https://github.com/matrix/perl-Crypt-OpenSSL-EC.git
ERRORS=$((ERRORS+$?))


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

echo

if [ $ERRORS -gt 0 ]; then
  echo "[ FAIL ] Some commands were not successful"
  exit 1
fi

echo "[  OK  ] All commands were successful"
exit 0

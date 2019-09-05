#!/bin/sh

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Test suite installation helper script

# Sum of all exit codes
ERRORS=0

cpan install Authen::Passphrase::LANManager \
             Authen::Passphrase::MySQL323   \
             Authen::Passphrase::NTHash     \
             Authen::Passphrase::PHPass     \
             Convert::EBCDIC                \
             Crypt::CBC                     \
             Crypt::DES                     \
             Crypt::Digest::RIPEMD160       \
             Crypt::Digest::Whirlpool       \
             Crypt::ECB                     \
             Crypt::Eksblowfish::Bcrypt     \
             Crypt::GCrypt                  \
             Crypt::Mode::ECB               \
             Crypt::MySQL                   \
             Crypt::OpenSSH::ChachaPoly     \
             Crypt::PBKDF2                  \
             Crypt::RC4                     \
             Crypt::Rijndael                \
             Crypt::ScryptKDF               \
             Crypt::Skip32                  \
             Crypt::Twofish                 \
             Crypt::UnixCrypt_XS            \
             Data::Types                    \
             Digest::BLAKE2                 \
             Digest::CMAC                   \
             Digest::CRC                    \
             Digest::GOST                   \
             Digest::HMAC                   \
             Digest::HMAC_MD5               \
             Digest::Keccak                 \
             Digest::MD4                    \
             Digest::MD5                    \
             Digest::Perl::MD5              \
             Digest::SHA                    \
             Digest::SHA1                   \
             Digest::SHA3                   \
             Digest::SipHash                \
             JSON                           \
             MIME::Base32                   \
             MIME::Base64                   \
             Net::DNS::RR::NSEC3            \
             Net::DNS::SEC                  \
             Text::Iconv                    \
             ;

ERRORS=$((ERRORS+$?))

pip2 install pygost pycryptoplus

pip2 -y uninstall pycryptodome

ERRORS=$((ERRORS+$?))

echo
if [ $ERRORS -eq 0 ]; then
  echo '[  OK  ] All commands were successful'
  exit 0
else
  echo '[ FAIL ] Some commands were not successful'
  exit 1
fi

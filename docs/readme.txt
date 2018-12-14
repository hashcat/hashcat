hashcat v5.1.0
==============

AMD GPUs on Linux require "RadeonOpenCompute (ROCm)" Software Platform (1.6.180 or later)
AMD GPUs on Windows require "AMD Radeon Software Crimson Edition" (15.12 or later)
Intel CPUs require "OpenCL Runtime for Intel Core and Intel Xeon Processors" (16.1.1 or later)
Intel GPUs on Linux require "OpenCL 2.0 GPU Driver Package for Linux" (2.0 or later)
Intel GPUs on Windows require "OpenCL Driver for Intel Iris and Intel HD Graphics"
NVIDIA GPUs require "NVIDIA Driver" (367.x or later)

##
## Features
##

- World's fastest password cracker
- World's first and only in-kernel rule engine
- Free
- Open-Source (MIT License)
- Multi-OS (Linux, Windows and macOS)
- Multi-Platform (CPU, GPU, DSP, FPGA, etc., everything that comes with an OpenCL runtime)
- Multi-Hash (Cracking multiple hashes at the same time)
- Multi-Devices (Utilizing multiple devices in same system)
- Multi-Device-Types (Utilizing mixed device types in same system)
- Supports password candidate brain functionality
- Supports distributed cracking networks (using overlay)
- Supports interactive pause / resume
- Supports sessions
- Supports restore
- Supports reading password candidates from file and stdin
- Supports hex-salt and hex-charset
- Supports automatic performance tuning
- Supports automatic keyspace ordering markov-chains
- Built-in benchmarking system
- Integrated thermal watchdog
- 200+ Hash-types implemented with performance in mind

##
## Hash-Types
##

- MD4
- MD5
- Half MD5
- SHA1
- SHA2-224
- SHA2-256
- SHA2-384
- SHA2-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- Keccak-224
- Keccak-256
- Keccak-384
- Keccak-512
- BLAKE2b-512
- SipHash
- RIPEMD-160
- Whirlpool
- GOST R 34.11-94
- GOST R 34.11-2012 (Streebog) 256-bit
- GOST R 34.11-2012 (Streebog) 512-bit
- md5($pass.$salt)
- md5($salt.$pass)
- md5(utf16le($pass).$salt)
- md5($salt.utf16le($pass))
- md5($salt.$pass.$salt)
- md5($salt.md5($pass))
- md5($salt.md5($salt.$pass))
- md5($salt.md5($pass.$salt))
- md5(md5($pass))
- md5(md5($pass).md5($salt))
- md5(strtoupper(md5($pass)))
- md5(sha1($pass))
- sha1($pass.$salt)
- sha1($salt.$pass)
- sha1(utf16le($pass).$salt)
- sha1($salt.utf16le($pass))
- sha1(sha1($pass))
- sha1($salt.sha1($pass))
- sha1(md5($pass))
- sha1(md5(md5($pass)))
- sha1($salt.$pass.$salt)
- sha1(CX)
- sha256($pass.$salt)
- sha256($salt.$pass)
- sha256(utf16le($pass).$salt)
- sha256($salt.utf16le($pass))
- sha512($pass.$salt)
- sha512($salt.$pass)
- sha512(utf16le($pass).$salt)
- sha512($salt.utf16le($pass))
- HMAC-MD5 (key = $pass)
- HMAC-MD5 (key = $salt)
- HMAC-SHA1 (key = $pass)
- HMAC-SHA1 (key = $salt)
- HMAC-SHA256 (key = $pass)
- HMAC-SHA256 (key = $salt)
- HMAC-SHA512 (key = $pass)
- HMAC-SHA512 (key = $salt)
- DES (PT = $salt, key = $pass)
- 3DES (PT = $salt, key = $pass)
- Skip32 (PT = $salt, key = $pass)
- ChaCha20
- phpass
- scrypt
- PBKDF2-HMAC-MD5
- PBKDF2-HMAC-SHA1
- PBKDF2-HMAC-SHA256
- PBKDF2-HMAC-SHA512
- Skype
- WPA-EAPOL-PBKDF2
- WPA-EAPOL-PMK
- WPA-PMKID-PBKDF2
- WPA-PMKID-PMK
- iSCSI CHAP authentication, MD5(CHAP)
- IKE-PSK MD5
- IKE-PSK SHA1
- NetNTLMv1
- NetNTLMv1+ESS
- NetNTLMv2
- IPMI2 RAKP HMAC-SHA1
- Kerberos 5 AS-REQ Pre-Auth etype 23
- DNSSEC (NSEC3)
- CRAM-MD5
- PostgreSQL CRAM (MD5)
- MySQL CRAM (SHA1)
- SIP digest authentication (MD5)
- Kerberos 5 TGS-REP etype 23
- TACACS+
- JWT (JSON Web Token)
- SMF (Simple Machines Forum) > v1.1
- phpBB3 (MD5)
- vBulletin < v3.8.5
- vBulletin >= v3.8.5
- MyBB 1.2+
- IPB2+ (Invision Power Board)
- WBB3 (Woltlab Burning Board)
- Joomla < 2.5.18
- Joomla >= 2.5.18 (MD5)
- WordPress (MD5)
- PHPS
- Drupal7
- osCommerce
- xt:Commerce
- PrestaShop
- Django (SHA-1)
- Django (PBKDF2-SHA256)
- Tripcode
- MediaWiki B type
- OpenCart
- Redmine
- PunBB
- Atlassian (PBKDF2-HMAC-SHA1)
- PostgreSQL
- MSSQL (2000)
- MSSQL (2005)
- MSSQL (2012, 2014)
- MySQL323
- MySQL4.1/MySQL5
- Oracle H: Type (Oracle 7+)
- Oracle S: Type (Oracle 11+)
- Oracle T: Type (Oracle 12+)
- Sybase ASE
- Episerver 6.x < .NET 4
- Episerver 6.x >= .NET 4
- Apache $apr1$ MD5, md5apr1, MD5 (APR)
- ColdFusion 10+
- hMailServer
- nsldap, SHA-1(Base64), Netscape LDAP SHA
- nsldaps, SSHA-1(Base64), Netscape LDAP SSHA
- SSHA-256(Base64), LDAP {SSHA256}
- SSHA-512(Base64), LDAP {SSHA512}
- CRAM-MD5 Dovecot
- FileZilla Server >= 0.9.55
- CRC32
- LM
- NTLM
- Domain Cached Credentials (DCC), MS Cache
- Domain Cached Credentials 2 (DCC2), MS Cache 2
- DPAPI masterkey file v1
- DPAPI masterkey file v2
- MS-AzureSync  PBKDF2-HMAC-SHA256
- descrypt, DES (Unix), Traditional DES
- BSDi Crypt, Extended DES
- md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
- bcrypt $2*$, Blowfish (Unix)
- sha256crypt $5$, SHA256 (Unix)
- sha512crypt $6$, SHA512 (Unix)
- macOS v10.4, MacOS v10.5, MacOS v10.6
- macOS v10.7
- macOS v10.8+ (PBKDF2-SHA512)
- AIX {smd5}
- AIX {ssha1}
- AIX {ssha256}
- AIX {ssha512}
- Cisco-PIX MD5
- Cisco-ASA MD5
- Cisco-IOS $1$ (MD5)
- Cisco-IOS type 4 (SHA256)
- Cisco-IOS $8$ (PBKDF2-SHA256)
- Cisco-IOS $9$ (scrypt)
- Juniper NetScreen/SSG (ScreenOS)
- Juniper IVE
- Juniper/NetBSD sha1crypt
- FortiGate (FortiOS)
- Samsung Android Password/PIN
- Windows Phone 8+ PIN/password
- Citrix NetScaler
- RACF
- GRUB 2
- Radmin2
- ArubaOS
- SAP CODVN B (BCODE)
- SAP CODVN F/G (PASSCODE)
- SAP CODVN H (PWDSALTEDHASH) iSSHA-1
- Lotus Notes/Domino 5
- Lotus Notes/Domino 6
- Lotus Notes/Domino 8
- PeopleSoft
- PeopleSoft PS_TOKEN
- 7-Zip
- RAR3-hp
- RAR5
- AxCrypt
- AxCrypt in-memory SHA1
- WinZip
- iTunes backup < 10.0
- iTunes backup >= 10.0
- TrueCrypt
- Android FDE <= 4.3
- Android FDE (Samsung DEK)
- eCryptfs
- VeraCrypt
- LUKS
- FileVault 2
- Apple File System (APFS)
- MS Office <= 2003
- MS Office 2007
- MS Office 2010
- MS Office 2013
- PDF 1.1 - 1.3 (Acrobat 2 - 4)
- PDF 1.4 - 1.6 (Acrobat 5 - 8)
- PDF 1.7 Level 3 (Acrobat 9)
- PDF 1.7 Level 8 (Acrobat 10 - 11)
- Apple Secure Notes
- Open Document Format (ODF) 1.1 (SHA-1, Blowfish)
- Open Document Format (ODF) 1.2 (SHA-256, AES)
- Password Safe v2
- Password Safe v3
- LastPass + LastPass sniffed
- 1Password, agilekeychain
- 1Password, cloudkeychain
- Bitcoin/Litecoin wallet.dat
- Blockchain, My Wallet
- Blockchain, My Wallet, V2
- Electrum Wallet (Salt-Type 1-2)
- KeePass 1 (AES/Twofish) and KeePass 2 (AES)
- JKS Java Key Store Private Keys (SHA1)
- Ethereum Wallet, PBKDF2-HMAC-SHA256
- Ethereum Wallet, SCRYPT
- Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256
- Ansible Vault
- Kerberos 5 AS-REP etype 23
- Plaintext

##
## Attack-Modes
##

- Straight *
- Combination
- Brute-force
- Hybrid dict + mask
- Hybrid mask + dict

* = Supports rules

##
## Supported OpenCL runtimes
##

- AMD
- Apple
- Intel
- Mesa (Gallium)
- NVidia
- pocl

##
## Supported OpenCL device types
##

- GPU
- CPU
- APU
- DSP
- FPGA
- Coprocessor

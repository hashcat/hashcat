
      _____:  _____________         _____:  -aTZ!      _______ ____
     _\    |__\_______   _/_______ _\    |_____ _______\______    /__ ______
     |     _     |  __   \   ____/____   _     |   ___/____  __    |_______/
     |:    |    .|  \    _\____      /   |    .|   \      /  \    :|     |
     |_____|    :|______/     /    //____|    :|___     //_________|    :|
           |_____|     /___________/     |_____|  /_____/        /_______|
                 :                             :                         :

hashcat v5.1.0
==============

AMD GPUs on Linux require "RadeonOpenCompute (ROCm)" Software Platform (1.6.180 or later)
AMD GPUs on Windows require "AMD Radeon Software Crimson Edition" (15.12 or later)
Intel CPUs require "OpenCL Runtime for Intel Core and Intel Xeon Processors" (16.1.1 or later)
Intel GPUs on Linux require "OpenCL 2.0 GPU Driver Package for Linux" (2.0 or later)
Intel GPUs on Windows require "OpenCL Driver for Intel Iris and Intel HD Graphics"
NVIDIA GPUs require "NVIDIA Driver" (418.56 or later) and "CUDA Toolkit" (10.1 or later)

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
- SHA1
- SHA2-224
- SHA2-256
- SHA2-384
- SHA2-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- RIPEMD-160
- BLAKE2b-512
- GOST R 34.11-2012 (Streebog) 256-bit, big-endian
- GOST R 34.11-2012 (Streebog) 512-bit, big-endian
- GOST R 34.11-94
- Half MD5
- Java Object hashCode()
- Keccak-224
- Keccak-256
- Keccak-384
- Keccak-512
- sha256(sha256_bin(pass))
- Whirlpool
- SipHash
- BitShares v0.x - sha512(sha512_bin(pass))
- md5($pass.$salt)
- md5($salt.$pass)
- md5($salt.$pass.$salt)
- md5($salt.md5($pass))
- md5($salt.md5($pass.$salt))
- md5($salt.md5($salt.$pass))
- md5($salt.sha1($salt.$pass))
- md5($salt.utf16le($pass))
- md5(md5($pass))
- md5(md5($pass).md5($salt))
- md5(sha1($pass))
- md5(sha1($pass).md5($pass).sha1($pass))
- md5(sha1($salt).md5($pass))
- md5(strtoupper(md5($pass)))
- md5(utf16le($pass).$salt)
- sha1($pass.$salt)
- sha1($salt.$pass)
- sha1($salt.$pass.$salt)
- sha1($salt.sha1($pass))
- sha1($salt.utf16le($pass))
- sha1($salt1.$pass.$salt2)
- sha1(CX)
- sha1(md5($pass))
- sha1(md5($pass).$salt)
- sha1(md5($pass.$salt))
- sha1(md5(md5($pass)))
- sha1(sha1($pass))
- sha1(utf16le($pass).$salt)
- sha256($pass.$salt)
- sha256($salt.$pass)
- sha256($salt.utf16le($pass))
- sha256(md5($pass))
- sha256(sha256($pass).$salt)
- sha256(utf16le($pass).$salt)
- sha512($pass.$salt)
- sha512($salt.$pass)
- sha512($salt.utf16le($pass))
- sha512(utf16le($pass).$salt)
- Ruby on Rails Restful-Authentication
- HMAC-MD5 (key = $pass)
- HMAC-MD5 (key = $salt)
- HMAC-SHA1 (key = $pass)
- HMAC-SHA1 (key = $salt)
- HMAC-SHA256 (key = $pass)
- HMAC-SHA256 (key = $salt)
- HMAC-SHA512 (key = $pass)
- HMAC-SHA512 (key = $salt)
- HMAC-Streebog-256 (key = $pass), big-endian
- HMAC-Streebog-256 (key = $salt), big-endian
- HMAC-Streebog-512 (key = $pass), big-endian
- HMAC-Streebog-512 (key = $salt), big-endian
- CRC32
- 3DES (PT = $salt, key = $pass)
- DES (PT = $salt, key = $pass)
- ChaCha20
- Skip32 (PT = $salt, key = $pass)
- PBKDF2-HMAC-MD5
- PBKDF2-HMAC-SHA1
- PBKDF2-HMAC-SHA256
- PBKDF2-HMAC-SHA512
- scrypt
- phpass
- Ansible Vault
- Atlassian (PBKDF2-HMAC-SHA1)
- Python passlib pbkdf2-sha512
- Python passlib pbkdf2-sha256
- Python passlib pbkdf2-sha1
- TACACS+
- SIP digest authentication (MD5)
- IKE-PSK MD5
- IKE-PSK SHA1
- WPA-EAPOL-PBKDF2
- WPA-EAPOL-PMK
- WPA-PMKID-PBKDF2
- WPA-PMKID-PMK
- IPMI2 RAKP HMAC-SHA1
- CRAM-MD5
- iSCSI CHAP authentication, MD5(CHAP)
- JWT (JSON Web Token)
- Kerberos 5, etype 23, AS-REQ Pre-Auth
- Kerberos 5, etype 23, TGS-REP
- Kerberos 5, etype 23, AS-REP
- Kerberos 5, etype 17, TGS-REP
- Kerberos 5, etype 18, TGS-REP
- Kerberos 5, etype 17, Pre-Auth
- Kerberos 5, etype 18, Pre-Auth
- NetNTLMv1 / NetNTLMv1+ESS
- NetNTLMv2
- Skype
- PostgreSQL CRAM (MD5)
- MySQL CRAM (SHA1)
- RACF
- AIX {smd5}
- AIX {ssha1}
- AIX {ssha256}
- AIX {ssha512}
- LM
- QNX /etc/shadow (MD5)
- QNX /etc/shadow (SHA256)
- QNX /etc/shadow (SHA512)
- DPAPI masterkey file v1
- DPAPI masterkey file v2
- GRUB 2
- MS-AzureSync PBKDF2-HMAC-SHA256
- BSDi Crypt, Extended DES
- NTLM
- macOS v10.4, macOS v10.5, MacOS v10.6
- macOS v10.7
- macOS v10.8+ (PBKDF2-SHA512)
- Radmin2
- Samsung Android Password/PIN
- bcrypt $2*$, Blowfish (Unix)
- md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
- descrypt, DES (Unix), Traditional DES
- sha256crypt $5$, SHA256 (Unix)
- sha512crypt $6$, SHA512 (Unix)
- Windows Phone 8+ PIN/password
- Cisco-ASA MD5
- Cisco-IOS $8$ (PBKDF2-SHA256)
- Cisco-IOS $9$ (scrypt)
- Cisco-IOS type 4 (SHA256)
- Cisco-PIX MD5
- Citrix NetScaler
- Domain Cached Credentials (DCC), MS Cache
- Domain Cached Credentials 2 (DCC2), MS Cache 2
- FortiGate (FortiOS)
- ArubaOS
- Juniper IVE
- Juniper NetScreen/SSG (ScreenOS)
- Juniper/NetBSD sha1crypt
- MSSQL (2000)
- MSSQL (2005)
- MSSQL (2012, 2014)
- PostgreSQL
- Oracle H: Type (Oracle 7+)
- Oracle S: Type (Oracle 11+)
- Oracle T: Type (Oracle 12+)
- MySQL323
- MySQL4.1/MySQL5
- Sybase ASE
- hMailServer
- DNSSEC (NSEC3)
- CRAM-MD5 Dovecot
- SSHA-256(Base64), LDAP {SSHA256}
- SSHA-512(Base64), LDAP {SSHA512}
- FileZilla Server >= 0.9.55
- ColdFusion 10+
- Apache $apr1$ MD5, md5apr1, MD5 (APR)
- Episerver 6.x < .NET 4
- Episerver 6.x >= .NET 4
- nsldap, SHA-1(Base64), Netscape LDAP SHA
- nsldaps, SSHA-1(Base64), Netscape LDAP SSHA
- SAP CODVN B (BCODE)
- SAP CODVN B (BCODE) from RFC_READ_TABLE
- SAP CODVN F/G (PASSCODE)
- SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE
- SAP CODVN H (PWDSALTEDHASH) iSSHA-1
- PeopleSoft
- PeopleSoft PS_TOKEN
- SolarWinds Orion
- Lotus Notes/Domino 5
- Lotus Notes/Domino 6
- Lotus Notes/Domino 8
- Oracle Transportation Management (SHA256)
- Huawei sha1(md5($pass).$salt)
- AuthMe sha256
- eCryptfs
- LUKS
- VeraCrypt
- FileVault 2
- DiskCryptor
- Android FDE (Samsung DEK)
- Android FDE <= 4.3
- Apple File System (APFS)
- TrueCrypt
- PDF 1.1 - 1.3 (Acrobat 2 - 4)
- PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1
- PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2
- PDF 1.4 - 1.6 (Acrobat 5 - 8)
- PDF 1.7 Level 3 (Acrobat 9)
- PDF 1.7 Level 8 (Acrobat 10 - 11)
- MS Office 2007
- MS Office 2010
- MS Office 2013
- MS Office <= 2003 $0/$1, MD5 + RC4
- MS Office <= 2003 $0/$1, MD5 + RC4, collider #1
- MS Office <= 2003 $0/$1, MD5 + RC4, collider #2
- MS Office <= 2003 $3/$4, SHA1 + RC4
- MS Office <= 2003 $3, SHA1 + RC4, collider #1
- MS Office <= 2003 $3, SHA1 + RC4, collider #2
- Open Document Format (ODF) 1.2 (SHA-256, AES)
- Open Document Format (ODF) 1.1 (SHA-1, Blowfish)
- Apple Secure Notes
- JKS Java Key Store Private Keys (SHA1)
- 1Password, agilekeychain
- 1Password, cloudkeychain
- Password Safe v2
- Password Safe v3
- LastPass + LastPass sniffed
- KeePass 1 (AES/Twofish) and KeePass 2 (AES)
- Bitcoin/Litecoin wallet.dat
- Electrum Wallet (Salt-Type 1-3)
- Blockchain, My Wallet
- Blockchain, My Wallet, V2
- Blockchain, My Wallet, Second Password (SHA256)
- Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256
- Ethereum Wallet, PBKDF2-HMAC-SHA256
- Ethereum Wallet, SCRYPT
- 7-Zip
- RAR3-hp
- RAR5
- PKZIP (Compressed)
- PKZIP (Compressed Multi-File)
- PKZIP (Mixed Multi-File)
- PKZIP (Mixed Multi-File Checksum-Only)
- PKZIP (Uncompressed)
- PKZIP Master Key
- PKZIP Master Key (6 byte optimization)
- iTunes backup < 10.0
- iTunes backup >= 10.0
- WinZip
- Android Backup
- AxCrypt
- AxCrypt in-memory SHA1
- WBB3 (Woltlab Burning Board)
- vBulletin < v3.8.5
- vBulletin >= v3.8.5
- PHPS
- SMF (Simple Machines Forum) > v1.1
- MediaWiki B type
- Redmine
- Django (PBKDF2-SHA256)
- Django (SHA-1)
- Joomla < 2.5.18
- OpenCart
- PrestaShop
- Tripcode
- Drupal7
- osCommerce, xt:Commerce
- PunBB
- MyBB 1.2+, IPB2+ (Invision Power Board)
- TOTP (HMAC-SHA1)

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

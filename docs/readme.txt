hashcat v3.20
=============

AMD users on Windows require "AMD Radeon Software Crimson Edition" (15.12 or later)
AMD users on Linux require "AMDGPU-Pro Driver" (16.40 or later)
Intel CPU users require "OpenCL Runtime for Intel Core and Intel Xeon Processors" (16.1.1 or later)
Intel GPU on Windows users require "OpenCL Driver for Intel Iris and Intel HD Graphics"
Intel GPU on Linux users require "OpenCL 2.0 GPU Driver Package for Linux" (2.0 or later)
NVidia users require "NVIDIA Driver" (367.x or later)

##
## Features
##

- World's fastest password cracker
- World's first and only in-kernel rule engine
- Free
- Open-Source (MIT License)
- Multi-OS (Linux, Windows and OSX)
- Multi-Platform (CPU, GPU, DSP, FPGA, etc., everything that comes with an OpenCL runtime)
- Multi-Hash (Cracking multiple hashes at the same time)
- Multi-Devices (Utilizing multiple devices in same system)
- Multi-Device-Types (Utilizing mixed device types in same system)
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
- 160+ Hash-types implemented with performance in mind

##
## Hash-Types
##

- MD4
- MD5
- Half MD5 (left, mid, right)
- SHA1
- SHA-256
- SHA-384
- SHA-512
- SHA-3 (Keccak)
- SipHash
- RipeMD160
- Whirlpool
- DES (PT = $salt, key = $pass)
- 3DES (PT = $salt, key = $pass)
- GOST R 34.11-94
- GOST R 34.11-2012 (Streebog) 256-bit
- GOST R 34.11-2012 (Streebog) 512-bit
- Double MD5
- Double SHA1
- md5($pass.$salt)
- md5($salt.$pass)
- md5(unicode($pass).$salt)
- md5($salt.unicode($pass))
- md5(sha1($pass))
- md5($salt.md5($pass))
- md5($salt.$pass.$salt)
- md5(strtoupper(md5($pass)))
- sha1($pass.$salt)
- sha1($salt.$pass)
- sha1(unicode($pass).$salt)
- sha1($salt.unicode($pass))
- sha1(md5($pass))
- sha1($salt.$pass.$salt)
- sha1(CX)
- sha256($pass.$salt)
- sha256($salt.$pass)
- sha256(unicode($pass).$salt)
- sha256($salt.unicode($pass))
- sha512($pass.$salt)
- sha512($salt.$pass)
- sha512(unicode($pass).$salt)
- sha512($salt.unicode($pass))
- HMAC-MD5 (key = $pass)
- HMAC-MD5 (key = $salt)
- HMAC-SHA1 (key = $pass)
- HMAC-SHA1 (key = $salt)
- HMAC-SHA256 (key = $pass)
- HMAC-SHA256 (key = $salt)
- HMAC-SHA512 (key = $pass)
- HMAC-SHA512 (key = $salt)
- PBKDF2-HMAC-MD5
- PBKDF2-HMAC-SHA1
- PBKDF2-HMAC-SHA256
- PBKDF2-HMAC-SHA512
- MyBB
- phpBB3
- SMF
- vBulletin
- IPB
- Woltlab Burning Board
- osCommerce
- xt:Commerce
- PrestaShop
- Mediawiki B type
- Wordpress
- Drupal
- Joomla
- PHPS
- Django (SHA-1)
- Django (PBKDF2-SHA256)
- EPiServer
- ColdFusion 10+
- Apache MD5-APR
- MySQL
- PostgreSQL
- MSSQL
- Oracle H: Type (Oracle 7+)
- Oracle S: Type (Oracle 11+)
- Oracle T: Type (Oracle 12+)
- Sybase
- hMailServer
- DNSSEC (NSEC3)
- IKE-PSK
- IPMI2 RAKP
- iSCSI CHAP
- Cram MD5
- MySQL Challenge-Response Authentication (SHA1)
- PostgreSQL Challenge-Response Authentication (MD5)
- SIP Digest Authentication (MD5)
- WPA
- WPA2
- NetNTLMv1
- NetNTLMv1 + ESS
- NetNTLMv2
- Kerberos 5 AS-REQ Pre-Auth etype 23
- Kerberos 5 TGS-REP etype 23
- Netscape LDAP SHA/SSHA
- LM
- NTLM
- Domain Cached Credentials (DCC), MS Cache
- Domain Cached Credentials 2 (DCC2), MS Cache 2
- MS-AzureSync PBKDF2-HMAC-SHA256
- descrypt
- bsdicrypt
- md5crypt
- sha256crypt
- sha512crypt
- bcrypt
- scrypt
- OSX v10.4
- OSX v10.5
- OSX v10.6
- OSX v10.7
- OSX v10.8
- OSX v10.9
- OSX v10.10
- AIX {smd5}
- AIX {ssha1}
- AIX {ssha256}
- AIX {ssha512}
- Cisco-ASA
- Cisco-PIX
- Cisco-IOS
- Cisco $8$
- Cisco $9$
- Juniper IVE
- Juniper Netscreen/SSG (ScreenOS)
- Android PIN
- Windows 8+ phone PIN/Password
- GRUB 2
- CRC32
- RACF
- Radmin2
- Redmine
- OpenCart
- Citrix Netscaler
- SAP CODVN B (BCODE)
- SAP CODVN F/G (PASSCODE)
- SAP CODVN H (PWDSALTEDHASH) iSSHA-1
- PeopleSoft
- PeopleSoft PS_TOKEN
- Skype
- WinZip
- 7-Zip
- RAR3-hp
- RAR5
- AxCrypt
- AxCrypt in memory SHA1
- PDF 1.1 - 1.3 (Acrobat 2 - 4)
- PDF 1.4 - 1.6 (Acrobat 5 - 8)
- PDF 1.7 Level 3 (Acrobat 9)
- PDF 1.7 Level 8 (Acrobat 10 - 11)
- MS Office <= 2003 MD5
- MS Office <= 2003 SHA1
- MS Office 2007
- MS Office 2010
- MS Office 2013
- Lotus Notes/Domino 5
- Lotus Notes/Domino 6
- Lotus Notes/Domino 8
- Bitcoin/Litecoin wallet.dat
- Blockchain, My Wallet
- 1Password, agilekeychain
- 1Password, cloudkeychain
- Lastpass
- Password Safe v2
- Password Safe v3
- Keepass 1 (AES/Twofish) and Keepass 2 (AES)
- Plaintext
- eCryptfs
- Android FDE <= 4.3
- Android FDE (Samsung DEK)
- TrueCrypt
- VeraCrypt

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

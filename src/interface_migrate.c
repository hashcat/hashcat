
  "  10100 | SipHash                                          | Raw Hash",
  "   6000 | RIPEMD-160                                       | Raw Hash",
  "   6100 | Whirlpool                                        | Raw Hash",
  "  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian | Raw Hash",
  "  11800 | GOST R 34.11-2012 (Streebog) 512-bit, big-endian | Raw Hash",
  "     30 | md5(utf16le($pass).$salt)                        | Raw Hash, Salted and/or Iterated",
  "     40 | md5($salt.utf16le($pass))                        | Raw Hash, Salted and/or Iterated",
  "   3800 | md5($salt.$pass.$salt)                           | Raw Hash, Salted and/or Iterated",
  "   3710 | md5($salt.md5($pass))                            | Raw Hash, Salted and/or Iterated",
  "   4010 | md5($salt.md5($salt.$pass))                      | Raw Hash, Salted and/or Iterated",
  "   4110 | md5($salt.md5($pass.$salt))                      | Raw Hash, Salted and/or Iterated",
  "   2600 | md5(md5($pass))                                  | Raw Hash, Salted and/or Iterated",
  "   4300 | md5(strtoupper(md5($pass)))                      | Raw Hash, Salted and/or Iterated",
  "   4400 | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated",
  "    120 | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated",
  "    130 | sha1(utf16le($pass).$salt)                       | Raw Hash, Salted and/or Iterated",
  "    140 | sha1($salt.utf16le($pass))                       | Raw Hash, Salted and/or Iterated",
  "   4500 | sha1(sha1($pass))                                | Raw Hash, Salted and/or Iterated",
  "   4520 | sha1($salt.sha1($pass))                          | Raw Hash, Salted and/or Iterated",
  "   4700 | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated",
  "   4900 | sha1($salt.$pass.$salt)                          | Raw Hash, Salted and/or Iterated",
  "  14400 | sha1(CX)                                         | Raw Hash, Salted and/or Iterated",
  "   1410 | sha256($pass.$salt)                              | Raw Hash, Salted and/or Iterated",
  "   1420 | sha256($salt.$pass)                              | Raw Hash, Salted and/or Iterated",
  "   1430 | sha256(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated",
  "   1440 | sha256($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated",
  "   1710 | sha512($pass.$salt)                              | Raw Hash, Salted and/or Iterated",
  "   1720 | sha512($salt.$pass)                              | Raw Hash, Salted and/or Iterated",
  "   1730 | sha512(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated",
  "   1740 | sha512($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated",
  "     50 | HMAC-MD5 (key = $pass)                           | Raw Hash, Authenticated",
  "     60 | HMAC-MD5 (key = $salt)                           | Raw Hash, Authenticated",
  "    150 | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated",
  "    160 | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated",
  "   1450 | HMAC-SHA256 (key = $pass)                        | Raw Hash, Authenticated",
  "   1460 | HMAC-SHA256 (key = $salt)                        | Raw Hash, Authenticated",
  "   1750 | HMAC-SHA512 (key = $pass)                        | Raw Hash, Authenticated",
  "   1760 | HMAC-SHA512 (key = $salt)                        | Raw Hash, Authenticated",
  "  11750 | HMAC-Streebog-256 (key = $pass), big-endian      | Raw Hash, Authenticated",
  "  11760 | HMAC-Streebog-256 (key = $salt), big-endian      | Raw Hash, Authenticated",
  "  11850 | HMAC-Streebog-512 (key = $pass), big-endian      | Raw Hash, Authenticated",
  "  11860 | HMAC-Streebog-512 (key = $salt), big-endian      | Raw Hash, Authenticated",
  "  11900 | PBKDF2-HMAC-MD5                                  | Generic KDF",
  "  10900 | PBKDF2-HMAC-SHA256                               | Generic KDF",
  "  12100 | PBKDF2-HMAC-SHA512                               | Generic KDF",
  "   8300 | DNSSEC (NSEC3)                                   | Network Protocols",
  "  10200 | CRAM-MD5                                         | Network Protocols",
  "  11100 | PostgreSQL CRAM (MD5)                            | Network Protocols",
  "  11200 | MySQL CRAM (SHA1)                                | Network Protocols",
  "  11400 | SIP digest authentication (MD5)                  | Network Protocols",
  "  16100 | TACACS+                                          | Network Protocols",
  "  16500 | JWT (JSON Web Token)                             | Network Protocols",
  "    121 | SMF (Simple Machines Forum) > v1.1               | Forums, CMS, E-Commerce, Frameworks",
  "   2611 | vBulletin < v3.8.5                               | Forums, CMS, E-Commerce, Frameworks",
  "   2711 | vBulletin >= v3.8.5                              | Forums, CMS, E-Commerce, Frameworks",
  "   8400 | WBB3 (Woltlab Burning Board)                     | Forums, CMS, E-Commerce, Frameworks",
  "   2612 | PHPS                                             | Forums, CMS, E-Commerce, Frameworks",
  "   7900 | Drupal7                                          | Forums, CMS, E-Commerce, Frameworks",
  "    124 | Django (SHA-1)                                   | Forums, CMS, E-Commerce, Frameworks",
  "  10000 | Django (PBKDF2-SHA256)                           | Forums, CMS, E-Commerce, Frameworks",
  "   3711 | MediaWiki B type                                 | Forums, CMS, E-Commerce, Frameworks",
  "  13900 | OpenCart                                         | Forums, CMS, E-Commerce, Frameworks",
  "   4521 | Redmine                                          | Forums, CMS, E-Commerce, Frameworks",
  "   4522 | PunBB                                            | Forums, CMS, E-Commerce, Frameworks",
  "  12001 | Atlassian (PBKDF2-HMAC-SHA1)                     | Forums, CMS, E-Commerce, Frameworks",
  "    131 | MSSQL (2000)                                     | Database Server",
  "    132 | MSSQL (2005)                                     | Database Server",
  "   1731 | MSSQL (2012, 2014)                               | Database Server",
  "    112 | Oracle S: Type (Oracle 11+)                      | Database Server",
  "  12300 | Oracle T: Type (Oracle 12+)                      | Database Server",
  "   8000 | Sybase ASE                                       | Database Server",
  "    141 | Episerver 6.x < .NET 4                           | HTTP, SMTP, LDAP Server",
  "   1441 | Episerver 6.x >= .NET 4                          | HTTP, SMTP, LDAP Server",
  "   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)            | HTTP, SMTP, LDAP Server",
  "   1421 | hMailServer                                      | HTTP, SMTP, LDAP Server",
  "    111 | nsldaps, SSHA-1(Base64), Netscape LDAP SSHA      | HTTP, SMTP, LDAP Server",
  "   1411 | SSHA-256(Base64), LDAP {SSHA256}                 | HTTP, SMTP, LDAP Server",
  "   1711 | SSHA-512(Base64), LDAP {SSHA512}                 | HTTP, SMTP, LDAP Server",
  "  16400 | CRAM-MD5 Dovecot                                 | HTTP, SMTP, LDAP Server",
  "  12800 | MS-AzureSync  PBKDF2-HMAC-SHA256                 | Operating Systems",
  "    122 | macOS v10.4, MacOS v10.5, MacOS v10.6            | Operating Systems",
  "   1722 | macOS v10.7                                      | Operating Systems",
  "    500 | Cisco-IOS $1$ (MD5)                              | Operating Systems",
  "   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                    | Operating Systems",
  "     22 | Juniper NetScreen/SSG (ScreenOS)                 | Operating Systems",
  "  15100 | Juniper/NetBSD sha1crypt                         | Operating Systems",
  "   7000 | FortiGate (FortiOS)                              | Operating Systems",
  "  13800 | Windows Phone 8+ PIN/password                    | Operating Systems",
  "   8100 | Citrix NetScaler                                 | Operating Systems",
  "   9900 | Radmin2                                          | Operating Systems",
  "    125 | ArubaOS                                          | Operating Systems",
  "   7700 | SAP CODVN B (BCODE)                              | Enterprise Application Software (EAS)",
  "   7701 | SAP CODVN B (BCODE) via RFC_READ_TABLE           | Enterprise Application Software (EAS)",
  "   7800 | SAP CODVN F/G (PASSCODE)                         | Enterprise Application Software (EAS)",
  "   7801 | SAP CODVN F/G (PASSCODE) via RFC_READ_TABLE      | Enterprise Application Software (EAS)",
  "  10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1              | Enterprise Application Software (EAS)",
  "   8600 | Lotus Notes/Domino 5                             | Enterprise Application Software (EAS)",
  "   8700 | Lotus Notes/Domino 6                             | Enterprise Application Software (EAS)",
  "   9100 | Lotus Notes/Domino 8                             | Enterprise Application Software (EAS)",
  "    133 | PeopleSoft                                       | Enterprise Application Software (EAS)",
  "  13200 | AxCrypt                                          | Archives",
  "  13300 | AxCrypt in-memory SHA1                           | Archives",
  "  13600 | WinZip                                           | Archives",
  "  14700 | iTunes backup < 10.0                             | Backup",
  "  14800 | iTunes backup >= 10.0                            | Backup",
  "   8800 | Android FDE <= 4.3                               | Full-Disk Encryption (FDE)",
  "  12900 | Android FDE (Samsung DEK)                        | Full-Disk Encryption (FDE)",
  "  12200 | eCryptfs                                         | Full-Disk Encryption (FDE)",
  "   9400 | MS Office 2007                                   | Documents",
  "   9500 | MS Office 2010                                   | Documents",
  "  10600 | PDF 1.7 Level 3 (Acrobat 9)                      | Documents",
  "  10700 | PDF 1.7 Level 8 (Acrobat 10 - 11)                | Documents",
  "  16200 | Apple Secure Notes                               | Documents",
  "  12700 | Blockchain, My Wallet                            | Password Managers",
  "  15200 | Blockchain, My Wallet, V2                        | Password Managers",
  "  16600 | Electrum Wallet (Salt-Type 1-2)                  | Password Managers",
  "  15500 | JKS Java Key Store Private Keys (SHA1)           | Password Managers",
  "  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256     | Password Managers",

/**
 * Missing self-test hashes:
 *
 * ST_HASH_16500  multi-hash-mode algorithm, unlikely to match self-test hash settings
 */

static const char *ST_HASH_00021 = "e983672a03adcc9767b24584338eb378:00";
static const char *ST_HASH_00022 = "nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n:26506173";
static const char *ST_HASH_00030 = "1169500a7dfece72e1f7fc9c9410867a:687430237020";
static const char *ST_HASH_00040 = "23a8a90599fc5d0d15265d4d3b565f6e:58802707";
static const char *ST_HASH_00050 = "e28e4e37e972a945e464b5226053bac0:40";
static const char *ST_HASH_00060 = "7f51edecfa6fb401a0b5e63d33fc8c0e:84143";
static const char *ST_HASH_00111 = "{SSHA}FLzWcQqyle6Mo7NvrwXCMAmRzXQxNjYxMTYzNw==";
static const char *ST_HASH_00112 = "63ec5f6113843f5d229e2d49c068d983a9670d02:57677783202322766743";
static const char *ST_HASH_00120 = "a428863972744b16afef28e0087fc094b44bb7b1:465727565";
static const char *ST_HASH_00121 = "d27c0a627a45db487af161fcc3a4005d88eb8a1f:25551135";
static const char *ST_HASH_00122 = "86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9";
static const char *ST_HASH_00124 = "sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013";
static const char *ST_HASH_00125 = "83377286015bcebb857b23b94331e2b316b6ecbe9fbf26c4fc";
static const char *ST_HASH_00130 = "0a9e4591f539a77cd3af67bae207d250bc86bac6:23240710432";
static const char *ST_HASH_00131 = "0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939";
static const char *ST_HASH_00132 = "0x010045083578bf13a6e30ca29c40e540813772754d54a5ffd325";
static const char *ST_HASH_00133 = "uXmFVrdBvv293L9kDR3VnRmx4ZM=";
static const char *ST_HASH_00140 = "03b83421e2aa6d872d1f8dee001dc226ef01722b:818436";
static const char *ST_HASH_00141 = "$episerver$*0*MjEwNA==*ZUgAmuaYTqAvisD0A427FA3oaWU";
static const char *ST_HASH_00150 = "02b256705348a28b1d6c0f063907979f7e0c82f8:10323";
static const char *ST_HASH_00160 = "8d7cb4d4a27a438059bb83a34d1e6cc439669168:2134817";
static const char *ST_HASH_01410 = "5bb7456f43e3610363f68ad6de82b8b96f3fc9ad24e9d1f1f8d8bd89638db7c0:12480864321";
static const char *ST_HASH_01411 = "{SSHA256}L5Wk0zPY2lmoR5pH20zngq37KkxFwgTquEhx95rxfVk3Ng==";
static const char *ST_HASH_01420 = "816d1ded1d621873595048912ea3405d9d42afd3b57665d9f5a2db4d89720854:36176620";
static const char *ST_HASH_01421 = "8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3";
static const char *ST_HASH_01430 = "b2d0db162e30dfef1bfd606689a3acbc213c47ef3fd11968394191886075249d:32002";
static const char *ST_HASH_01440 = "84ebe1bc3d59919a8c4f9337d66bd163661586c828b24b8067a27a6dc4228c64:05662";
static const char *ST_HASH_01441 = "$episerver$*1*NDg1NTIz*8BFCg/YJBAuZs/wjbH3OWKe69BLr5Lao26ybpnD48Zk";
static const char *ST_HASH_01450 = "b435ffbacea34d5eb0dbc4d69a92f0152f2cf4cd364d34c2ece322ca22d8b334:21217";
static const char *ST_HASH_01460 = "8b9472281c36c3a693703de0e0f1ffab8fc0ecdd3bc5ead04c76dd74ef431e49:70108387805";
static const char *ST_HASH_01600 = "$apr1$62722340$zGjeAwVP2KwY6MtumUI1N/";
static const char *ST_HASH_01710 = "3f749c84d00c6f94a6651b5c195c71dacae08f3cea6fed760232856cef701f7bf60d7f38a587f69f159d4e4cbe00435aeb9c8c0a4927b252d76a744e16e87e91:388026522082";
static const char *ST_HASH_01711 = "{SSHA512}Bz8w5q6qEtB1Nnc8b1jfTvTXVTwohWag33oghQGOtLChnkZTw/cuJaHQlLJEI3AWKZGCRyLA6Phujdxo+is7AjA2MDcyNjY1Mg==";
static const char *ST_HASH_01720 = "efc5dd0e4145970917abdc311e1d4e23ba0afa9426d960cb28569f4d585cb031af5c936f57fbcb0a08368a1b302573cf582100d40bd7c632f3d8aecd1a1a8eb1:812";
static const char *ST_HASH_01730 = "eefb67342d62a5d8ac84e8ae89d0f157f03749bd0427c80637003a4760feefdb36cbe11ba35ab2015b3691e2e83803178c986aa85f29e6f56938b469a31ccd7a:6576666";
static const char *ST_HASH_01740 = "ce77bf8a8ca9b9cf0ed67edde58ed7fafd4542ce1378fc8bd87b05656ebf92e5711517d5930c18de93a71990e77e1037423e5b64c2f293be7d859d7b6921622e:1512373";
static const char *ST_HASH_01722 = "07543781b07e905f6f947db8ae305c248b9e12f509b41097e852e2f450e824790e677ea7397b8a9a552b1c19ecf6a6e1dd3844fa5ee5db23976962859676f7d2fb85ca94";
static const char *ST_HASH_01731 = "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1";
static const char *ST_HASH_01750 = "138c00f17a1a0363f274817c91118f019aff09f937bfdaea844280a0c0e7811267cc4735d967d8640eed1218268c1c4a76fec8f7aa551491b353829f3a654270:885142";
static const char *ST_HASH_01760 = "7d02921299935179d509e6dd4f3d0f2944e3451ea9de3af16baead6a7297e5653577d2473a0fff743d9fe78a89bd49296114319989dc7e7870fc7f62bc96accb:114";
static const char *ST_HASH_02600 = "a936af92b0ae20b1ff6c3347a72e5fbe";
static const char *ST_HASH_02611 = "28f9975808ae2bdc5847b1cda26033ea:308";
static const char *ST_HASH_02612 = "$PHPS$30353031383437363132$f02b0b2f25e5754edb04522c346ba243";
static const char *ST_HASH_02711 = "0844fbb2fdeda31884a7a45ec2010bb6:324410183853308365427804872426";
static const char *ST_HASH_03710 = "a3aa0ae2b4a102a9974cdf40edeabee0:242812778074";
static const char *ST_HASH_03711 = "$B$2152187716$8c8b39c3602b194eeeb6cac78eea2742";
static const char *ST_HASH_03800 = "78274b1105fb8a7c415b43ffe35ec4a9:6";
static const char *ST_HASH_04010 = "82422514daaa8253be0aa43f3e263af5:7530326651137";
static const char *ST_HASH_04110 = "45b1005214e2d9472a7ad681578b2438:64268771004";
static const char *ST_HASH_04300 = "b8c385461bb9f9d733d3af832cf60b27";
static const char *ST_HASH_04400 = "288496df99b33f8f75a7ce4837d1b480";
static const char *ST_HASH_04500 = "3db9184f5da4e463832b086211af8d2314919951";
static const char *ST_HASH_04520 = "59b80a295392eedb677ca377ad7bf3487928df96:136472340404074825440760227553028141804855170538";
static const char *ST_HASH_04521 = "c18e826af2a78c7b9b7261452613233417e65817:28246535720688452723483475753333";
static const char *ST_HASH_04522 = "9038129c474caa3f0de56f38db84033d0fe1d4b8:365563602032";
static const char *ST_HASH_04700 = "92d85978d884eb1d99a51652b1139c8279fa8663";
static const char *ST_HASH_04900 = "75d280ca9a0c2ee18729603104ead576d9ca6285:347070";
static const char *ST_HASH_06000 = "012cb9b334ec1aeb71a9c8ce85586082467f7eb6";
static const char *ST_HASH_06100 = "7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258";
static const char *ST_HASH_07000 = "AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8=";
static const char *ST_HASH_07700 = "027642760180$77EC38630C08DF8D";
static const char *ST_HASH_07701 = "027642760180$77EC386300000000";
static const char *ST_HASH_07800 = "604020408266$32837BA7B97672BA4E5AC74767A4E6E1AE802651";
static const char *ST_HASH_07801 = "604020408266$32837BA7B97672BA4E5A00000000000000000000";
static const char *ST_HASH_07900 = "$S$C20340258nzjDWpoQthrdNTR02f0pmev0K/5/Nx80WSkOQcPEQRh";
static const char *ST_HASH_08000 = "0xc0071808773188715731b69bd4e310b4129913aaf657356c5bdf3c46f249ed42477b5c74af6eaac4d15a";
static const char *ST_HASH_08100 = "1130725275da09ca13254957f2314a639818d44c37ef6d558";
static const char *ST_HASH_08300 = "pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1";
static const char *ST_HASH_08400 = "7f8d1951fe48ae3266980c2979c141f60e4415e5:5037864764153886517871426607441768004150";
static const char *ST_HASH_08600 = "3dd2e1e5ac03e230243d58b8c5ada076";
static const char *ST_HASH_08700 = "(GDJ0nDZI8l8RJzlRbemg)";
static const char *ST_HASH_08800 = "$fde$16$ca56e82e7b5a9c2fc1e3b5a7d671c2f9$16$7c124af19ac913be0fc137b75a34b20d$eac806ae7277c8d48243d52a8644fa57a817317bd3457f94dca727964cbc27c88296954f289597a9de3314a4e9d9f28dce70cf9ce3e1c3c0c6fc041687a0ad3cb333d4449bc9da8fcc7d5f85948a7ac3bc6d34f505e9d0d91da4396e35840bde3465ad11c5086c89ee6db68d65e47a2e5413f272caa01e02224e5ff3dc3bed3953a702e85e964e562e62f5c97a2df6c47547bfb5aeeb329ff8f9c9666724d399043fe970c8b282b45e93d008333f3b4edd5eb147bd023ed18ac1f9f75a6cd33444b507694c64e1e98a964b48c0a77276e9930250d01801813c235169a7b1952891c63ce0d462abc688bd96c0337174695a957858b4c9fd277d04abe8a0c2c5def4b352ba29410f8dbec91bcb2ca2b8faf26d44f02340b3373bc94e7487ce014e6adfbf7edfdd2057225f8aeb324c9d1be877c6ae4211ae387e07bf2a056984d2ed2815149b3e9cf9fbfae852f7dd5906c2b86e7910c0d7755ef5bcc39f0e135bf546c839693dc4af3e50b8382c7c8c754d4ee218fa85d70ee0a5707a9f827209a7ddb6c2fb9431a61c9775112cc88aa2a34f97c2f53dfce082aa0758917269a5fc30049ceab67d3efd721fee021ffca979f839b4f052e27f5c382c0dd5c02fd39fbc9b26e04bf9e051d1923eff9a7cde3244902bb8538b1b9f11631def5aad7c21d2113bcdc989b771ff6bf220f94354034dd417510117b55a669e969fc3bc6c5dcd4741b8313bf7d999dc94d4949f27eec0cd06f906c17a80d09f583a5dd601854832673b78d125a2c5ad0352932be7b93c611fee8c6049670442d8c532674f3d21d45d3d009211d2a9e6568252ac4682982172cb43e7c6b05e85851787ad90e25b77cce3f7968d455f92653a1d3790bc50e5f6e1f743ac47275ffa8e81bbe832a8d7d78d5d5a7c73f95703aebb355849ae566492093bd9cb51070f39c69bb4e22b99cc0e60e96d048385bb69f1c44a3b79547fbc19a873a632f43f05fa2d8a6f9155e59d153e2851b739c42444018b8c4e09a93be43570834667d0b5a5d2a53b1572dab3e750b3f9e641e303559bace06612fbd451a5e822201442828e79168c567a85d8c024cd8ce32bf650105b1af98cc5428675f4f4bbede37a0ef98d1533a8a6dcb27d87a2b799f18706f4677edaa0411becac4c591ede83993aedba660d1dd67f6c4a5c141ad3e6e0c77730cb0ecbf4f4bd8ef6067e05ca3bc563d9e1554a893fea0050bdd1733c883f533f87eac39cceee0ccf817fc1f19bcfdd13e9f241b89bfb149b509e9a0747658438536b6705514cc6d6bb3c64c903e4710435d8bebc35297d1ebbdff8074b203f37d1910d8b4637e4d3dab997f4aa378a7a67c79e698a11e83d0d7e759d0e7969c4f5408168b282fe28d3279ec1d4cc6f85a0f8e5d01f21c7508a69773c44167ff8d467d0801f9ec54f9ee2496d4e7e470214abc1ca11355bb18cd23273aac6b05b47f9e301b42b137a2455758c24e2716dcd2e55bbeb780f592e664e7392bf6eccb80959f24c8800816c84f2575e82e1f3559c33a5be7a3a0c843c2989f486b113d5eeada007caf6b5a0f6d71e2f5c09a4def57c7057168051868317a9ec790d570d76a0d21a45ad951c475db5a66101475871147c5a5907ec4e6b14128ed6695bb73c1c97952e96826eeb6003aa13462093e4afc209627241f03b0247e110fbab983640423b7cdf112e01579fed68c80ac7df7449d9d2114b9ae5539c03c2037be45c5f74e7357b25c6a24b7bd503864437147e50d7ac4ccc4bbd0cabecdc6bac60a362285fe450e2c2d0a446578c8880dc957e6e8061e691b83eb8062d1aad476e0c7b25e4d5454f1288686eb525f37fe649637b235b7828366b0219a9c63d6ddbb696dc3585a2ebfbd5f5e4c170d6784ab9993e15142535e194d2bee3dc9477ef8b8e1b07605e0c04f49edf6d42be3a9dabbc592dde78ce8b7dd9684bfcf4ca2f5a44b1872abe18fb6fa67a79390f273a9d12f9269389629456d71b9e7ed3447462269a849ce83e1893f253c832537f850b1acce5b11d2ba6b7c2f99e8e7c8085f390c21f69e1ce4bbf85b4e1ad86c0d6706432766978076f4cada9ca6f28d395d9cc5e74b2a6b46eb9d1de79eeecff7dc97ec2a8d8870e3894e1e4e26ccb98dd2f88c0229bbd3152fa149f0cc132561f";
static const char *ST_HASH_09100 = "(HC34tD3KtDp4oCZWmCJ4qC30mC30mC3KmC30mCcA5ovrMLH9M)";
static const char *ST_HASH_09200 = "$8$84486783037343$pYNyVrtyMalQrZLxRi7ZLQS1Fl.jkYCgASUi5P8JNb2";
static const char *ST_HASH_09400 = "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f";
static const char *ST_HASH_09500 = "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9";
static const char *ST_HASH_09900 = "22527bee5c29ce95373c4e0f359f079b";
static const char *ST_HASH_10000 = "pbkdf2_sha256$10000$1135411628$bFYX62rfJobJ07VwrUMXfuffLfj2RDM2G6/BrTrUWkE=";
static const char *ST_HASH_10100 = "583e6f51e52ba296:2:4:47356410265714355482333327356688";
static const char *ST_HASH_10200 = "$cram_md5$MTI=$dXNlciBiOGYwNjk5MTE0YjA1Nzg4OTIyM2RmMDg0ZjgyMjQ2Zg==";
static const char *ST_HASH_10300 = "{x-issha, 1024}BnjXMqcNTwa3BzdnUOf1iAu6dw02NzU4MzE2MTA=";
static const char *ST_HASH_10600 = "$pdf$5*5*256*-1028*1*16*28562274676426582441147358074521*127*a3aab04cff2c536118870976d768f1fdd445754d6b2dd81fba10bb6e742acd7f2856227467642658244114735807452100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";
static const char *ST_HASH_10700 = "$pdf$5*6*256*-1028*1*16*62137640825124540503886403748430*127*0391647179352257f7181236ba371e540c2dbb82fac1c462313eb58b772a54956213764082512454050388640374843000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";
static const char *ST_HASH_10900 = "sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk";
static const char *ST_HASH_11100 = "$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e";
static const char *ST_HASH_11200 = "$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601";
static const char *ST_HASH_11400 = "$sip$*72087*1215344588738747***342210558720*737232616*1215344588738747*8867133055*65600****MD5*e9980869221f9d1182c83b0d5e56a7db";
static const char *ST_HASH_11700 = "57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36";
static const char *ST_HASH_11750 = "0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337";
static const char *ST_HASH_11760 = "d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337";
static const char *ST_HASH_11800 = "5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3";
static const char *ST_HASH_11850 = "be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337";
static const char *ST_HASH_11860 = "bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337";
static const char *ST_HASH_11900 = "md5:1000:NjAxMDY4MQ==:a00DtIW9hP9voC85fmEA5uVhgdDx67nSPSm9yADHjkI=";
static const char *ST_HASH_12001 = "{PKCS5S2}NTczNTY0NDY2NjQyNzU1Mx8gGiRGobaZYwumctGHbn2ZOHB8LkwzH+Z1gkWfy1zD";
static const char *ST_HASH_12100 = "sha512:1000:NzY2:DNWohLbdIWIt4Npk9gpTvA==";
static const char *ST_HASH_12200 = "$ecryptfs$0$1$4207883745556753$567daa975114206c";
static const char *ST_HASH_12300 = "8F75FBD166AFDB6D7587DAB89C2F15672AAC031C5B0B5E65C0835FB130555F6FF4E0E5764976755558112246FFF306450C22F6B7746B9E9831ED97B373992F9157436180438417080374881414745255";
static const char *ST_HASH_12700 = "$blockchain$288$713253722114000682636604801283547365b7a53a802a7388d08eb7e6c32c1efb4a157fe19bca940a753d7f16e8bdaf491aa9cf6cda4035ac48d56bb025aced81455424272f3e0459ec7674df3e82abd7323bc09af4fd0869fd790b3f17f8fe424b8ec81a013e1476a5c5a6a53c4b85a055eecfbc13eccf855f905d3ddc3f0c54015b8cb177401d5942af833f655947bfc12fc00656302f31339187de2a69ab06bc61073933b3a48c9f144177ae4b330968eb919f8a22cec312f734475b28cdfe5c25b43c035bf132887f3241d86b71eb7e1cf517f99305b19c47997a1a1f89df6248749ac7f38ca7c88719cf16d6af2394307dce55600b8858f4789cf1ae8fd362ef565cd9332f32068b3c04c9282553e658b759c2e76ed092d67bd55961ae";
static const char *ST_HASH_12800 = "v1;PPH1_MD4,54188415275183448824,100,55b530f052a9af79a7ba9c466dddcb8b116f8babf6c3873a51a3898fb008e123";
static const char *ST_HASH_12900 = "15738301074686823451275227041071157383010746868234512752270410712bc4be900bf96ccf43c9852fff49b5f5874a9f6e7bf301686fa6d98286de151f15738301074686823451275227041071";
static const char *ST_HASH_13200 = "$axcrypt$*1*10467*9a7cd609bb262c738d9f0e4977039b94*ecbe0fd05a96fd2099d88a92eebb76c59d6837dfe55b3631";
static const char *ST_HASH_13300 = "$axcrypt_sha1$b89eaac7e61417341b710b727768294d";
static const char *ST_HASH_13600 = "$zip2$*0*3*0*74705614874758221371566185145124*1605*0**75bf9be92e8ab106ff67*$/zip2$";
static const char *ST_HASH_13800 = "060a4a94cb2263bcefe74705bd0efe7643d09c2bc25fc69f6a32c1b8d5a5d0d9:4647316184156410832507278642444030512402463246148636510356103432440257733102761444262383653100802140838605535187005586063548643765207865344068042278454875021452355870320020868064506248840047414683714173748364871633802572014845467035357710118327480707136422";
static const char *ST_HASH_13900 = "058c1c3773340c8563421e2b17e60eb7c916787e:827500576";
static const char *ST_HASH_14400 = "fcdc7ec700b887e8eaebf94c2ec52aebb5521223:63038426024388230227";
static const char *ST_HASH_14700 = "$itunes_backup$*9*ebd7f9b33293b2511f0a4139d5b213feff51476968863cef60ec38d720497b6ff39a0bb63fa9f84e*10000*2202015774208421818002001652122401871832**";
static const char *ST_HASH_14800 = "$itunes_backup$*10*17a3b858e79bc273be43a9f113b71efe7ec8e7e401396b350180b4592ef45db67ffef7b2d64329a5*10000*2721336781705041205314422175267631184867*1000*99fafc983e732998adb9fadc162a2e382143f115";
static const char *ST_HASH_15100 = "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q";
static const char *ST_HASH_15200 = "$blockchain$v2$5000$288$324724252428471806184866704068819419467b2b32fd9593fd1a274e0b68bf2c72e5a1f5e748fd319056d1e47ca7b40767136a2d97d7133d14faaeca50986f66cdbc0faec0a3fabbd0ba5d08d5322b6b53da021aacfc439c45bec0e9fe02ad81db82f94e9bd36a7d4d76b505c2339fcd46565d3abab958fbeb1de8bfc53beb96cde8fe44128965477c9ef0762c62bbb1d66532b4888e174ea949db54374a2ed9686a63eb0b5b17ae293f7410bb4ae5106f108314a259c5fd097d558515d79350713412159103a8a174cd384a14f3da45efe18044e1146036000231f6042577d0add98fc959d265368e398dc1550b0bc693e9023cd9d51b40e701bd786e19c3a281a90465aa6ea3f9e756d430164ab2eb43be5b6796d7ac15b2fe99217410f2";
static const char *ST_HASH_15500 = "$jksprivk$*338BD2FBEBA7B3EF198A4CBFC6E18AFF1E229367*5225850113575146134463704406336350011656*D5253EB151EB92DC73E542D8C0A4D7A848A5B0C0E370E625E6547D4E6F23416FC85A27BC295731B8021CDFBD003551C66C434FFBC87DACAD1FDF39022320034A2F86E779F2B1B3325428A666518FA89507AD63E15FD9C57B9E36EF5B642A2F448A9A3F09B79AD93D65F46B8692CD07539FD140146F8F219DC262971AF019E18EDC16C3C240569E1673F4D98BC818CCF28298D5A7BFF038A663DD10FE5E48643C3217C237D342164E2D41EF15075431FBD5B34800E5AE7EB80FAA5AE9982A55F35379AA7B31217E7F1C5F1964A15024A305AE4B3981FE1C80C163BC38ECA5581F11867E5C34C5D124D0367B3737E5E5BB14D2CAB26A698C8DAAB755C82BA6B823BCAECDD4A89C831651ACE5A6029FD0D3515C5D1D53AD8B9062CE8C445373862035CBBF60D490CA2E4975EE6E0358EC32E871FAB15347E3032E21F30F543BAAB01D779BA833CA0B8C7591B42C7C59A8FDD46D7DECEC0E91ADBF331177605E7830ABED62FAD7D5D806D8EFD01C38765940B7F97168FC72C39BF4C98F944FFC310CA8F4EB1D0F960F352CC5E2BB23A1EB221072A5471EDA2CE81C04595B8D37088CFB5C14F6A4A881AD12125DEFBB8154EB4C130AB7FD9933FD36DF1A6A26B51AB169866788678FCED988C8E017CA84354F487A5508210181AFB8B3AD0753E3E28BE674DFBD4E4FBDFD1E30D592F4EA3A77A2F0F5CF9A175DBC590EF5D42971A39918F12B92DCD8BFD56BE9A3459856B5587603C7B53062663A4C8894BBC9894FB1663BF30F32D907664328138B7A50EAC7F8E3183D74562A5C90FE1889AC4C5FE43EBEB8974563B6682F92591ECA4FA0DA72236C3851DA102DB6BA0CC07BFD32F7E962AB0EDCF4A8DEA6525174F5BB5C021E2A9A3F7F761E9CA90B6E27FB7E55CD91DA184FAC5E534E8AD25314C56CE5796506A0CA70881782F9C5147D87705065D68BD67D2B0344205BA6445D562273690004CA5A303274FB283A75F49BA968D7947943AA98F2AF9CB8253B425B86225E7395A331AC4CB1B1700C64D4F458D5D642C54148AE6DA41D9E26657D331B157D76042C2CF3057B83997C23D8BF68FB3C7337CAFB8B324AD0DF7A80B554B4D7F9AD6ED527E7932F1741A573C152A41610F6517E3F4A3BC6B66685871A7CE3795C559BD47CDB8E34CB2C1DFE980518D79E2078C258C54F312EB38609F640E7DC013E0F2A16A25BB5971882B4308D27930CA99FEC231AE927B62215A1B56098C362B7F20593953B29428681875070E84BF5B60BEA3948127151634123DA77C814AAD54CE10905763C8C19BC191C0C40458C809402E1957C4C05C4EAE27576B2D30593F7FDCC9A248DB5DB23CF2FA22A92C016090F611690BF0AB5B8B2866ED25F345EFE85DF3311C9E91C37CEE709CF16E7CB09D01BECD2961D094C02D42EC85BF47FAB1B67A13B9A1741C15F7156D57A71BFFABB03B71E69707913A5C136B3D69CE3F71ABFE376F0A21D723FFA2E60AC180689D3E8AF4348C9F555CD897387327FC8BA2B9C51A7298547E556A11A60441EF5331A1BFB847A3D23DD9F7C50E636A2C6309BC82E1A8852F5A8569B6D93*14*78D6A2424484CF5149932B7EA8BF*test";
static const char *ST_HASH_16100 = "$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006";
static const char *ST_HASH_16200 = "$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41";
static const char *ST_HASH_16300 = "$ethereum$w*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128*f3abede76ac15228f1b161dd9660bb9094e81b1b*d201ccd492c284484c7824c4d37b1593";
static const char *ST_HASH_16400 = "{CRAM-MD5}5389b33b9725e5657cb631dc50017ff100000000000000000000000000000000";
static const char *ST_HASH_16600 = "$electrum$1*44358283104603165383613672586868*c43a6632d9f59364f74c395a03d8c2ea";

static const char *HT_00030 = "md5(utf16le($pass).$salt)";
static const char *HT_00040 = "md5($salt.utf16le($pass))";
static const char *HT_00050 = "HMAC-MD5 (key = $pass)";
static const char *HT_00060 = "HMAC-MD5 (key = $salt)";
static const char *HT_00100 = "SHA1";
static const char *HT_00110 = "sha1($pass.$salt)";
static const char *HT_00120 = "sha1($salt.$pass)";
static const char *HT_00130 = "sha1(utf16le($pass).$salt)";
static const char *HT_00140 = "sha1($salt.utf16le($pass))";
static const char *HT_00150 = "HMAC-SHA1 (key = $pass)";
static const char *HT_00160 = "HMAC-SHA1 (key = $salt)";
static const char *HT_01410 = "sha256($pass.$salt)";
static const char *HT_01420 = "sha256($salt.$pass)";
static const char *HT_01430 = "sha256(utf16le($pass).$salt)";
static const char *HT_01440 = "sha256($salt.utf16le($pass))";
static const char *HT_01450 = "HMAC-SHA256 (key = $pass)";
static const char *HT_01460 = "HMAC-SHA256 (key = $salt)";
static const char *HT_01600 = "Apache $apr1$ MD5, md5apr1, MD5 (APR)";
static const char *HT_01710 = "sha512($pass.$salt)";
static const char *HT_01720 = "sha512($salt.$pass)";
static const char *HT_01730 = "sha512(utf16le($pass).$salt)";
static const char *HT_01740 = "sha512($salt.utf16le($pass))";
static const char *HT_01750 = "HMAC-SHA512 (key = $pass)";
static const char *HT_01760 = "HMAC-SHA512 (key = $salt)";
static const char *HT_02600 = "md5(md5($pass))";
static const char *HT_03710 = "md5($salt.md5($pass))";
static const char *HT_03711 = "MediaWiki B type";
static const char *HT_03800 = "md5($salt.$pass.$salt)";
static const char *HT_04010 = "md5($salt.md5($salt.$pass))";
static const char *HT_04110 = "md5($salt.md5($pass.$salt))";
static const char *HT_04300 = "md5(strtoupper(md5($pass)))";
static const char *HT_04400 = "md5(sha1($pass))";
static const char *HT_04500 = "sha1(sha1($pass))";
static const char *HT_04520 = "sha1($salt.sha1($pass))";
static const char *HT_04700 = "sha1(md5($pass))";
static const char *HT_04900 = "sha1($salt.$pass.$salt)";
static const char *HT_06000 = "RIPEMD-160";
static const char *HT_06100 = "Whirlpool";
static const char *HT_07000 = "FortiGate (FortiOS)";
static const char *HT_07700 = "SAP CODVN B (BCODE)";
static const char *HT_07701 = "SAP CODVN B (BCODE) mangled from RFC_READ_TABLE";
static const char *HT_07800 = "SAP CODVN F/G (PASSCODE)";
static const char *HT_07801 = "SAP CODVN F/G (PASSCODE) mangled from RFC_READ_TABLE";
static const char *HT_07900 = "Drupal7";
static const char *HT_08000 = "Sybase ASE";
static const char *HT_08100 = "Citrix NetScaler";
static const char *HT_08300 = "DNSSEC (NSEC3)";
static const char *HT_08400 = "WBB3 (Woltlab Burning Board)";
static const char *HT_08600 = "Lotus Notes/Domino 5";
static const char *HT_08700 = "Lotus Notes/Domino 6";
static const char *HT_08800 = "Android FDE <= 4.3";
static const char *HT_09100 = "Lotus Notes/Domino 8";
static const char *HT_09200 = "Cisco-IOS $8$ (PBKDF2-SHA256)";
static const char *HT_09400 = "MS Office 2007";
static const char *HT_09500 = "MS Office 2010";
static const char *HT_09900 = "Radmin2";
static const char *HT_10000 = "Django (PBKDF2-SHA256)";
static const char *HT_10100 = "SipHash";
static const char *HT_10200 = "CRAM-MD5";
static const char *HT_10300 = "SAP CODVN H (PWDSALTEDHASH) iSSHA-1";
static const char *HT_10600 = "PDF 1.7 Level 3 (Acrobat 9)";
static const char *HT_10700 = "PDF 1.7 Level 8 (Acrobat 10 - 11)";
static const char *HT_10900 = "PBKDF2-HMAC-SHA256";
static const char *HT_11100 = "PostgreSQL CRAM (MD5)";
static const char *HT_11200 = "MySQL CRAM (SHA1)";
static const char *HT_11400 = "SIP digest authentication (MD5)";
static const char *HT_11700 = "GOST R 34.11-2012 (Streebog) 256-bit, big-endian";
static const char *HT_11750 = "HMAC-Streebog-256 (key = $pass), big-endian";
static const char *HT_11760 = "HMAC-Streebog-256 (key = $salt), big-endian";
static const char *HT_11800 = "GOST R 34.11-2012 (Streebog) 512-bit, big-endian";
static const char *HT_11850 = "HMAC-Streebog-512 (key = $pass), big-endian";
static const char *HT_11860 = "HMAC-Streebog-512 (key = $salt), big-endian";
static const char *HT_11900 = "PBKDF2-HMAC-MD5";
static const char *HT_12100 = "PBKDF2-HMAC-SHA512";
static const char *HT_12200 = "eCryptfs";
static const char *HT_12300 = "Oracle T: Type (Oracle 12+)";
static const char *HT_12700 = "Blockchain, My Wallet";
static const char *HT_12800 = "MS-AzureSync PBKDF2-HMAC-SHA256";
static const char *HT_12900 = "Android FDE (Samsung DEK)";
static const char *HT_13200 = "AxCrypt";
static const char *HT_13300 = "AxCrypt in-memory SHA1";
static const char *HT_13600 = "WinZip";
static const char *HT_13800 = "Windows Phone 8+ PIN/password";
static const char *HT_13900 = "OpenCart";
static const char *HT_14400 = "sha1(CX)";
static const char *HT_14700 = "iTunes backup < 10.0";
static const char *HT_14800 = "iTunes backup >= 10.0";
static const char *HT_15100 = "Juniper/NetBSD sha1crypt";
static const char *HT_15200 = "Blockchain, My Wallet, V2";
static const char *HT_15500 = "JKS Java Key Store Private Keys (SHA1)";
static const char *HT_16100 = "TACACS+";
static const char *HT_16200 = "Apple Secure Notes";
static const char *HT_16300 = "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256";
static const char *HT_16400 = "CRAM-MD5 Dovecot";
static const char *HT_16500 = "JWT (JSON Web Token)";
static const char *HT_16600 = "Electrum Wallet (Salt-Type 1-3)";

static const char *HT_00022 = "Juniper NetScreen/SSG (ScreenOS)";
static const char *HT_00101 = "nsldap, SHA-1(Base64), Netscape LDAP SHA";
static const char *HT_00111 = "nsldaps, SSHA-1(Base64), Netscape LDAP SSHA";
static const char *HT_00112 = "Oracle S: Type (Oracle 11+)";
static const char *HT_00121 = "SMF (Simple Machines Forum) > v1.1";
static const char *HT_00122 = "macOS v10.4, macOS v10.5, MacOS v10.6";
static const char *HT_00124 = "Django (SHA-1)";
static const char *HT_00125 = "ArubaOS";
static const char *HT_00131 = "MSSQL (2000)";
static const char *HT_00132 = "MSSQL (2005)";
static const char *HT_00133 = "PeopleSoft";
static const char *HT_00141 = "Episerver 6.x < .NET 4";
static const char *HT_01411 = "SSHA-256(Base64), LDAP {SSHA256}";
static const char *HT_01421 = "hMailServer";
static const char *HT_01441 = "Episerver 6.x >= .NET 4";
static const char *HT_01711 = "SSHA-512(Base64), LDAP {SSHA512}";
static const char *HT_01722 = "macOS v10.7";
static const char *HT_01731 = "MSSQL (2012, 2014)";
static const char *HT_02611 = "vBulletin < v3.8.5";
static const char *HT_02612 = "PHPS";
static const char *HT_02711 = "vBulletin >= v3.8.5";
static const char *HT_04521 = "Redmine";
static const char *HT_04522 = "PunBB";
static const char *HT_12001 = "Atlassian (PBKDF2-HMAC-SHA1)";

static const char *SIGNATURE_ANDROIDFDE         = "$fde$";
static const char *SIGNATURE_AXCRYPT            = "$axcrypt$";
static const char *SIGNATURE_AXCRYPT_SHA1       = "$axcrypt_sha1$";
static const char *SIGNATURE_CISCO8             = "$8$";
static const char *SIGNATURE_CRAM_MD5           = "$cram_md5$";
static const char *SIGNATURE_CRAM_MD5_DOVECOT   = "{CRAM-MD5}";
static const char *SIGNATURE_DJANGOPBKDF2       = "pbkdf2_sha256";
static const char *SIGNATURE_DJANGOSHA1         = "sha1$";
static const char *SIGNATURE_DRUPAL7            = "$S$";
static const char *SIGNATURE_ECRYPTFS           = "$ecryptfs$";
static const char *SIGNATURE_EPISERVER          = "$episerver$";
static const char *SIGNATURE_MEDIAWIKI_B        = "$B$";
static const char *SIGNATURE_MS_DRSR            = "v1;PPH1_MD4";
static const char *SIGNATURE_MSSQL              = "0x0100";
static const char *SIGNATURE_MSSQL2012          = "0x0200";
static const char *SIGNATURE_MYSQL_AUTH         = "$mysqlna$";
static const char *SIGNATURE_MYWALLET           = "$blockchain$";
static const char *SIGNATURE_MYWALLETV2         = "$blockchain$v2$";
static const char *SIGNATURE_NETSCALER          = "1";
static const char *SIGNATURE_OFFICE2007         = "$office$";
static const char *SIGNATURE_OFFICE2010         = "$office$";
static const char *SIGNATURE_PBKDF2_MD5         = "md5";
static const char *SIGNATURE_PBKDF2_SHA256      = "sha256";
static const char *SIGNATURE_PBKDF2_SHA512      = "sha512";
static const char *SIGNATURE_PHPS               = "$PHPS$";
static const char *SIGNATURE_POSTGRESQL_AUTH    = "$postgres$";
static const char *SIGNATURE_SAPH_SHA1          = "{x-issha, ";
static const char *SIGNATURE_SHA1B64            = "{SHA}";
static const char *SIGNATURE_SHA256B64S         = "{SSHA256}";
static const char *SIGNATURE_SHA512B64S         = "{SSHA512}";
static const char *SIGNATURE_SIP_AUTH           = "$sip$";
static const char *SIGNATURE_SSHA1B64_lower     = "{ssha}";
static const char *SIGNATURE_SSHA1B64_upper     = "{SSHA}";
static const char *SIGNATURE_SYBASEASE          = "0xc007";
static const char *SIGNATURE_ZIP2_START         = "$zip2$";
static const char *SIGNATURE_ZIP2_STOP          = "$/zip2$";
static const char *SIGNATURE_ITUNES_BACKUP      = "$itunes_backup$";
static const char *SIGNATURE_FORTIGATE          = "AK1";
static const char *SIGNATURE_ATLASSIAN          = "{PKCS5S2}";
static const char *SIGNATURE_NETBSD_SHA1CRYPT   = "$sha1$";
static const char *SIGNATURE_JKS_SHA1           = "$jksprivk$";
static const char *SIGNATURE_TACACS_PLUS        = "$tacacs-plus$0$";
static const char *SIGNATURE_ETHEREUM_PRESALE   = "$ethereum$w";
static const char *SIGNATURE_ELECTRUM_WALLET    = "$electrum$";
static const char *SIGNATURE_APPLE_SECURE_NOTES = "$ASN$";

/**
 * decoder / encoder
 */

static void netbsd_sha1crypt_decode (u8 digest[20], const u8 buf[28], u8 *additional_byte)
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  additional_byte[0] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

static void netbsd_sha1crypt_encode (const u8 digest[20], u8 additional_byte, u8 buf[30])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (additional_byte << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);
  buf[28] = 0;
}

static void drupal7_decode (u8 digest[64], const u8 buf[44])
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[15] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[17] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  digest[18] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[20] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[28]) <<  0;
  l |= itoa64_to_int (buf[29]) <<  6;
  l |= itoa64_to_int (buf[30]) << 12;
  l |= itoa64_to_int (buf[31]) << 18;

  digest[21] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[23] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[32]) <<  0;
  l |= itoa64_to_int (buf[33]) <<  6;
  l |= itoa64_to_int (buf[34]) << 12;
  l |= itoa64_to_int (buf[35]) << 18;

  digest[24] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[26] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[36]) <<  0;
  l |= itoa64_to_int (buf[37]) <<  6;
  l |= itoa64_to_int (buf[38]) << 12;
  l |= itoa64_to_int (buf[39]) << 18;

  digest[27] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[29] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[40]) <<  0;
  l |= itoa64_to_int (buf[41]) <<  6;
  l |= itoa64_to_int (buf[42]) << 12;
  l |= itoa64_to_int (buf[43]) << 18;

  digest[30] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[32] = (l >> 16) & 0xff;

  digest[33] = 0;
  digest[34] = 0;
  digest[35] = 0;
  digest[36] = 0;
  digest[37] = 0;
  digest[38] = 0;
  digest[39] = 0;
  digest[40] = 0;
  digest[41] = 0;
  digest[42] = 0;
  digest[43] = 0;
  digest[44] = 0;
  digest[45] = 0;
  digest[46] = 0;
  digest[47] = 0;
  digest[48] = 0;
  digest[49] = 0;
  digest[50] = 0;
  digest[51] = 0;
  digest[52] = 0;
  digest[53] = 0;
  digest[54] = 0;
  digest[55] = 0;
  digest[56] = 0;
  digest[57] = 0;
  digest[58] = 0;
  digest[59] = 0;
  digest[60] = 0;
  digest[61] = 0;
  digest[62] = 0;
  digest[63] = 0;
}

static void drupal7_encode (const u8 digest[64], u8 buf[43])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[15] << 0) | (digest[16] << 8) | (digest[17] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (digest[18] << 0) | (digest[19] << 8) | (digest[20] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);

  l = (digest[21] << 0) | (digest[22] << 8) | (digest[23] << 16);

  buf[28] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[29] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[30] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[31] = int_to_itoa64 (l & 0x3f);

  l = (digest[24] << 0) | (digest[25] << 8) | (digest[26] << 16);

  buf[32] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[33] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[34] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[35] = int_to_itoa64 (l & 0x3f);

  l = (digest[27] << 0) | (digest[28] << 8) | (digest[29] << 16);

  buf[36] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[37] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[38] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[39] = int_to_itoa64 (l & 0x3f);

  l = (digest[30] << 0) | (digest[31] << 8) | (digest[32] << 16);

  buf[40] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[41] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[42] = int_to_itoa64 (l & 0x3f); //l >>= 6;
  //buf[43] = int_to_itoa64 (l & 0x3f);
}

int arubaos_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 2;

  token.len[0]  = 10;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 40;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  if ((salt_pos[8] != '0') || (salt_pos[9] != '1')) return (PARSER_SIGNATURE_UNMATCHED);

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int macos1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 2;

  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 40;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int macos512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 2;

  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 128;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int netscreen_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 30;
  token.len_max[0] = 30;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[1] = 1;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  // unscramble

  u8 clean_input_buf[32] = { 0 };

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };
  int  pos[6] = {   0,   6,  12,  17,  23,  29 };

  for (int i = 0, j = 0, k = 0; i < 30; i++)
  {
    if (i == pos[j])
    {
      if (sig[j] != hash_pos[i]) return (PARSER_SIGNATURE_UNMATCHED);

      j++;
    }
    else
    {
      clean_input_buf[k] = hash_pos[i];

      k++;
    }
  }

  // base64 decode

  u32 a, b, c, d, e, f;

  a = base64_to_int (clean_input_buf[ 0] & 0x7f);
  b = base64_to_int (clean_input_buf[ 1] & 0x7f);
  c = base64_to_int (clean_input_buf[ 2] & 0x7f);
  d = base64_to_int (clean_input_buf[ 3] & 0x7f);
  e = base64_to_int (clean_input_buf[ 4] & 0x7f);
  f = base64_to_int (clean_input_buf[ 5] & 0x7f);

  digest[0] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[ 6] & 0x7f);
  b = base64_to_int (clean_input_buf[ 7] & 0x7f);
  c = base64_to_int (clean_input_buf[ 8] & 0x7f);
  d = base64_to_int (clean_input_buf[ 9] & 0x7f);
  e = base64_to_int (clean_input_buf[10] & 0x7f);
  f = base64_to_int (clean_input_buf[11] & 0x7f);

  digest[1] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[12] & 0x7f);
  b = base64_to_int (clean_input_buf[13] & 0x7f);
  c = base64_to_int (clean_input_buf[14] & 0x7f);
  d = base64_to_int (clean_input_buf[15] & 0x7f);
  e = base64_to_int (clean_input_buf[16] & 0x7f);
  f = base64_to_int (clean_input_buf[17] & 0x7f);

  digest[2] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[18] & 0x7f);
  b = base64_to_int (clean_input_buf[19] & 0x7f);
  c = base64_to_int (clean_input_buf[20] & 0x7f);
  d = base64_to_int (clean_input_buf[21] & 0x7f);
  e = base64_to_int (clean_input_buf[22] & 0x7f);
  f = base64_to_int (clean_input_buf[23] & 0x7f);

  digest[3] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // max. salt length: 55 (max for MD5) - 22 (":Administration Tools:") - 1 (0x80) = 32
  // 32 - 4 bytes (to fit w0lr for all attack modes) = 28

  if (salt->salt_len > 28) return (PARSER_SALT_LENGTH);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  static const char *adm = ":Administration Tools:";

  memcpy (salt_buf_ptr + salt->salt_len, adm, strlen (adm));

  salt->salt_len += strlen (adm);

  return (PARSER_OK);
}

int episerver_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_EPISERVER;

  token.len_min[0] = 11;
  token.len_max[0] = 11;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 0;
  token.len_max[2] = 44;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[3] = 27;
  token.len_max[3] = 27;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int md4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD4M_A;
    digest[1] -= MD4M_B;
    digest[2] -= MD4M_C;
    digest[3] -= MD4M_D;
  }

  return (PARSER_OK);
}

int md4s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD4M_A;
    digest[1] -= MD4M_B;
    digest[2] -= MD4M_C;
    digest[3] -= MD4M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  return (PARSER_OK);
}

int md5s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  if (hashconfig->opts_type & OPTS_TYPE_ST_HASH_MD5)
  {
    // precompute md5 of the salt

    precompute_salt_md5 (salt->salt_buf, salt->salt_len, (u8 *) salt->salt_buf_pc);
  }

  return (PARSER_OK);
}

int md5pix_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.sep[0]     = ':';
  token.len_min[0] = 16;
  token.len_max[0] = 16;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = itoa64_to_int (hash_pos[ 0]) <<  0
            | itoa64_to_int (hash_pos[ 1]) <<  6
            | itoa64_to_int (hash_pos[ 2]) << 12
            | itoa64_to_int (hash_pos[ 3]) << 18;
  digest[1] = itoa64_to_int (hash_pos[ 4]) <<  0
            | itoa64_to_int (hash_pos[ 5]) <<  6
            | itoa64_to_int (hash_pos[ 6]) << 12
            | itoa64_to_int (hash_pos[ 7]) << 18;
  digest[2] = itoa64_to_int (hash_pos[ 8]) <<  0
            | itoa64_to_int (hash_pos[ 9]) <<  6
            | itoa64_to_int (hash_pos[10]) << 12
            | itoa64_to_int (hash_pos[11]) << 18;
  digest[3] = itoa64_to_int (hash_pos[12]) <<  0
            | itoa64_to_int (hash_pos[13]) <<  6
            | itoa64_to_int (hash_pos[14]) << 12
            | itoa64_to_int (hash_pos[15]) << 18;

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  return (PARSER_OK);
}

int md5md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  /**
   * This is a virtual salt. While the algorithm is basically not salted
   * we can exploit the salt buffer to set the 0x80 and the w[14] value.
   * This way we can save a special md5md5 kernel and reuse the one from vbull.
   */

  static const u8 *zero = (const u8*) "";

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, zero, 0, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int vb30_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 23;
  token.len_max[1] = 31;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  return (PARSER_OK);
}

int sha1axcrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_AXCRYPT_SHA1;

  token.len[0]     = 14;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 32;
  token.len_max[1] = 40;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = 0;

  return (PARSER_OK);
}

int sha1s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha1b64_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SHA1B64;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 28;
  token.len_max[1] = 28;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];
  const int hash_len = token.len[1];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  return (PARSER_OK);
}

int sha1b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_SSHA1B64_lower;
  token.signatures_buf[1] = SIGNATURE_SSHA1B64_upper;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 28;
  token.len_max[1] = 368; // 368 = 20 + 256 where 20 is digest length and 256 is SALT_MAX
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashsalt_pos = token.buf[1];
  const int hashsalt_len = token.len[1];

  u8 tmp_buf[512] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, hashsalt_pos, hashsalt_len, tmp_buf);

  if (tmp_len < 20) return (PARSER_HASH_LENGTH);

  u8 *hash_pos = tmp_buf;

  memcpy (digest, hash_pos, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  // salt

  u8 *salt_pos = tmp_buf + 20;
  int salt_len = tmp_len - 20;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, salt_pos, salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int mssql2000_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MSSQL;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 8;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 40;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[3]     = 40;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[3];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int mssql2005_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MSSQL;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 8;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 40;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int mssql2012_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MSSQL2012;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 8;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 128;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int oracles_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 20;
  token.len_max[1] = 20;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int oraclet_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 2;

  token.len[0]  = 128;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 32;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  digest[ 0] = byte_swap_32 (digest[ 0]);
  digest[ 1] = byte_swap_32 (digest[ 1]);
  digest[ 2] = byte_swap_32 (digest[ 2]);
  digest[ 3] = byte_swap_32 (digest[ 3]);
  digest[ 4] = byte_swap_32 (digest[ 4]);
  digest[ 5] = byte_swap_32 (digest[ 5]);
  digest[ 6] = byte_swap_32 (digest[ 6]);
  digest[ 7] = byte_swap_32 (digest[ 7]);
  digest[ 8] = byte_swap_32 (digest[ 8]);
  digest[ 9] = byte_swap_32 (digest[ 9]);
  digest[10] = byte_swap_32 (digest[10]);
  digest[11] = byte_swap_32 (digest[11]);
  digest[12] = byte_swap_32 (digest[12]);
  digest[13] = byte_swap_32 (digest[13]);
  digest[14] = byte_swap_32 (digest[14]);
  digest[15] = byte_swap_32 (digest[15]);

  const u8 *salt_pos = token.buf[1];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_iter = ROUNDS_ORACLET - 1;
  salt->salt_len  = 16;

  return (PARSER_OK);
}

int sha224_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 56;
  token.len_max[0] = 56;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA224M_A;
    digest[1] -= SHA224M_B;
    digest[2] -= SHA224M_C;
    digest[3] -= SHA224M_D;
    digest[4] -= SHA224M_E;
    digest[5] -= SHA224M_F;
    digest[6] -= SHA224M_G;
  }

  return (PARSER_OK);
}

int sha256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  return (PARSER_OK);
}

int sha256s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha384_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 96;
  token.len_max[0] = 96;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +  0);
  digest[1] = hex_to_u64 (hash_pos + 16);
  digest[2] = hex_to_u64 (hash_pos + 32);
  digest[3] = hex_to_u64 (hash_pos + 48);
  digest[4] = hex_to_u64 (hash_pos + 64);
  digest[5] = hex_to_u64 (hash_pos + 80);
  digest[6] = 0;
  digest[7] = 0;

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = 0;
  digest[7] = 0;

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA384M_A;
    digest[1] -= SHA384M_B;
    digest[2] -= SHA384M_C;
    digest[3] -= SHA384M_D;
    digest[4] -= SHA384M_E;
    digest[5] -= SHA384M_F;
    digest[6] -= 0;
    digest[7] -= 0;
  }

  return (PARSER_OK);
}

int sha512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  return (PARSER_OK);
}

int sha512s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int ripemd160_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  return (PARSER_OK);
}

int whirlpool_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  digest[ 0] = byte_swap_32 (digest[ 0]);
  digest[ 1] = byte_swap_32 (digest[ 1]);
  digest[ 2] = byte_swap_32 (digest[ 2]);
  digest[ 3] = byte_swap_32 (digest[ 3]);
  digest[ 4] = byte_swap_32 (digest[ 4]);
  digest[ 5] = byte_swap_32 (digest[ 5]);
  digest[ 6] = byte_swap_32 (digest[ 6]);
  digest[ 7] = byte_swap_32 (digest[ 7]);
  digest[ 8] = byte_swap_32 (digest[ 8]);
  digest[ 9] = byte_swap_32 (digest[ 9]);
  digest[10] = byte_swap_32 (digest[10]);
  digest[11] = byte_swap_32 (digest[11]);
  digest[12] = byte_swap_32 (digest[12]);
  digest[13] = byte_swap_32 (digest[13]);
  digest[14] = byte_swap_32 (digest[14]);
  digest[15] = byte_swap_32 (digest[15]);

  return (PARSER_OK);
}

int episerver4_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_EPISERVER;

  token.len_min[0] = 11;
  token.len_max[0] = 11;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 0;
  token.len_max[2] = 24;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[3] = 43;
  token.len_max[3] = 43;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sha512grub_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SHA512GRUB;

  token.len[0]     = 19;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.sep[1]     = '.';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = SALT_MIN;
  token.len_max[2] = SALT_MAX;
  token.sep[2]     = '.';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[3] = 128;
  token.len_max[3] = 128;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[3];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2] / 2;

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha512->salt_buf;

  for (int i = 0, j = 0; i < salt_len; i += 1, j += 2)
  {
    salt_buf_ptr[i] = hex_to_u8 (salt_pos + j);
  }

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
  salt->salt_buf[4] = pbkdf2_sha512->salt_buf[4];
  salt->salt_buf[5] = pbkdf2_sha512->salt_buf[5];
  salt->salt_buf[6] = pbkdf2_sha512->salt_buf[6];
  salt->salt_buf[7] = pbkdf2_sha512->salt_buf[7];
  salt->salt_len    = salt_len;

  const u8 *iter_pos = token.buf[1];

  salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10) - 1;

  return (PARSER_OK);
}

int sha512b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SHA512B64S;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 88;
  token.len_max[1] = 428; // 428 = 64 + 256 where 64 is digest length and 256 is SALT_MAX
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashsalt_pos = token.buf[1];
  const int hashsalt_len = token.len[1];

  u8 tmp_buf[512] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, hashsalt_pos, hashsalt_len, tmp_buf);

  if (tmp_len < 64) return (PARSER_HASH_LENGTH);

  u8 *hash_pos = tmp_buf;

  memcpy (digest, hash_pos, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  // salt

  u8 *salt_pos = tmp_buf + 64;
  int salt_len = tmp_len - 64;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, salt_pos, salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int sapb_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.len_min[0] = 1;
  token.len_max[0] = 40;
  token.sep[0]     = '$';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[1] = 16;
  token.len_max[1] = 16;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * salt
   */

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  int user_len = 0;

  for (int i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  /**
   * hash
   */

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos + 0);
  digest[1] = hex_to_u32 (hash_pos + 8);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int sapg_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.len_min[0] = 1;
  token.len_max[0] = 40;
  token.sep[0]     = '$';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[1] = 40;
  token.len_max[1] = 40;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * salt
   */

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  int user_len = 0;

  for (int i = 0; i < salt_len; i++)
  {
    if (salt_pos[i] == ' ') continue;

    user_len++;
  }

  // SAP user names cannot be longer than 12 characters
  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  /**
   * hash
   */

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int drupal7_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DRUPAL7;

  token.len[0]     = 3;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len[2]     = 8;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  token.len[3]     = 43;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 salt_iter = 1u << itoa64_to_int (iter_pos[0]);

  if (salt_iter > 0x80000000) return (PARSER_SALT_ITERATION);

  memcpy ((u8 *) salt->salt_sign, input_buf, 4);

  salt->salt_iter = salt_iter;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  // hash

  const u8 *hash_pos = token.buf[3];

  drupal7_decode ((u8 *) digest, hash_pos);

  // ugly hack start

  u8 *tmp = (u8 *) salt->salt_buf_pc;

  tmp[0] = hash_pos[42];

  // ugly hack end

  digest[ 0] = byte_swap_64 (digest[ 0]);
  digest[ 1] = byte_swap_64 (digest[ 1]);
  digest[ 2] = byte_swap_64 (digest[ 2]);
  digest[ 3] = byte_swap_64 (digest[ 3]);
  digest[ 4] = 0;
  digest[ 5] = 0;
  digest[ 6] = 0;
  digest[ 7] = 0;

  return (PARSER_OK);
}

int sybasease_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SYBASEASE;

  token.len[0]  = 6;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 16;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]  = 64;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // hash

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int mysql323_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 16;
  token.len_max[0] = 16;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = 0;
  digest[3] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int netscaler_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_NETSCALER;

  token.len[0]  = 1;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 8;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]  = 40;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  memcpy (salt->salt_buf, salt_pos, salt_len);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_len = salt_len;

  // hash

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  return (PARSER_OK);
}

int nsec3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.sep[0]     = ':';
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 32;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = ':';
  token.len_min[2] = 1;
  token.len_max[2] = 32;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]     = ':';
  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // ok, the plan for this algorithm is the following:
  // we have 2 salts here, the domain-name and a random salt
  // while both are used in the initial transformation,
  // only the random salt is used in the following iterations
  // so we create two buffer, one that includes domain-name (stored into salt_buf_pc[])
  // and one that includes only the real salt (stored into salt_buf[]).
  // the domain-name length is put into array position 7 of salt_buf_pc[] since there is not salt_pc_len

  const u8 *hash_pos = token.buf[0];
  const int hash_len = token.len[0];

  u8 tmp_buf[100] = { 0 };

  base32_decode (itoa32_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // domain

  const u8 *domain_pos = token.buf[1];
  const int domain_len = token.len[1];

  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  memcpy (salt_buf_pc_ptr, domain_pos, domain_len);

  if (salt_buf_pc_ptr[0] != '.') return (PARSER_SALT_VALUE);

  u8 *len_ptr = salt_buf_pc_ptr;

  *len_ptr = 0;

  for (int i = 1; i < domain_len; i++)
  {
    if (salt_buf_pc_ptr[i] == '.')
    {
      len_ptr = salt_buf_pc_ptr + i;

      *len_ptr = 0;
    }
    else
    {
      *len_ptr += 1;
    }
  }

  salt->salt_len_pc = domain_len;

  // "real" salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // iteration

  const u8 *iter_pos = token.buf[3];

  salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  return (PARSER_OK);
}

int wbb3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 40;
  token.len_max[1] = 40;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int opencart_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 9;
  token.len_max[1] = 9;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int lotus5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  return (PARSER_OK);
}

int lotus6_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 4;

  token.len[0]  = 1;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[1]  = 1;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]  = 19;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64A;

  token.len[3]  = 1;
  token.attr[3] = TOKEN_ATTR_FIXED_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  if (token.buf[0][0] != '(') return (PARSER_SIGNATURE_UNMATCHED);
  if (token.buf[1][0] != 'G') return (PARSER_SIGNATURE_UNMATCHED);
  if (token.buf[3][0] != ')') return (PARSER_SIGNATURE_UNMATCHED);

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, hash_pos, hash_len, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  // salt

  memcpy (salt->salt_buf, tmp_buf, 5);

  salt->salt_len = 5;

  memcpy (digest, tmp_buf + 5, 9);

  // yes, only 9 byte are needed to crack, but 10 to display

  salt->salt_buf_pc[7] = hash_pos[18];

  return (PARSER_OK);
}

int lotus8_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt = 4;

  token.len[0]  = 1;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[1]  = 1;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]  = 48;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64A;

  token.len[3]  = 1;
  token.attr[3] = TOKEN_ATTR_FIXED_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  if (token.buf[0][0] != '(') return (PARSER_SIGNATURE_UNMATCHED);
  if (token.buf[1][0] != 'H') return (PARSER_SIGNATURE_UNMATCHED);
  if (token.buf[3][0] != ')') return (PARSER_SIGNATURE_UNMATCHED);

  // decode

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, hash_pos, hash_len, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  // salt

  memcpy (salt->salt_buf, tmp_buf, 16);

  salt->salt_len = 16; // Attention: in theory we have 2 salt_len, one for the -m 8700 part (len: 8), 2nd for the 9100 part (len: 16)

  // iteration

  char tmp_iter_buf[11] = { 0 };

  memcpy (tmp_iter_buf, tmp_buf + 16, 10);

  tmp_iter_buf[10] = 0;

  salt->salt_iter = hc_strtoul ((const char *) tmp_iter_buf, NULL, 10);

  if (salt->salt_iter < 1) // well, the limit hopefully is much higher
  {
    return (PARSER_SALT_ITERATION);
  }

  salt->salt_iter--; // first round in init

  // 2 additional bytes for display only

  salt->salt_buf_pc[0] = tmp_buf[26];
  salt->salt_buf_pc[1] = tmp_buf[27];

  // digest

  memcpy (digest, tmp_buf + 28, 8);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int hmailserver_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  token.len_min[1] = 64;
  token.len_max[1] = 64;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int phps_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PHPS;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 0;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[2] = 32;
  token.len_max[2] = 32;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int mediawiki_b_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MEDIAWIKI_B;

  token.len[0]     = 3;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[2] = 32;
  token.len_max[2] = 32;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_buf_ptr[salt_len] = 0x2d;

  salt->salt_len = salt_len + 1;

  return (PARSER_OK);
}

int peoplesoft_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 28;
  token.len_max[0] = 28;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];
  const int hash_len = token.len[0];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  salt->salt_buf[0] = 0x80;

  salt->salt_len = 0;

  return (PARSER_OK);
}

int androidfde_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  androidfde_t *androidfde = (androidfde_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ANDROIDFDE;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 2;
  token.len_max[1] = 2;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[2] = 32;
  token.len_max[2] = 32;
  token.sep[2]     = '$';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[3] = 2;
  token.len_max[3] = 2;
  token.sep[3]     = '$';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[4] = 32;
  token.len_max[4] = 32;
  token.sep[4]     = '$';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[5] = 3072;
  token.len_max[5] = 3072;
  token.sep[5]     = '$';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[4];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len  = salt_len / 2;
  salt->salt_iter = ROUNDS_ANDROIDFDE - 1;

  // data

  const u8 *data_pos = token.buf[5];
  const int data_len = token.len[5];

  for (int i = 0, j = 0; i < data_len; i += 8, j += 1)
  {
    androidfde->data[j] = hex_to_u32 (data_pos + i);

    androidfde->data[j] = byte_swap_32 (androidfde->data[j]);
  }

  return (PARSER_OK);
}

int cisco8_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CISCO8;

  token.len[0]     = 3;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 14;
  token.len_max[1] = 14;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len[2]     = 43;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt is not encoded

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt_buf_ptr[17] = 0x01;
  salt_buf_ptr[18] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];

  salt->salt_len  = salt_len;
  salt->salt_iter = ROUNDS_CISCO8 - 1;

  // base64 decode hash

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[100] = { 0 };

  const int tmp_len = base64_decode (itoa64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int office2007_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2007_t *office2007 = (office2007_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE2007;

  token.len_min[0] = 8;
  token.len_max[0] = 8;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 4;
  token.len_max[1] = 4;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 2;
  token.len_max[2] = 2;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 3;
  token.len_max[3] = 3;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 2;
  token.len_max[4] = 2;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[5] = 32;
  token.len_max[5] = 32;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[6] = 32;
  token.len_max[6] = 32;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[7] = 40;
  token.len_max[7] = 40;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos               = token.buf[1];
  const u8 *verifierHashSize_pos      = token.buf[2];
  const u8 *keySize_pos               = token.buf[3];
  const u8 *saltSize_pos              = token.buf[4];
  const u8 *osalt_pos                 = token.buf[5];
  const u8 *encryptedVerifier_pos     = token.buf[6];
  const u8 *encryptedVerifierHash_pos = token.buf[7];

  const u32 version           = hc_strtoul ((const char *) version_pos, NULL, 10);
  const u32 verifierHashSize  = hc_strtoul ((const char *) verifierHashSize_pos, NULL, 10);
  const u32 keySize           = hc_strtoul ((const char *) keySize_pos, NULL, 10);
  const u32 saltSize          = hc_strtoul ((const char *) saltSize_pos, NULL, 10);

  if (version           != 2007)            return (PARSER_SALT_VALUE);
  if (verifierHashSize  != 20)              return (PARSER_SALT_VALUE);
  if (saltSize          != 16)              return (PARSER_SALT_VALUE);
  if ((keySize != 128) && (keySize != 256)) return (PARSER_SALT_VALUE);

  office2007->keySize = keySize;

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = ROUNDS_OFFICE2007;

  salt->salt_buf[0] = hex_to_u32 (osalt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (osalt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (osalt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (osalt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  /**
   * esalt
   */

  office2007->encryptedVerifier[0] = hex_to_u32 (encryptedVerifier_pos +  0);
  office2007->encryptedVerifier[1] = hex_to_u32 (encryptedVerifier_pos +  8);
  office2007->encryptedVerifier[2] = hex_to_u32 (encryptedVerifier_pos + 16);
  office2007->encryptedVerifier[3] = hex_to_u32 (encryptedVerifier_pos + 24);

  office2007->encryptedVerifier[0] = byte_swap_32 (office2007->encryptedVerifier[0]);
  office2007->encryptedVerifier[1] = byte_swap_32 (office2007->encryptedVerifier[1]);
  office2007->encryptedVerifier[2] = byte_swap_32 (office2007->encryptedVerifier[2]);
  office2007->encryptedVerifier[3] = byte_swap_32 (office2007->encryptedVerifier[3]);

  office2007->encryptedVerifierHash[0] = hex_to_u32 (encryptedVerifierHash_pos +  0);
  office2007->encryptedVerifierHash[1] = hex_to_u32 (encryptedVerifierHash_pos +  8);
  office2007->encryptedVerifierHash[2] = hex_to_u32 (encryptedVerifierHash_pos + 16);
  office2007->encryptedVerifierHash[3] = hex_to_u32 (encryptedVerifierHash_pos + 24);
  office2007->encryptedVerifierHash[4] = hex_to_u32 (encryptedVerifierHash_pos + 32);

  office2007->encryptedVerifierHash[0] = byte_swap_32 (office2007->encryptedVerifierHash[0]);
  office2007->encryptedVerifierHash[1] = byte_swap_32 (office2007->encryptedVerifierHash[1]);
  office2007->encryptedVerifierHash[2] = byte_swap_32 (office2007->encryptedVerifierHash[2]);
  office2007->encryptedVerifierHash[3] = byte_swap_32 (office2007->encryptedVerifierHash[3]);
  office2007->encryptedVerifierHash[4] = byte_swap_32 (office2007->encryptedVerifierHash[4]);

  /**
   * digest
   */

  digest[0] = office2007->encryptedVerifierHash[0];
  digest[1] = office2007->encryptedVerifierHash[1];
  digest[2] = office2007->encryptedVerifierHash[2];
  digest[3] = office2007->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int office2010_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  office2010_t *office2010 = (office2010_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE2010;

  token.len_min[0] = 8;
  token.len_max[0] = 8;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 4;
  token.len_max[1] = 4;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 6;
  token.len_max[2] = 6;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 3;
  token.len_max[3] = 3;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 2;
  token.len_max[4] = 2;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[5] = 32;
  token.len_max[5] = 32;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[6] = 32;
  token.len_max[6] = 32;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[7] = 64;
  token.len_max[7] = 64;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos               = token.buf[1];
  const u8 *spinCount_pos             = token.buf[2];
  const u8 *keySize_pos               = token.buf[3];
  const u8 *saltSize_pos              = token.buf[4];
  const u8 *osalt_pos                 = token.buf[5];
  const u8 *encryptedVerifier_pos     = token.buf[6];
  const u8 *encryptedVerifierHash_pos = token.buf[7];

  const u32 version   = hc_strtoul ((const char *) version_pos, NULL, 10);
  const u32 spinCount = hc_strtoul ((const char *) spinCount_pos, NULL, 10);
  const u32 keySize   = hc_strtoul ((const char *) keySize_pos, NULL, 10);
  const u32 saltSize  = hc_strtoul ((const char *) saltSize_pos, NULL, 10);

  if (version   != 2010)    return (PARSER_SALT_VALUE);
  if (spinCount != 100000)  return (PARSER_SALT_VALUE);
  if (keySize   != 128)     return (PARSER_SALT_VALUE);
  if (saltSize  != 16)      return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = spinCount;

  salt->salt_buf[0] = hex_to_u32 (osalt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (osalt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (osalt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (osalt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  /**
   * esalt
   */

  office2010->encryptedVerifier[0] = hex_to_u32 (encryptedVerifier_pos +  0);
  office2010->encryptedVerifier[1] = hex_to_u32 (encryptedVerifier_pos +  8);
  office2010->encryptedVerifier[2] = hex_to_u32 (encryptedVerifier_pos + 16);
  office2010->encryptedVerifier[3] = hex_to_u32 (encryptedVerifier_pos + 24);

  office2010->encryptedVerifier[0] = byte_swap_32 (office2010->encryptedVerifier[0]);
  office2010->encryptedVerifier[1] = byte_swap_32 (office2010->encryptedVerifier[1]);
  office2010->encryptedVerifier[2] = byte_swap_32 (office2010->encryptedVerifier[2]);
  office2010->encryptedVerifier[3] = byte_swap_32 (office2010->encryptedVerifier[3]);

  office2010->encryptedVerifierHash[0] = hex_to_u32 (encryptedVerifierHash_pos +  0);
  office2010->encryptedVerifierHash[1] = hex_to_u32 (encryptedVerifierHash_pos +  8);
  office2010->encryptedVerifierHash[2] = hex_to_u32 (encryptedVerifierHash_pos + 16);
  office2010->encryptedVerifierHash[3] = hex_to_u32 (encryptedVerifierHash_pos + 24);
  office2010->encryptedVerifierHash[4] = hex_to_u32 (encryptedVerifierHash_pos + 32);
  office2010->encryptedVerifierHash[5] = hex_to_u32 (encryptedVerifierHash_pos + 40);
  office2010->encryptedVerifierHash[6] = hex_to_u32 (encryptedVerifierHash_pos + 48);
  office2010->encryptedVerifierHash[7] = hex_to_u32 (encryptedVerifierHash_pos + 56);

  office2010->encryptedVerifierHash[0] = byte_swap_32 (office2010->encryptedVerifierHash[0]);
  office2010->encryptedVerifierHash[1] = byte_swap_32 (office2010->encryptedVerifierHash[1]);
  office2010->encryptedVerifierHash[2] = byte_swap_32 (office2010->encryptedVerifierHash[2]);
  office2010->encryptedVerifierHash[3] = byte_swap_32 (office2010->encryptedVerifierHash[3]);
  office2010->encryptedVerifierHash[4] = byte_swap_32 (office2010->encryptedVerifierHash[4]);
  office2010->encryptedVerifierHash[5] = byte_swap_32 (office2010->encryptedVerifierHash[5]);
  office2010->encryptedVerifierHash[6] = byte_swap_32 (office2010->encryptedVerifierHash[6]);
  office2010->encryptedVerifierHash[7] = byte_swap_32 (office2010->encryptedVerifierHash[7]);

  /**
   * digest
   */

  digest[0] = office2010->encryptedVerifierHash[0];
  digest[1] = office2010->encryptedVerifierHash[1];
  digest[2] = office2010->encryptedVerifierHash[2];
  digest[3] = office2010->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int radmin2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  return (PARSER_OK);
}

int djangosha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DJANGOSHA1;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len[2]     = 40;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int djangopbkdf2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DJANGOPBKDF2;

  token.sep[0]     = '$';
  token.len_min[0] = 13;
  token.len_max[0] = 13;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = SALT_MIN;
  token.len_max[2] = SALT_MAX;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]     = '$';
  token.len_min[3] = 44;
  token.len_max[3] = 44;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  const int iter = strtol ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len  = salt_len;

  salt_buf_ptr[salt_len + 3] = 0x01;
  salt_buf_ptr[salt_len + 4] = 0x80;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // base64 decode hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int siphash_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.sep[0]     = ':';
  token.len_min[0] = 16;
  token.len_max[0] = 16;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = ':';
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 iter_c = token.buf[1][0];
  const u8 iter_d = token.buf[2][0];

  // atm only defaults, let's see if there's more request
  if (iter_c != '2') return (PARSER_SALT_ITERATION);
  if (iter_d != '4') return (PARSER_SALT_ITERATION);

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos + 0);
  digest[1] = hex_to_u32 (hash_pos + 8);
  digest[2] = 0;
  digest[3] = 0;

  // salt

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len = 16;

  return (PARSER_OK);
}

int crammd5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  cram_md5_t *cram_md5 = (cram_md5_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CRAM_MD5;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 0;
  token.len_max[1] = 76;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[2]     = '$';
  token.len_min[2] = 44;
  token.len_max[2] = 132;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  u8  tmp_buf[100];
  int tmp_len;

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, (const u8 *) salt_pos, salt_len, tmp_buf);

  if (tmp_len > 55) return (PARSER_SALT_LENGTH);

  tmp_buf[tmp_len] = 0x80;

  memcpy (salt->salt_buf, tmp_buf, tmp_len + 1);

  salt->salt_len = tmp_len;

  // hash

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  if (tmp_len < 32 + 1) return (PARSER_HASH_LENGTH);

  u32 user_len = tmp_len - 32;

  const u8 *tmp_hash = tmp_buf + user_len;

  user_len--; // skip the trailing space

  if (is_valid_hex_string (tmp_hash, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 (tmp_hash +  0);
  digest[1] = hex_to_u32 (tmp_hash +  8);
  digest[2] = hex_to_u32 (tmp_hash + 16);
  digest[3] = hex_to_u32 (tmp_hash + 24);

  // store username for host only (output hash if cracked)

  memset (cram_md5->user, 0, sizeof (cram_md5->user));
  memcpy (cram_md5->user, tmp_buf, user_len);

  return (PARSER_OK);
}

int crammd5_dovecot_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CRAM_MD5_DOVECOT;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 32;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  u8 *hash_pos = input_buf + 10;

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  return (PARSER_OK);
}

int saph_sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SAPH_SHA1;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '}';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 32;
  token.len_max[2] = 49;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1)
  {
    return (PARSER_SALT_ITERATION);
  }

  iter--; // first iteration is special

  salt->salt_iter = iter;

  // decode

  const u8 *base64_pos = token.buf[2];
  const int base64_len = token.len[2];

  u8 tmp_buf[100] = { 0 };

  const u32 decoded_len = base64_decode (base64_to_int, (const u8 *) base64_pos, base64_len, tmp_buf);

  if (decoded_len < 24) return (PARSER_SALT_LENGTH);

  // copy the salt

  const u32 salt_len = decoded_len - 20;

  if (salt_len > 16) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf + 20, salt_len);

  salt->salt_len = salt_len;

  // set digest

  u32 *digest_ptr = (u32 *) tmp_buf;

  digest[0] = byte_swap_32 (digest_ptr[0]);
  digest[1] = byte_swap_32 (digest_ptr[1]);
  digest[2] = byte_swap_32 (digest_ptr[2]);
  digest[3] = byte_swap_32 (digest_ptr[3]);
  digest[4] = byte_swap_32 (digest_ptr[4]);

  return (PARSER_OK);
}

int redmine_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 32;
  token.len_max[1] = 32;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int punbb_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 12;
  token.len_max[1] = 12;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int pdf17l3_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  int ret = pdf17l8_parse_hash (input_buf, input_len, hash_buf, hashconfig);

  if (ret != PARSER_OK)
  {
    return ret;
  }

  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  salt->salt_buf[2] = 0x80;

  return (PARSER_OK);
}

int pdf17l8_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pdf_t *pdf = (pdf_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 16;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PDF;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 3;
  token.len_max[3] = 3;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 1;
  token.len_max[4] = 6;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[5] = 1;
  token.len_max[5] = 1;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[6] = 1;
  token.len_max[6] = 4;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[7] = 0;
  token.len_max[7] = 1024;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[8] = 1;
  token.len_max[8] = 4;
  token.sep[8]     = '*';
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[9] = 0;
  token.len_max[9] = 1024;
  token.sep[9]     = '*';
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[10] = 1;
  token.len_max[10] = 4;
  token.sep[10]     = '*';
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[11] = 0;
  token.len_max[11] = 1024;
  token.sep[11]     = '*';
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[12] = 1;
  token.len_max[12] = 4;
  token.sep[12]     = '*';
  token.attr[12]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[13] = 0;
  token.len_max[13] = 1024;
  token.sep[13]     = '*';
  token.attr[13]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[14] = 1;
  token.len_max[14] = 4;
  token.sep[14]     = '*';
  token.attr[14]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[15] = 0;
  token.len_max[15] = 1024;
  token.sep[15]     = '*';
  token.attr[15]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *V_pos      = token.buf[1];
  const u8 *R_pos      = token.buf[2];
  const u8 *bits_pos   = token.buf[3];
  const u8 *enc_md_pos = token.buf[5];
  const u8 *u_len_pos  = token.buf[8];
  const u8 *u_buf_pos  = token.buf[9];

  // validate data

  const int V = strtol ((const char *) V_pos, NULL, 10);
  const int R = strtol ((const char *) R_pos, NULL, 10);

  int vr_ok = 0;

  if ((V == 5) && (R == 5)) vr_ok = 1;
  if ((V == 5) && (R == 6)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int bits = strtol ((const char *) bits_pos, NULL, 10);

  if (bits != 256) return (PARSER_SALT_VALUE);

  int enc_md = strtol ((const char *) enc_md_pos, NULL, 10);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const u32 u_len  = hc_strtoul ((const char *) u_len_pos,  NULL, 10);

  // copy data to esalt

  if (u_len < 40) return (PARSER_SALT_VALUE);

  if (is_valid_hex_string (u_buf_pos, 80) == false) return (PARSER_SALT_ENCODING);

  for (int i = 0, j = 0; i < 8 + 2; i += 1, j += 8)
  {
    pdf->u_buf[i] = hex_to_u32 ((const u8 *) &u_buf_pos[j]);
  }

  salt->salt_buf[0] = pdf->u_buf[8];
  salt->salt_buf[1] = pdf->u_buf[9];

  salt->salt_len  = 8;
  salt->salt_iter = ROUNDS_PDF17L8;

  digest[0] = byte_swap_32 (pdf->u_buf[0]);
  digest[1] = byte_swap_32 (pdf->u_buf[1]);
  digest[2] = byte_swap_32 (pdf->u_buf[2]);
  digest[3] = byte_swap_32 (pdf->u_buf[3]);
  digest[4] = byte_swap_32 (pdf->u_buf[4]);
  digest[5] = byte_swap_32 (pdf->u_buf[5]);
  digest[6] = byte_swap_32 (pdf->u_buf[6]);
  digest[7] = byte_swap_32 (pdf->u_buf[7]);

  return (PARSER_OK);
}

int pbkdf2_sha256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PBKDF2_SHA256;

  token.sep[0]     = ':';
  token.len_min[0] = 6;
  token.len_max[0] = 6;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = ':';
  token.len_min[2] = SALT_MIN;
  token.len_max[2] = SALT_MAX;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = ':';
  token.len_min[3] = 16;
  token.len_max[3] = 256;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8  tmp_buf[512];
  int tmp_len;

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len > SALT_MAX) return (PARSER_SALT_LENGTH);

  memcpy (pbkdf2_sha256->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  salt->salt_buf[0] = pbkdf2_sha256->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha256->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha256->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha256->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int postgresql_auth_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_POSTGRESQL_AUTH;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 0;
  token.len_max[1] = 32;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '*';
  token.len_min[2] = 8;
  token.len_max[2] = 8;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[3];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  /*
   * store salt
   */

  const u8 *salt_pos = token.buf[2];

  // first 4 bytes are the "challenge"

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  salt_buf_ptr[0] = hex_to_u8 (salt_pos + 0);
  salt_buf_ptr[1] = hex_to_u8 (salt_pos + 2);
  salt_buf_ptr[2] = hex_to_u8 (salt_pos + 4);
  salt_buf_ptr[3] = hex_to_u8 (salt_pos + 6);

  // append the user name

  const u8 *user_pos = token.buf[1];
  const int user_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt (salt_buf_ptr + 4, (int *) &salt->salt_len, user_pos, user_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  salt->salt_len += 4;

  return (PARSER_OK);
}

int mysql_auth_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MYSQL_AUTH;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 40;
  token.len_max[1] = 40;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  /*
   * store salt
   */

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int sip_auth_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  sip_t *sip = (sip_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 15;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SIP_AUTH;

  token.sep[0]      = '*';
  token.len_min[0]  = 5;
  token.len_max[0]  = 5;
  token.attr[0]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]      = '*';
  token.len_min[1]  = 0;
  token.len_max[1]  = 512;
  token.attr[1]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]      = '*';
  token.len_min[2]  = 0;
  token.len_max[2]  = 512;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]      = '*';
  token.len_min[3]  = 0;
  token.len_max[3]  = 116;
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[4]      = '*';
  token.len_min[4]  = 0;
  token.len_max[4]  = 116;
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[5]      = '*';
  token.len_min[5]  = 0;
  token.len_max[5]  = 246;
  token.attr[5]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[6]      = '*';
  token.len_min[6]  = 0;
  token.len_max[6]  = 245;
  token.attr[6]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[7]      = '*';
  token.len_min[7]  = 1;
  token.len_max[7]  = 246;
  token.attr[7]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[8]      = '*';
  token.len_min[8]  = 0;
  token.len_max[8]  = 245;
  token.attr[8]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[9]      = '*';
  token.len_min[9]  = 1;
  token.len_max[9]  = 1024;
  token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[10]     = '*';
  token.len_min[10] = 0;
  token.len_max[10] = 1024;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[11]     = '*';
  token.len_min[11] = 0;
  token.len_max[11] = 1024;
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[12]     = '*';
  token.len_min[12] = 0;
  token.len_max[12] = 1024;
  token.attr[12]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[13]     = '*';
  token.len_min[13] = 3;
  token.len_max[13] = 3;
  token.attr[13]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[14]     = '*';
  token.len_min[14] = 32;
  token.len_max[14] = 32;
  token.attr[14]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos          = token.buf[ 3];
  const u8 *realm_pos         = token.buf[ 4];
  const u8 *method_pos        = token.buf[ 5];
  const u8 *URI_prefix_pos    = token.buf[ 6];
  const u8 *URI_resource_pos  = token.buf[ 7];
  const u8 *URI_suffix_pos    = token.buf[ 8];
  const u8 *nonce_pos         = token.buf[ 9];
  const u8 *nonce_client_pos  = token.buf[10];
  const u8 *nonce_count_pos   = token.buf[11];
  const u8 *qop_pos           = token.buf[12];
  const u8 *directive_pos     = token.buf[13];
  const u8 *digest_pos        = token.buf[14];

  const int user_len          = token.len[ 3];
  const int realm_len         = token.len[ 4];
  const int method_len        = token.len[ 5];
  const int URI_prefix_len    = token.len[ 6];
  const int URI_resource_len  = token.len[ 7];
  const int URI_suffix_len    = token.len[ 8];
  const int nonce_len         = token.len[ 9];
  const int nonce_client_len  = token.len[10];
  const int nonce_count_len   = token.len[11];
  const int qop_len           = token.len[12];

  // verify

  if (memcmp (directive_pos, "MD5", 3) != 0) return (PARSER_SIP_AUTH_DIRECTIVE);

  /*
   * first (pre-)compute: HA2 = md5 ($method . ":" . $uri)
   */

  static u8 *pcsep = (u8 *) ":";

  int md5_len = method_len + 1 + URI_prefix_len + URI_resource_len + URI_suffix_len;

  if (URI_prefix_len) md5_len++;
  if (URI_suffix_len) md5_len++;

  const int md5_max_len = 4 * 64;

  if (md5_len >= md5_max_len) return (PARSER_SALT_LENGTH);

  u32 tmp_md5_buf[64] = { 0 };

  u8 *tmp_md5_ptr = (u8 *) tmp_md5_buf;

  // method

  hc_strncat (tmp_md5_ptr, method_pos, method_len);

  hc_strncat (tmp_md5_ptr, pcsep, 1);

  // URI_prefix

  if (URI_prefix_len > 0)
  {
    hc_strncat (tmp_md5_ptr, URI_prefix_pos, URI_prefix_len);

    hc_strncat (tmp_md5_ptr, pcsep, 1);
  }

  // URI_resource

  hc_strncat (tmp_md5_ptr, URI_resource_pos, URI_resource_len);

  hc_strncat (tmp_md5_ptr, pcsep, 1);

  // URI_suffix

  if (URI_suffix_len > 0)
  {
    hc_strncat (tmp_md5_ptr, URI_suffix_pos, URI_suffix_len);

    hc_strncat (tmp_md5_ptr, pcsep, 1);
  }

  u32 tmp_digest[4] = { 0 };

  md5_complete_no_limit (tmp_digest, tmp_md5_buf, md5_len);

  tmp_digest[0] = byte_swap_32 (tmp_digest[0]);
  tmp_digest[1] = byte_swap_32 (tmp_digest[1]);
  tmp_digest[2] = byte_swap_32 (tmp_digest[2]);
  tmp_digest[3] = byte_swap_32 (tmp_digest[3]);

  /*
   * esalt
   */

  u8 *esalt_buf_ptr = (u8 *) sip->esalt_buf;

  int esalt_len = 0;

  const int max_esalt_len = sizeof (sip->esalt_buf);

  // there are 2 possibilities for the esalt:

  bool with_auth = false;

  if (qop_len == 4)
  {
    if (memcmp ((const char *) qop_pos, "auth", 4) == 0)
    {
      with_auth = true;
    }
  }

  if (qop_len == 8)
  {
    if (memcmp ((const char *) qop_pos, "auth-int", 8) == 0)
    {
      with_auth = true;
    }
  }

  if (with_auth == true)
  {
    esalt_len = 1 + nonce_len + 1 + nonce_count_len + 1 + nonce_client_len + 1 + qop_len + 1 + 32;

    if (esalt_len > max_esalt_len) return (PARSER_SALT_LENGTH);

    // init

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce

    hc_strncat (esalt_buf_ptr, nonce_pos, nonce_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce_count

    hc_strncat (esalt_buf_ptr, nonce_count_pos, nonce_count_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce_client

    hc_strncat (esalt_buf_ptr, nonce_client_pos, nonce_client_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // qop

    hc_strncat (esalt_buf_ptr, qop_pos, qop_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);
  }
  else
  {
    esalt_len = 1 + nonce_len + 1 + 32;

    if (esalt_len > max_esalt_len) return (PARSER_SALT_LENGTH);

    // init

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce

    hc_strncat (esalt_buf_ptr, nonce_pos, nonce_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);
  }

  // tmp_digest

  u8 tmp[64];

  snprintf ((char *) tmp, sizeof (tmp), "%08x%08x%08x%08x",
    tmp_digest[0],
    tmp_digest[1],
    tmp_digest[2],
    tmp_digest[3]);

  hc_strncat (esalt_buf_ptr, tmp, 32);

  // add 0x80 to esalt

  esalt_buf_ptr[esalt_len] = 0x80;

  sip->esalt_len = esalt_len;

  /*
   * actual salt
   */

  u8 *sip_salt_ptr = (u8 *) sip->salt_buf;

  int salt_len = user_len + 1 + realm_len + 1;

  int max_salt_len = 119;

  if (salt_len > max_salt_len) return (PARSER_SALT_LENGTH);

  // user_pos

  hc_strncat (sip_salt_ptr, user_pos, user_len);

  hc_strncat (sip_salt_ptr, pcsep, 1);

  // realm_pos

  hc_strncat (sip_salt_ptr, realm_pos, realm_len);

  hc_strncat (sip_salt_ptr, pcsep, 1);

  sip->salt_len = salt_len;

  /*
   * fake salt (for sorting)
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  max_salt_len = 55;

  int fake_salt_len = salt_len;

  if (fake_salt_len > max_salt_len)
  {
    fake_salt_len = max_salt_len;
  }

  memcpy (salt_buf_ptr, sip_salt_ptr, fake_salt_len);

  salt->salt_len = fake_salt_len;

  /*
   * digest
   */

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_pos[24]);

  return (PARSER_OK);
}

int streebog_256_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len[0]  = 64;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  return (PARSER_OK);
}

int streebog_256s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = ':';
  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int streebog_512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len[0]  = 128;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  return (PARSER_OK);
}

int streebog_512s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = ':';
  token.len_min[0] = 128;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +   0);
  digest[ 1] = hex_to_u32 (hash_pos +   8);
  digest[ 2] = hex_to_u32 (hash_pos +  16);
  digest[ 3] = hex_to_u32 (hash_pos +  24);
  digest[ 4] = hex_to_u32 (hash_pos +  32);
  digest[ 5] = hex_to_u32 (hash_pos +  40);
  digest[ 6] = hex_to_u32 (hash_pos +  48);
  digest[ 7] = hex_to_u32 (hash_pos +  56);
  digest[ 8] = hex_to_u32 (hash_pos +  64);
  digest[ 9] = hex_to_u32 (hash_pos +  72);
  digest[10] = hex_to_u32 (hash_pos +  80);
  digest[11] = hex_to_u32 (hash_pos +  88);
  digest[12] = hex_to_u32 (hash_pos +  96);
  digest[13] = hex_to_u32 (hash_pos + 104);
  digest[14] = hex_to_u32 (hash_pos + 112);
  digest[15] = hex_to_u32 (hash_pos + 120);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int pbkdf2_md5_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_md5_t *pbkdf2_md5 = (pbkdf2_md5_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PBKDF2_MD5;

  token.sep[0]     = ':';
  token.len_min[0] = 3;
  token.len_max[0] = 3;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = ':';
  token.len_min[2] = SALT_MIN;
  token.len_max[2] = SALT_MAX;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = ':';
  token.len_min[3] = 16;
  token.len_max[3] = 256;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8  tmp_buf[512];
  int tmp_len;

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len > SALT_MAX) return (PARSER_SALT_LENGTH);

  memcpy (pbkdf2_md5->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  salt->salt_buf[0] = pbkdf2_md5->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_md5->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_md5->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_md5->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 16);

  return (PARSER_OK);
}

int pbkdf2_sha512_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u64 *digest = (u64 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PBKDF2_SHA512;

  token.sep[0]     = ':';
  token.len_min[0] = 6;
  token.len_max[0] = 6;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = ':';
  token.len_min[2] = SALT_MIN;
  token.len_max[2] = SALT_MAX;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = ':';
  token.len_min[3] = 16;
  token.len_max[3] = 256;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8  tmp_buf[512];
  int tmp_len;

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len > SALT_MAX) return (PARSER_SALT_LENGTH);

  memcpy (pbkdf2_sha512->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  // hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len < 16) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 64);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  return (PARSER_OK);
}

int ecryptfs_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ECRYPTFS;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 16;
  token.len_max[3] = 16;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 16;
  token.len_max[4] = 16;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[4];

  digest[ 0] = hex_to_u32 (hash_pos + 0);
  digest[ 1] = hex_to_u32 (hash_pos + 8);
  digest[ 2] = 0;
  digest[ 3] = 0;
  digest[ 4] = 0;
  digest[ 5] = 0;
  digest[ 6] = 0;
  digest[ 7] = 0;
  digest[ 8] = 0;
  digest[ 9] = 0;
  digest[10] = 0;
  digest[11] = 0;
  digest[12] = 0;
  digest[13] = 0;
  digest[14] = 0;
  digest[15] = 0;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);

  // salt

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_iter = ROUNDS_ECRYPTFS;
  salt->salt_len  = 8;

  return (PARSER_OK);
}

int axcrypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_AXCRYPT;

  token.sep[0]     = '*';
  token.len_min[0] = 9;
  token.len_max[0] = 9;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 48;
  token.len_max[4] = 48;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *wrapping_rounds_pos = token.buf[2];

  salt->salt_iter = hc_strtoul ((const char *) wrapping_rounds_pos, NULL, 10);

  // salt

  const u8 *wrapped_key_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (wrapped_key_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (wrapped_key_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (wrapped_key_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (wrapped_key_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // data

  const u8 *data_pos = token.buf[4];

  salt->salt_buf[4] = hex_to_u32 (data_pos +  0);
  salt->salt_buf[5] = hex_to_u32 (data_pos +  8);
  salt->salt_buf[6] = hex_to_u32 (data_pos + 16);
  salt->salt_buf[7] = hex_to_u32 (data_pos + 24);
  salt->salt_buf[8] = hex_to_u32 (data_pos + 32);
  salt->salt_buf[9] = hex_to_u32 (data_pos + 40);

  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);
  salt->salt_buf[6] = byte_swap_32 (salt->salt_buf[6]);
  salt->salt_buf[7] = byte_swap_32 (salt->salt_buf[7]);
  salt->salt_buf[8] = byte_swap_32 (salt->salt_buf[8]);
  salt->salt_buf[9] = byte_swap_32 (salt->salt_buf[9]);

  salt->salt_len = 40;

  digest[0] = salt->salt_buf[0];
  digest[1] = salt->salt_buf[1];
  digest[2] = salt->salt_buf[2];
  digest[3] = salt->salt_buf[3];

  return (PARSER_OK);
}

int keepass_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  keepass_t *keepass = (keepass_t *) hash_buf->esalt;

  bool is_keyfile_present = false;

  if (input_len < 128) return (PARSER_SALT_LENGTH);

  if ((input_buf[input_len - (64 + 1 + 2 + 1 + 2)] == '*')
   && (input_buf[input_len - (64 + 1 + 2 + 1 + 1)] == '1')
   && (input_buf[input_len - (64 + 1 + 2 + 1 + 0)] == '*')) is_keyfile_present = true;

  token_t token;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KEEPASS;

  token.sep[0]     = '*';
  token.len_min[0] = 9;
  token.len_max[0] = 9;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 8;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 3;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  if (input_len < 16) return (PARSER_SALT_LENGTH);

  const u8 version = input_buf[10];

  if (version == '1')
  {
    token.token_cnt  = 11;

    token.sep[4]     = '*';
    token.len_min[4] = 32;
    token.len_max[4] = 32;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[5]     = '*';
    token.len_min[5] = 64;
    token.len_max[5] = 64;
    token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[6]     = '*';
    token.len_min[6] = 32;
    token.len_max[6] = 32;
    token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[7]     = '*';
    token.len_min[7] = 64;
    token.len_max[7] = 64;
    token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[8]     = '*';
    token.len_min[8] = 1;
    token.len_max[8] = 1;
    token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_DIGIT;

    token.sep[9]     = '*';
    token.len_min[9] = 1;
    token.len_max[9] = 6;
    token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_DIGIT;

    token.sep[10]     = '*';
    token.len_min[10] = 2;
    token.len_max[10] = 600000;
    token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;

    if (is_keyfile_present == true)
    {
      token.token_cnt = 14;

      token.sep[11]     = '*';
      token.len_min[11] = 1;
      token.len_max[11] = 1;
      token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                        | TOKEN_ATTR_VERIFY_DIGIT;

      token.sep[12]     = '*';
      token.len_min[12] = 2;
      token.len_max[12] = 2;
      token.attr[12]    = TOKEN_ATTR_VERIFY_LENGTH
                        | TOKEN_ATTR_VERIFY_DIGIT;

      token.sep[13]     = '*';
      token.len_min[13] = 64;
      token.len_max[13] = 64;
      token.attr[13]    = TOKEN_ATTR_VERIFY_LENGTH
                        | TOKEN_ATTR_VERIFY_HEX;
    }
  }
  else if (version == '2')
  {
    token.token_cnt  = 9;

    token.sep[4]     = '*';
    token.len_min[4] = 64;
    token.len_max[4] = 64;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[5]     = '*';
    token.len_min[5] = 64;
    token.len_max[5] = 64;
    token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[6]     = '*';
    token.len_min[6] = 32;
    token.len_max[6] = 32;
    token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[7]     = '*';
    token.len_min[7] = 64;
    token.len_max[7] = 64;
    token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[8]     = '*';
    token.len_min[8] = 64;
    token.len_max[8] = 64;
    token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    if (is_keyfile_present == true)
    {
      token.token_cnt = 12;

      token.sep[9]      = '*';
      token.len_min[9]  = 1;
      token.len_max[9]  = 1;
      token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH
                        | TOKEN_ATTR_VERIFY_DIGIT;

      token.sep[10]     = '*';
      token.len_min[10] = 2;
      token.len_max[10] = 2;
      token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                        | TOKEN_ATTR_VERIFY_DIGIT;

      token.sep[11]     = '*';
      token.len_min[11] = 64;
      token.len_max[11] = 64;
      token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                        | TOKEN_ATTR_VERIFY_HEX;
    }
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  keepass->version = hc_strtoul ((const char *) version_pos, NULL, 10);

  // iter

  const u8 *rounds_pos = token.buf[2];

  salt->salt_iter = hc_strtoul ((const char *) rounds_pos, NULL, 10);

  // algo

  const u8 *algorithm_pos = token.buf[3];

  keepass->algorithm = hc_strtoul ((const char *) algorithm_pos, NULL, 10);

  // final_random_seed_pos

  const u8 *final_random_seed_pos = token.buf[4];

  keepass->final_random_seed[0] = hex_to_u32 ((const u8 *) &final_random_seed_pos[ 0]);
  keepass->final_random_seed[1] = hex_to_u32 ((const u8 *) &final_random_seed_pos[ 8]);
  keepass->final_random_seed[2] = hex_to_u32 ((const u8 *) &final_random_seed_pos[16]);
  keepass->final_random_seed[3] = hex_to_u32 ((const u8 *) &final_random_seed_pos[24]);

  keepass->final_random_seed[0] = byte_swap_32 (keepass->final_random_seed[0]);
  keepass->final_random_seed[1] = byte_swap_32 (keepass->final_random_seed[1]);
  keepass->final_random_seed[2] = byte_swap_32 (keepass->final_random_seed[2]);
  keepass->final_random_seed[3] = byte_swap_32 (keepass->final_random_seed[3]);

  if (keepass->version == 2)
  {
    keepass->final_random_seed[4] = hex_to_u32 ((const u8 *) &final_random_seed_pos[32]);
    keepass->final_random_seed[5] = hex_to_u32 ((const u8 *) &final_random_seed_pos[40]);
    keepass->final_random_seed[6] = hex_to_u32 ((const u8 *) &final_random_seed_pos[48]);
    keepass->final_random_seed[7] = hex_to_u32 ((const u8 *) &final_random_seed_pos[56]);

    keepass->final_random_seed[4] = byte_swap_32 (keepass->final_random_seed[4]);
    keepass->final_random_seed[5] = byte_swap_32 (keepass->final_random_seed[5]);
    keepass->final_random_seed[6] = byte_swap_32 (keepass->final_random_seed[6]);
    keepass->final_random_seed[7] = byte_swap_32 (keepass->final_random_seed[7]);
  }

  // transf_random_seed_pos

  const u8 *transf_random_seed_pos = token.buf[5];

  keepass->transf_random_seed[0] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[ 0]);
  keepass->transf_random_seed[1] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[ 8]);
  keepass->transf_random_seed[2] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[16]);
  keepass->transf_random_seed[3] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[24]);
  keepass->transf_random_seed[4] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[32]);
  keepass->transf_random_seed[5] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[40]);
  keepass->transf_random_seed[6] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[48]);
  keepass->transf_random_seed[7] = hex_to_u32 ((const u8 *) &transf_random_seed_pos[56]);

  keepass->transf_random_seed[0] = byte_swap_32 (keepass->transf_random_seed[0]);
  keepass->transf_random_seed[1] = byte_swap_32 (keepass->transf_random_seed[1]);
  keepass->transf_random_seed[2] = byte_swap_32 (keepass->transf_random_seed[2]);
  keepass->transf_random_seed[3] = byte_swap_32 (keepass->transf_random_seed[3]);
  keepass->transf_random_seed[4] = byte_swap_32 (keepass->transf_random_seed[4]);
  keepass->transf_random_seed[5] = byte_swap_32 (keepass->transf_random_seed[5]);
  keepass->transf_random_seed[6] = byte_swap_32 (keepass->transf_random_seed[6]);
  keepass->transf_random_seed[7] = byte_swap_32 (keepass->transf_random_seed[7]);

  // enc_iv_pos

  const u8 *enc_iv_pos = token.buf[6];

  keepass->enc_iv[0] = hex_to_u32 ((const u8 *) &enc_iv_pos[ 0]);
  keepass->enc_iv[1] = hex_to_u32 ((const u8 *) &enc_iv_pos[ 8]);
  keepass->enc_iv[2] = hex_to_u32 ((const u8 *) &enc_iv_pos[16]);
  keepass->enc_iv[3] = hex_to_u32 ((const u8 *) &enc_iv_pos[24]);

  keepass->enc_iv[0] = byte_swap_32 (keepass->enc_iv[0]);
  keepass->enc_iv[1] = byte_swap_32 (keepass->enc_iv[1]);
  keepass->enc_iv[2] = byte_swap_32 (keepass->enc_iv[2]);
  keepass->enc_iv[3] = byte_swap_32 (keepass->enc_iv[3]);

  const u8 *keyfile_pos = NULL;

  if (keepass->version == 1)
  {
    // contents_hash

    const u8 *contents_hash_pos = token.buf[7];

    keepass->contents_hash[0] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 0]);
    keepass->contents_hash[1] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 8]);
    keepass->contents_hash[2] = hex_to_u32 ((const u8 *) &contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32 ((const u8 *) &contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32 ((const u8 *) &contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32 ((const u8 *) &contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32 ((const u8 *) &contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32 ((const u8 *) &contents_hash_pos[56]);

    keepass->contents_hash[0] = byte_swap_32 (keepass->contents_hash[0]);
    keepass->contents_hash[1] = byte_swap_32 (keepass->contents_hash[1]);
    keepass->contents_hash[2] = byte_swap_32 (keepass->contents_hash[2]);
    keepass->contents_hash[3] = byte_swap_32 (keepass->contents_hash[3]);
    keepass->contents_hash[4] = byte_swap_32 (keepass->contents_hash[4]);
    keepass->contents_hash[5] = byte_swap_32 (keepass->contents_hash[5]);
    keepass->contents_hash[6] = byte_swap_32 (keepass->contents_hash[6]);
    keepass->contents_hash[7] = byte_swap_32 (keepass->contents_hash[7]);

    // contents

    const u8 *contents_pos = token.buf[10];
    const int contents_len = token.len[10];

    keepass->contents_len = contents_len / 2;

    for (int i = 0, j = 0; j < contents_len; i += 1, j += 8)
    {
      keepass->contents[i] = hex_to_u32 ((const u8 *) &contents_pos[j]);

      keepass->contents[i] = byte_swap_32 (keepass->contents[i]);
    }

    if (is_keyfile_present == true)
    {
      keyfile_pos = token.buf[13];
    }
  }
  else if (keepass->version == 2)
  {
    // expected_bytes

    const u8 *expected_bytes_pos = token.buf[7];

    keepass->expected_bytes[0] = hex_to_u32 ((const u8 *) &expected_bytes_pos[ 0]);
    keepass->expected_bytes[1] = hex_to_u32 ((const u8 *) &expected_bytes_pos[ 8]);
    keepass->expected_bytes[2] = hex_to_u32 ((const u8 *) &expected_bytes_pos[16]);
    keepass->expected_bytes[3] = hex_to_u32 ((const u8 *) &expected_bytes_pos[24]);
    keepass->expected_bytes[4] = hex_to_u32 ((const u8 *) &expected_bytes_pos[32]);
    keepass->expected_bytes[5] = hex_to_u32 ((const u8 *) &expected_bytes_pos[40]);
    keepass->expected_bytes[6] = hex_to_u32 ((const u8 *) &expected_bytes_pos[48]);
    keepass->expected_bytes[7] = hex_to_u32 ((const u8 *) &expected_bytes_pos[56]);

    keepass->expected_bytes[0] = byte_swap_32 (keepass->expected_bytes[0]);
    keepass->expected_bytes[1] = byte_swap_32 (keepass->expected_bytes[1]);
    keepass->expected_bytes[2] = byte_swap_32 (keepass->expected_bytes[2]);
    keepass->expected_bytes[3] = byte_swap_32 (keepass->expected_bytes[3]);
    keepass->expected_bytes[4] = byte_swap_32 (keepass->expected_bytes[4]);
    keepass->expected_bytes[5] = byte_swap_32 (keepass->expected_bytes[5]);
    keepass->expected_bytes[6] = byte_swap_32 (keepass->expected_bytes[6]);
    keepass->expected_bytes[7] = byte_swap_32 (keepass->expected_bytes[7]);

    // contents_hash

    const u8 *contents_hash_pos = token.buf[8];

    keepass->contents_hash[0] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 0]);
    keepass->contents_hash[1] = hex_to_u32 ((const u8 *) &contents_hash_pos[ 8]);
    keepass->contents_hash[2] = hex_to_u32 ((const u8 *) &contents_hash_pos[16]);
    keepass->contents_hash[3] = hex_to_u32 ((const u8 *) &contents_hash_pos[24]);
    keepass->contents_hash[4] = hex_to_u32 ((const u8 *) &contents_hash_pos[32]);
    keepass->contents_hash[5] = hex_to_u32 ((const u8 *) &contents_hash_pos[40]);
    keepass->contents_hash[6] = hex_to_u32 ((const u8 *) &contents_hash_pos[48]);
    keepass->contents_hash[7] = hex_to_u32 ((const u8 *) &contents_hash_pos[56]);

    keepass->contents_hash[0] = byte_swap_32 (keepass->contents_hash[0]);
    keepass->contents_hash[1] = byte_swap_32 (keepass->contents_hash[1]);
    keepass->contents_hash[2] = byte_swap_32 (keepass->contents_hash[2]);
    keepass->contents_hash[3] = byte_swap_32 (keepass->contents_hash[3]);
    keepass->contents_hash[4] = byte_swap_32 (keepass->contents_hash[4]);
    keepass->contents_hash[5] = byte_swap_32 (keepass->contents_hash[5]);
    keepass->contents_hash[6] = byte_swap_32 (keepass->contents_hash[6]);
    keepass->contents_hash[7] = byte_swap_32 (keepass->contents_hash[7]);

    if (is_keyfile_present == true)
    {
      keyfile_pos = token.buf[11];
    }
  }

  if (is_keyfile_present == true)
  {
    keepass->keyfile_len = 32;

    keepass->keyfile[0] = hex_to_u32 ((const u8 *) &keyfile_pos[ 0]);
    keepass->keyfile[1] = hex_to_u32 ((const u8 *) &keyfile_pos[ 8]);
    keepass->keyfile[2] = hex_to_u32 ((const u8 *) &keyfile_pos[16]);
    keepass->keyfile[3] = hex_to_u32 ((const u8 *) &keyfile_pos[24]);
    keepass->keyfile[4] = hex_to_u32 ((const u8 *) &keyfile_pos[32]);
    keepass->keyfile[5] = hex_to_u32 ((const u8 *) &keyfile_pos[40]);
    keepass->keyfile[6] = hex_to_u32 ((const u8 *) &keyfile_pos[48]);
    keepass->keyfile[7] = hex_to_u32 ((const u8 *) &keyfile_pos[56]);

    keepass->keyfile[0] = byte_swap_32 (keepass->keyfile[0]);
    keepass->keyfile[1] = byte_swap_32 (keepass->keyfile[1]);
    keepass->keyfile[2] = byte_swap_32 (keepass->keyfile[2]);
    keepass->keyfile[3] = byte_swap_32 (keepass->keyfile[3]);
    keepass->keyfile[4] = byte_swap_32 (keepass->keyfile[4]);
    keepass->keyfile[5] = byte_swap_32 (keepass->keyfile[5]);
    keepass->keyfile[6] = byte_swap_32 (keepass->keyfile[6]);
    keepass->keyfile[7] = byte_swap_32 (keepass->keyfile[7]);
  }

  if (keepass->version == 1)
  {
    digest[0] = keepass->contents_hash[0];
    digest[1] = keepass->contents_hash[1];
    digest[2] = keepass->contents_hash[2];
    digest[3] = keepass->contents_hash[3];
  }
  else
  {
    digest[0] = keepass->expected_bytes[0];
    digest[1] = keepass->expected_bytes[1];
    digest[2] = keepass->expected_bytes[2];
    digest[3] = keepass->expected_bytes[3];
  }

  salt->salt_buf[0] = keepass->transf_random_seed[0];
  salt->salt_buf[1] = keepass->transf_random_seed[1];
  salt->salt_buf[2] = keepass->transf_random_seed[2];
  salt->salt_buf[3] = keepass->transf_random_seed[3];
  salt->salt_buf[4] = keepass->transf_random_seed[4];
  salt->salt_buf[5] = keepass->transf_random_seed[5];
  salt->salt_buf[6] = keepass->transf_random_seed[6];
  salt->salt_buf[7] = keepass->transf_random_seed[7];

  salt->salt_len = 32;

  return (PARSER_OK);
}

int mywallet_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MYWALLET;

  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 64;
  token.len_max[2] = 65536;
  token.sep[2]     = '$';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * salt
   */

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is actually the CT, which is also the hash later (if matched)

  salt->salt_buf[4] = hex_to_u32 (salt_pos + 32);
  salt->salt_buf[5] = hex_to_u32 (salt_pos + 40);
  salt->salt_buf[6] = hex_to_u32 (salt_pos + 48);
  salt->salt_buf[7] = hex_to_u32 (salt_pos + 56);

  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);
  salt->salt_buf[6] = byte_swap_32 (salt->salt_buf[6]);
  salt->salt_buf[7] = byte_swap_32 (salt->salt_buf[7]);

  salt->salt_len = 32; // note we need to fix this to 16 in kernel

  salt->salt_iter = ROUNDS_MYWALLET - 1;

  /**
   * digest buf
   */

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int mywalletv2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MYWALLETV2;

  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 5;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 64;
  token.len_max[3] = 20000;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *data_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 ((const u8 *) &data_pos[ 0]);
  salt->salt_buf[1] = hex_to_u32 ((const u8 *) &data_pos[ 8]);
  salt->salt_buf[2] = hex_to_u32 ((const u8 *) &data_pos[16]);
  salt->salt_buf[3] = hex_to_u32 ((const u8 *) &data_pos[24]);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  // this is actually the CT, which is also the hash later (if matched)

  salt->salt_buf[4] = hex_to_u32 ((const u8 *) &data_pos[32]);
  salt->salt_buf[5] = hex_to_u32 ((const u8 *) &data_pos[40]);
  salt->salt_buf[6] = hex_to_u32 ((const u8 *) &data_pos[48]);
  salt->salt_buf[7] = hex_to_u32 ((const u8 *) &data_pos[56]);

  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);
  salt->salt_buf[6] = byte_swap_32 (salt->salt_buf[6]);
  salt->salt_buf[7] = byte_swap_32 (salt->salt_buf[7]);

  salt->salt_len = 32; // note we need to fix this to 16 in kernel

  // hash

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int ms_drsr_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MS_DRSR;

  token.len_min[0] = 11;
  token.len_max[0] = 11;
  token.sep[0]     = ',';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 20;
  token.len_max[1] = 20;
  token.sep[1]     = ',';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.sep[2]     = ',';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 64;
  token.len_max[3] = 64;
  token.sep[3]     = ',';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16) & 0x0000ffff;
  salt->salt_buf[3] = 0;

  salt->salt_len = salt_len / 2;

  // iter

  const u8 *iter_pos = token.buf[2];

  salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10) - 1ul;

  // hash

  const u8 *hash_pos = token.buf[3];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int androidfde_samsung_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 3;

  token.len[0]  = 64;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]  = 64;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]  = 32;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * salt
   */

  const u8 *salt1_pos = token.buf[2];
  const u8 *salt2_pos = token.buf[0];

  salt->salt_buf[ 0] = hex_to_u32 (salt1_pos +  0);
  salt->salt_buf[ 1] = hex_to_u32 (salt1_pos +  8);
  salt->salt_buf[ 2] = hex_to_u32 (salt1_pos + 16);
  salt->salt_buf[ 3] = hex_to_u32 (salt1_pos + 24);
  salt->salt_buf[ 4] = hex_to_u32 (salt2_pos +  0);
  salt->salt_buf[ 5] = hex_to_u32 (salt2_pos +  8);
  salt->salt_buf[ 6] = hex_to_u32 (salt2_pos + 16);
  salt->salt_buf[ 7] = hex_to_u32 (salt2_pos + 24);
  salt->salt_buf[ 8] = hex_to_u32 (salt2_pos + 32);
  salt->salt_buf[ 9] = hex_to_u32 (salt2_pos + 40);
  salt->salt_buf[10] = hex_to_u32 (salt2_pos + 48);
  salt->salt_buf[11] = hex_to_u32 (salt2_pos + 56);

  salt->salt_buf[ 0] = byte_swap_32 (salt->salt_buf[ 0]);
  salt->salt_buf[ 1] = byte_swap_32 (salt->salt_buf[ 1]);
  salt->salt_buf[ 2] = byte_swap_32 (salt->salt_buf[ 2]);
  salt->salt_buf[ 3] = byte_swap_32 (salt->salt_buf[ 3]);
  salt->salt_buf[ 4] = byte_swap_32 (salt->salt_buf[ 4]);
  salt->salt_buf[ 5] = byte_swap_32 (salt->salt_buf[ 5]);
  salt->salt_buf[ 6] = byte_swap_32 (salt->salt_buf[ 6]);
  salt->salt_buf[ 7] = byte_swap_32 (salt->salt_buf[ 7]);
  salt->salt_buf[ 8] = byte_swap_32 (salt->salt_buf[ 8]);
  salt->salt_buf[ 9] = byte_swap_32 (salt->salt_buf[ 9]);
  salt->salt_buf[10] = byte_swap_32 (salt->salt_buf[10]);
  salt->salt_buf[11] = byte_swap_32 (salt->salt_buf[11]);

  salt->salt_len = 48;

  salt->salt_iter = ROUNDS_ANDROIDFDE_SAMSUNG - 1;

  /**
   * digest buf
   */

  const u8 *hash_pos  = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int zip2_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  zip2_t *zip2 = (zip2_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 10;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_ZIP2_START;
  token.signatures_buf[1] = SIGNATURE_ZIP2_STOP;

  token.len_min[0] = 6;
  token.len_max[0] = 6;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 1;
  token.len_max[3] = 1;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 16;
  token.len_max[4] = 32;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[5] = 1;
  token.len_max[5] = 6;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[6] = 1;
  token.len_max[6] = 6;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[7] = 0;
  token.len_max[7] = 16384;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[8] = 20;
  token.len_max[8] = 20;
  token.sep[8]     = '*';
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[9] = 7;
  token.len_max[9] = 7;
  token.sep[9]     = '*';
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_pos = token.buf[1];

  const u32 type = hc_strtoul ((const char *) type_pos, NULL, 10);

  if (type != 0) return (PARSER_SALT_VALUE);

  zip2->type = type;

  // mode

  const u8 *mode_pos = token.buf[2];

  const u32 mode = hc_strtoul ((const char *) mode_pos, NULL, 10);

  zip2->mode = mode;

  // magic

  const u8 *magic_pos = token.buf[3];

  const u32 magic = hc_strtoul ((const char *) magic_pos, NULL, 10);

  if (magic != 0) return (PARSER_SALT_VALUE);

  zip2->magic = magic;

  // verify_bytes

  const u8 *verify_bytes_pos = token.buf[5];

  u32 verify_bytes;

  if (sscanf ((const char *) verify_bytes_pos, "%4x*", &verify_bytes) == EOF)
  {
    return (PARSER_SALT_VALUE);
  }

  if (verify_bytes >= 0x10000) return (PARSER_SALT_VALUE);

  zip2->verify_bytes = verify_bytes;

  // compress_length

  const u8 *compress_length_pos = token.buf[6];

  const u32 compress_length = hc_strtoul ((const char *) compress_length_pos, NULL, 10);

  zip2->compress_length = compress_length;

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  if (mode == 1)
  {
    if (salt_len != 16) return (PARSER_SALT_VALUE);

    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
    zip2->salt_buf[2] = 0;
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 8;
  }
  else if (mode == 2)
  {
    if (salt_len != 24) return (PARSER_SALT_VALUE);

    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
    zip2->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
    zip2->salt_buf[3] = 0;

    zip2->salt_len = 12;
  }
  else if (mode == 3)
  {
    if (salt_len != 32) return (PARSER_SALT_VALUE);

    zip2->salt_buf[0] = hex_to_u32 ((const u8 *) &salt_pos[ 0]);
    zip2->salt_buf[1] = hex_to_u32 ((const u8 *) &salt_pos[ 8]);
    zip2->salt_buf[2] = hex_to_u32 ((const u8 *) &salt_pos[16]);
    zip2->salt_buf[3] = hex_to_u32 ((const u8 *) &salt_pos[24]);

    zip2->salt_len = 16;
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  // data

  const u8 *data_buf = token.buf[7];
  const int data_len = token.len[7];

  u8 *data_buf_ptr = (u8 *) zip2->data_buf;

  for (int i = 0; i < data_len; i += 2)
  {
    const u8 p0 = data_buf[i + 0];
    const u8 p1 = data_buf[i + 1];

    *data_buf_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;

    zip2->data_len++;
  }

  *data_buf_ptr = 0x80;

  // auth

  const u8 *auth_buf = token.buf[8];
  const int auth_len = token.len[8];

  u8 *auth_ptr = (u8 *) zip2->auth_buf;

  for (int i = 0; i < auth_len; i += 2)
  {
    const u8 p0 = auth_buf[i + 0];
    const u8 p1 = auth_buf[i + 1];

    *auth_ptr++ = hex_convert (p1) << 0
                | hex_convert (p0) << 4;

    zip2->auth_len++;
  }

  /**
   * salt buf (fake)
   */

  salt->salt_buf[0] = zip2->salt_buf[0];
  salt->salt_buf[1] = zip2->salt_buf[1];
  salt->salt_buf[2] = zip2->salt_buf[2];
  salt->salt_buf[3] = zip2->salt_buf[3];
  salt->salt_buf[4] = zip2->data_buf[0];
  salt->salt_buf[5] = zip2->data_buf[1];
  salt->salt_buf[6] = zip2->data_buf[2];
  salt->salt_buf[7] = zip2->data_buf[3];

  salt->salt_len = 32;

  salt->salt_iter = ROUNDS_ZIP2 - 1;

  /**
   * digest buf (fake)
   */

  digest[0] = zip2->auth_buf[0];
  digest[1] = zip2->auth_buf[1];
  digest[2] = zip2->auth_buf[2];
  digest[3] = zip2->auth_buf[3];

  return (PARSER_OK);
}

int win8phone_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  win8phone_t *esalt = (win8phone_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 2;

  token.len_min[0] = 64;
  token.len_max[0] = 64;
  token.sep[0]     = hashconfig->separator;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 256;
  token.len_max[1] = 256;
  token.sep[1]     = hashconfig->separator;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  // salt

  const u8 *salt_pos = token.buf[1];

  u32 *salt_buf = esalt->salt_buf;

  for (int i = 0, j = 0; i < 32; i += 1, j += 8)
  {
    salt_buf[i] = hex_to_u32 (salt_pos + j);

    salt_buf[i] = byte_swap_32 (salt_buf[i]);
  }

  salt->salt_buf[0] = salt_buf[0];
  salt->salt_buf[1] = salt_buf[1];
  salt->salt_buf[2] = salt_buf[2];
  salt->salt_buf[3] = salt_buf[3];
  salt->salt_buf[4] = salt_buf[4];
  salt->salt_buf[5] = salt_buf[5];
  salt->salt_buf[6] = salt_buf[6];
  salt->salt_buf[7] = salt_buf[7];

  salt->salt_len = 32;

  return (PARSER_OK);
}

int plaintext_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 1;
  token.len_max[0] = 55;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  memset (digest, 0, hashconfig->dgst_size);

  const u8 *pw_buf = token.buf[0];
  const int pw_len = token.len[0];

  memcpy ((char *) digest + 64, pw_buf, pw_len);

  //strncpy ((char *) digest + 64, (char *) input_buf, 64);

  u32 w[16] = { 0 };

  //strncpy ((char *) w, (char *) input_buf, 64);

  memcpy (w, pw_buf, pw_len);

  u8 *w_ptr = (u8 *) w;

  w_ptr[input_len] = 0x80;

  w[14] = input_len * 8;

  u32 dgst[4];

  dgst[0] = MD4M_A;
  dgst[1] = MD4M_B;
  dgst[2] = MD4M_C;
  dgst[3] = MD4M_D;

  md4_64 (w, dgst);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    dgst[0] -= MD4M_A;
    dgst[1] -= MD4M_B;
    dgst[2] -= MD4M_C;
    dgst[3] -= MD4M_D;
  }

  digest[0] = dgst[0];
  digest[1] = dgst[1];
  digest[2] = dgst[2];
  digest[3] = dgst[3];

  return (PARSER_OK);
}

int sha1cx_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 40;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 20;
  token.len_max[1] = 20;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int itunes_backup_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 hash_mode = hashconfig->hash_mode;

  salt_t *salt = hash_buf->salt;

  itunes_backup_t *itunes_backup = (itunes_backup_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ITUNES_BACKUP;

  token.len_min[0] = 15;
  token.len_max[0] = 15;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 80;
  token.len_max[2] = 80;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 40;
  token.len_max[4] = 40;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[5] = 0;
  token.len_max[5] = 10;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[6] = 0;
  token.len_max[6] = 40;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  u32 version = hc_strtoul ((const char *) version_pos, NULL, 10);

  if (hash_mode == 14700)
  {
    if (version != 9) return (PARSER_SEPARATOR_UNMATCHED);
  }
  else if (hash_mode == 14800)
  {
    if (version != 10) return (PARSER_SEPARATOR_UNMATCHED);
  }

  salt->salt_sign[0] = (char) version;

  // wpky

  const u8 *wpky_pos = token.buf[2];

  u32 *wpky_buf_ptr = (u32 *) itunes_backup->wpky;

  wpky_buf_ptr[0] = hex_to_u32 ((const u8 *) &wpky_pos[ 0]);
  wpky_buf_ptr[1] = hex_to_u32 ((const u8 *) &wpky_pos[ 8]);
  wpky_buf_ptr[2] = hex_to_u32 ((const u8 *) &wpky_pos[16]);
  wpky_buf_ptr[3] = hex_to_u32 ((const u8 *) &wpky_pos[24]);
  wpky_buf_ptr[4] = hex_to_u32 ((const u8 *) &wpky_pos[32]);
  wpky_buf_ptr[5] = hex_to_u32 ((const u8 *) &wpky_pos[40]);
  wpky_buf_ptr[6] = hex_to_u32 ((const u8 *) &wpky_pos[48]);
  wpky_buf_ptr[7] = hex_to_u32 ((const u8 *) &wpky_pos[56]);
  wpky_buf_ptr[8] = hex_to_u32 ((const u8 *) &wpky_pos[64]);
  wpky_buf_ptr[9] = hex_to_u32 ((const u8 *) &wpky_pos[72]);

  wpky_buf_ptr[0] = byte_swap_32 (wpky_buf_ptr[0]);
  wpky_buf_ptr[1] = byte_swap_32 (wpky_buf_ptr[1]);
  wpky_buf_ptr[2] = byte_swap_32 (wpky_buf_ptr[2]);
  wpky_buf_ptr[3] = byte_swap_32 (wpky_buf_ptr[3]);
  wpky_buf_ptr[4] = byte_swap_32 (wpky_buf_ptr[4]);
  wpky_buf_ptr[5] = byte_swap_32 (wpky_buf_ptr[5]);
  wpky_buf_ptr[6] = byte_swap_32 (wpky_buf_ptr[6]);
  wpky_buf_ptr[7] = byte_swap_32 (wpky_buf_ptr[7]);
  wpky_buf_ptr[8] = byte_swap_32 (wpky_buf_ptr[8]);
  wpky_buf_ptr[9] = byte_swap_32 (wpky_buf_ptr[9]);

  // iter

  const u8 *iter_pos = token.buf[3];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  if (hash_mode == 14700)
  {
    salt->salt_iter  = iter - 1;
  }
  else if (hash_mode == 14800)
  {
    salt->salt_iter  = 0; // set later
    salt->salt_iter2 = iter - 1;
  }

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, salt_pos, salt_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // dpic + dpsl

  const u8 *dpic_pos = token.buf[5];
  const int dpic_len = token.len[5];

  const u8 *dpsl_pos = token.buf[6];
  const int dpsl_len = token.len[6];

  u32 dpic = 0;

  if (hash_mode == 14700)
  {
    if (dpic_len > 0) return (PARSER_SEPARATOR_UNMATCHED);
    if (dpsl_len > 0) return (PARSER_SEPARATOR_UNMATCHED);
  }
  else if (hash_mode == 14800)
  {
    if (dpic_len < 1) return (PARSER_SALT_ITERATION);
    if (dpic_len > 9) return (PARSER_SALT_ITERATION);

    dpic = hc_strtoul ((const char *) dpic_pos, NULL, 10);

    if (dpic < 1) return (PARSER_SALT_ITERATION);

    salt->salt_iter = dpic - 1;

    if (dpsl_len != 40) return (PARSER_SEPARATOR_UNMATCHED);

    u32 *dpsl_buf_ptr = (u32 *) itunes_backup->dpsl;

    dpsl_buf_ptr[0] = hex_to_u32 ((const u8 *) &dpsl_pos[ 0]);
    dpsl_buf_ptr[1] = hex_to_u32 ((const u8 *) &dpsl_pos[ 8]);
    dpsl_buf_ptr[2] = hex_to_u32 ((const u8 *) &dpsl_pos[16]);
    dpsl_buf_ptr[3] = hex_to_u32 ((const u8 *) &dpsl_pos[24]);
    dpsl_buf_ptr[4] = hex_to_u32 ((const u8 *) &dpsl_pos[32]);

    dpsl_buf_ptr[0] = byte_swap_32 (dpsl_buf_ptr[ 0]);
    dpsl_buf_ptr[1] = byte_swap_32 (dpsl_buf_ptr[ 1]);
    dpsl_buf_ptr[2] = byte_swap_32 (dpsl_buf_ptr[ 2]);
    dpsl_buf_ptr[3] = byte_swap_32 (dpsl_buf_ptr[ 3]);
    dpsl_buf_ptr[4] = byte_swap_32 (dpsl_buf_ptr[ 4]);
  }

  return (PARSER_OK);
}

int fortigate_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_FORTIGATE;

  token.len[0]  = 3;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 44;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * verify data
   */

  const u8 *hash_pos = token.buf[1];
  const int hash_len = token.len[1];

  // decode salt + SHA1 hash (12 + 20 = 32)

  u8 tmp_buf[100] = { 0 };

  const int decoded_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (decoded_len != 32) return (PARSER_HASH_LENGTH);

  /**
   * store data
   */

  // salt

  u32 salt_len = 12;

  memcpy (salt->salt_buf, tmp_buf, salt_len);

  salt->salt_len = salt_len;

  // digest

  memcpy (digest, tmp_buf + salt_len, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  return (PARSER_OK);
}

int sha256b64s_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SHA256B64S;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 44;
  token.len_max[1] = 385; // 385 = 32 + 256 where 32 is digest length and 256 is SALT_MAX
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashsalt_pos = token.buf[1];
  const int hashsalt_len = token.len[1];

  u8 tmp_buf[512] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, hashsalt_pos, hashsalt_len, tmp_buf);

  if (tmp_len < 32) return (PARSER_HASH_LENGTH);

  u8 *hash_pos = tmp_buf;

  memcpy (digest, hash_pos, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_PRECOMPUTE_MERKLE)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  // salt

  u8 *salt_pos = tmp_buf + 32;
  int salt_len = tmp_len - 32;

  salt->salt_len = salt_len;

  memcpy (salt->salt_buf, salt_pos, salt_len);

  if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
  {
    u8 *ptr = (u8 *) salt->salt_buf;

    ptr[salt_len] = 0x80;
  }

  return (PARSER_OK);
}

int netbsd_sha1crypt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_NETBSD_SHA1CRYPT;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 8;
  token.len_max[2] = 8;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]     = '$';
  token.len_min[3] = 28;
  token.len_max[3] = 28;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 99) return (PARSER_SALT_ITERATION); // (actually: CRYPT_SHA1_ITERATIONS should be 24680 or more)

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memcpy ((u8 *) salt->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  // hash

  const u8 *hash_pos = token.buf[3];

  netbsd_sha1crypt_decode ((u8 *) digest, hash_pos, (u8 *) salt->salt_sign);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // precompute salt

  char *ptr = (char *) salt->salt_buf_pc;

  const int salt_len_pc = snprintf (ptr, 64, "%s$sha1$%u", (char *) salt->salt_buf, iter);

  ptr[salt_len_pc] = 0x80;

  salt->salt_len_pc = salt_len_pc;

  return (PARSER_OK);
}

int atlassian_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  pbkdf2_sha1_t *pbkdf2_sha1 = (pbkdf2_sha1_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ATLASSIAN;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 64;
  token.len_max[1] = 64;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hashsalt_pos = token.buf[1];
  const int hashsalt_len = token.len[1];

  u8 tmp_buf[100] = { 0 };

  const int base64_decode_len = base64_decode (base64_to_int, hashsalt_pos, hashsalt_len, tmp_buf);

  if (base64_decode_len != (16 + 32)) return (PARSER_HASH_LENGTH);

  u8 *hash_pos = tmp_buf + 16;

  memcpy (digest, hash_pos, 16);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // store salt

  u8 *salt_pos = tmp_buf;
  int salt_len = 16;

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha1->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len  = salt_len;
  salt->salt_iter = ROUNDS_ATLASSIAN - 1;

  // add some stuff to normal salt to make sorted happy

  salt->salt_buf[0] = pbkdf2_sha1->salt_buf[0];
  salt->salt_buf[1] = pbkdf2_sha1->salt_buf[1];
  salt->salt_buf[2] = pbkdf2_sha1->salt_buf[2];
  salt->salt_buf[3] = pbkdf2_sha1->salt_buf[3];
  salt->salt_buf[4] = salt->salt_iter;

  return (PARSER_OK);
}

int jks_sha1_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  jks_sha1_t *jks_sha1 = (jks_sha1_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_JKS_SHA1;

  token.sep[0]     = '*';
  token.len_min[0] = 10;
  token.len_max[0] = 10;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 40;
  token.len_max[1] = 40;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 2;
  token.len_max[3] = 16384;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 2;
  token.len_max[4] = 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len_min[5] = 28;
  token.len_max[5] = 28;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len_min[6] = 0;
  token.len_max[6] = 64;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // checksum

  const u8 *checksum_pos = token.buf[1];

  jks_sha1->checksum[0] = hex_to_u32 ((const u8 *) &checksum_pos[ 0]);
  jks_sha1->checksum[1] = hex_to_u32 ((const u8 *) &checksum_pos[ 8]);
  jks_sha1->checksum[2] = hex_to_u32 ((const u8 *) &checksum_pos[16]);
  jks_sha1->checksum[3] = hex_to_u32 ((const u8 *) &checksum_pos[24]);
  jks_sha1->checksum[4] = hex_to_u32 ((const u8 *) &checksum_pos[32]);

  // iv

  const u8 *iv_pos = token.buf[2];

  jks_sha1->iv[0] = hex_to_u32 ((const u8 *) &iv_pos[ 0]);
  jks_sha1->iv[1] = hex_to_u32 ((const u8 *) &iv_pos[ 8]);
  jks_sha1->iv[2] = hex_to_u32 ((const u8 *) &iv_pos[16]);
  jks_sha1->iv[3] = hex_to_u32 ((const u8 *) &iv_pos[24]);
  jks_sha1->iv[4] = hex_to_u32 ((const u8 *) &iv_pos[32]);

  // enc_key

  const u8 *enc_key_pos = token.buf[3];
  const int enc_key_len = token.len[3];

  u8 *enc_key_buf = (u8 *) jks_sha1->enc_key_buf;

  for (int i = 0, j = 0; j < enc_key_len; i += 1, j += 2)
  {
    enc_key_buf[i] = hex_to_u8 ((const u8 *) &enc_key_pos[j]);

    jks_sha1->enc_key_len++;
  }

  // der1

  const u8 *der1_pos = token.buf[4];

  u8 *der = (u8 *) jks_sha1->der;

  der[0] = hex_to_u8 ((const u8 *) &der1_pos[0]);

  // der2

  const u8 *der2_pos = token.buf[5];

  for (int i = 6, j = 0; j < 28; i += 1, j += 2)
  {
    der[i] = hex_to_u8 ((const u8 *) &der2_pos[j]);
  }

  der[1] = 0;
  der[2] = 0;
  der[3] = 0;
  der[4] = 0;
  der[5] = 0;

  // alias

  const u8 *alias_pos = token.buf[6];

  strncpy ((char *) jks_sha1->alias, (const char *) alias_pos, 64);

  // fake salt

  salt->salt_buf[0] = jks_sha1->iv[0];
  salt->salt_buf[1] = jks_sha1->iv[1];
  salt->salt_buf[2] = jks_sha1->iv[2];
  salt->salt_buf[3] = jks_sha1->iv[3];
  salt->salt_buf[4] = jks_sha1->iv[4];

  salt->salt_len = 20;

  // fake digest

  digest[0] = byte_swap_32 (jks_sha1->der[0]);
  digest[1] = byte_swap_32 (jks_sha1->der[1]);
  digest[2] = byte_swap_32 (jks_sha1->der[2]);
  digest[3] = byte_swap_32 (jks_sha1->der[3]);
  digest[4] = byte_swap_32 (jks_sha1->der[4]);

  return (PARSER_OK);
}

int tacacs_plus_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  tacacs_plus_t *tacacs_plus = (tacacs_plus_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TACACS_PLUS;

  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 8;
  token.len_max[1] = 8;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len_min[2] = 12;
  token.len_max[2] = 256;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len_min[3] = 4;
  token.len_max[3] = 4;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // session

  const u8 *session_pos = token.buf[1];

  u8 *session_ptr = (u8 *) tacacs_plus->session_buf;

  session_ptr[0] = hex_to_u8 ((const u8 *) session_pos + 0);
  session_ptr[1] = hex_to_u8 ((const u8 *) session_pos + 2);
  session_ptr[2] = hex_to_u8 ((const u8 *) session_pos + 4);
  session_ptr[3] = hex_to_u8 ((const u8 *) session_pos + 6);

  // ct_buf

  const u8 *ct_buf_pos = token.buf[2];
  const int ct_buf_len = token.len[2];

  u8 *ct_data_ptr = (u8 *) tacacs_plus->ct_data_buf;

  for (int i = 0, j = 0; j < ct_buf_len; i += 1, j += 2)
  {
    ct_data_ptr[i] = hex_to_u8 ((const u8 *) &ct_buf_pos[j]);

    tacacs_plus->ct_data_len++;
  }

  // sequence

  const u8 *sequence_pos = token.buf[3];

  u8 *sequence_ptr = (u8 *) tacacs_plus->sequence_buf;

  sequence_ptr[0] = hex_to_u8 ((const u8 *) sequence_pos + 0);
  sequence_ptr[1] = hex_to_u8 ((const u8 *) sequence_pos + 2);

  // fake salt

  salt->salt_buf[0] = tacacs_plus->session_buf[0];
  salt->salt_buf[1] = tacacs_plus->sequence_buf[0];
  salt->salt_buf[2] = tacacs_plus->ct_data_buf[0];
  salt->salt_buf[3] = tacacs_plus->ct_data_buf[1];

  salt->salt_len = 16;

  // fake hash

  digest[0] = tacacs_plus->ct_data_buf[2];
  digest[1] = tacacs_plus->ct_data_buf[3];
  digest[2] = tacacs_plus->ct_data_buf[4];
  digest[3] = tacacs_plus->ct_data_buf[5];

  return (PARSER_OK);
}

int apple_secure_notes_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  apple_secure_notes_t *apple_secure_notes = (apple_secure_notes_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_APPLE_SECURE_NOTES;

  token.sep[0]     = '*';
  token.len_min[0] = 5;
  token.len_max[0] = 5;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 48;
  token.len_max[4] = 48;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * parse line
   */

  // Z_PK

  const u8 *Z_PK_pos = token.buf[1];

  const u32 Z_PK = hc_strtoul ((const char *) Z_PK_pos, NULL, 10);

  apple_secure_notes->Z_PK = Z_PK;

  // ZCRYPTOITERATIONCOUNT

  const u8 *ZCRYPTOITERATIONCOUNT_pos = token.buf[2];

  const u32 ZCRYPTOITERATIONCOUNT = hc_strtoul ((const char *) ZCRYPTOITERATIONCOUNT_pos, NULL, 10);

  apple_secure_notes->ZCRYPTOITERATIONCOUNT = ZCRYPTOITERATIONCOUNT;

  // ZCRYPTOSALT

  const u8 *ZCRYPTOSALT_pos = token.buf[3];

  apple_secure_notes->ZCRYPTOSALT[ 0] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[ 0]);
  apple_secure_notes->ZCRYPTOSALT[ 1] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[ 8]);
  apple_secure_notes->ZCRYPTOSALT[ 2] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[16]);
  apple_secure_notes->ZCRYPTOSALT[ 3] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[24]);
  apple_secure_notes->ZCRYPTOSALT[ 4] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 5] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 6] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 7] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 8] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 9] = 0;
  apple_secure_notes->ZCRYPTOSALT[10] = 0;
  apple_secure_notes->ZCRYPTOSALT[11] = 0;
  apple_secure_notes->ZCRYPTOSALT[12] = 0;
  apple_secure_notes->ZCRYPTOSALT[13] = 0;
  apple_secure_notes->ZCRYPTOSALT[14] = 0;
  apple_secure_notes->ZCRYPTOSALT[15] = 0;

  // ZCRYPTOWRAPPEDKEY

  const u8 *ZCRYPTOWRAPPEDKEY_pos = token.buf[4];

  apple_secure_notes->ZCRYPTOWRAPPEDKEY[0] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[ 0]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[1] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[ 8]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[2] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[16]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[3] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[24]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[4] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[32]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[5] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[40]);

  // fake salt

  salt->salt_buf[0] = apple_secure_notes->ZCRYPTOSALT[0];
  salt->salt_buf[1] = apple_secure_notes->ZCRYPTOSALT[1];
  salt->salt_buf[2] = apple_secure_notes->ZCRYPTOSALT[2];
  salt->salt_buf[3] = apple_secure_notes->ZCRYPTOSALT[3];
  salt->salt_buf[4] = apple_secure_notes->Z_PK;

  salt->salt_iter = apple_secure_notes->ZCRYPTOITERATIONCOUNT - 1;
  salt->salt_len  = 20;

  // fake hash

  digest[0] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[0];
  digest[1] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[1];
  digest[2] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[2];
  digest[3] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[3];

  return (PARSER_OK);
}

int ethereum_presale_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  ethereum_presale_t *ethereum_presale = (ethereum_presale_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ETHEREUM_PRESALE;

  token.sep[0]     = '*';
  token.len_min[0] = 11;
  token.len_max[0] = 11;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 64;
  token.len_max[1] = 1248;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // encseed

  const u8 *encseed_pos = token.buf[1];
  const int encseed_len = token.len[1];

  ethereum_presale->iv[0] = hex_to_u32 ((const u8 *) &encseed_pos[ 0]);
  ethereum_presale->iv[1] = hex_to_u32 ((const u8 *) &encseed_pos[ 8]);
  ethereum_presale->iv[2] = hex_to_u32 ((const u8 *) &encseed_pos[16]);
  ethereum_presale->iv[3] = hex_to_u32 ((const u8 *) &encseed_pos[24]);

  ethereum_presale->iv[0] = byte_swap_32 (ethereum_presale->iv[0]);
  ethereum_presale->iv[1] = byte_swap_32 (ethereum_presale->iv[1]);
  ethereum_presale->iv[2] = byte_swap_32 (ethereum_presale->iv[2]);
  ethereum_presale->iv[3] = byte_swap_32 (ethereum_presale->iv[3]);

  u32 *esalt_buf_ptr = ethereum_presale->enc_seed;

  for (int i = 32, j = 0; i < encseed_len; i += 8, j++)
  {
    esalt_buf_ptr[j] = hex_to_u32 ((const u8 *) &encseed_pos[i]);

    esalt_buf_ptr[j] = byte_swap_32 (esalt_buf_ptr[j]);
  }

  ethereum_presale->enc_seed_len = (encseed_len - 32) / 2; // encseed length without IV (raw bytes, not hex)

  // salt (address)

  const u8 *ethaddr_pos = token.buf[2];
  const int ethaddr_len = token.len[2];

  const bool parse_rc = parse_and_store_generic_salt ((u8 *) salt->salt_buf, (int *) &salt->salt_len, ethaddr_pos, ethaddr_len, hashconfig);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  salt->salt_iter = ROUNDS_ETHEREUM_PRESALE;

  // hash (bkp)

  const u8 *bkp_pos = token.buf[3];

  digest[0] = hex_to_u32 ((const u8 *) &bkp_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &bkp_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &bkp_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &bkp_pos[24]);

  return (PARSER_OK);
}

int jwt_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  // no digest yet

  salt_t *salt = hash_buf->salt;

  jwt_t *jwt = (jwt_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 3;

  token.sep[0]     = '.';
  token.len_min[0] = 1;
  token.len_max[0] = 2047;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64C;

  token.sep[1]     = '.';
  token.len_min[1] = 1;
  token.len_max[1] = 2047;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64C;

  token.sep[2]     = '.';
  token.len_min[2] = 43;
  token.len_max[2] = 86;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64C;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // header

  const int header_len = token.len[0];

  // payload

  const int payload_len = token.len[1];

  // signature

  const u8 *signature_pos = token.buf[2];
  const int signature_len = token.len[2];

  // esalt

  const int esalt_len = header_len + 1 + payload_len;

  if (esalt_len > 4096) return (PARSER_SALT_LENGTH);

  memcpy (jwt->salt_buf, input_buf, esalt_len);

  jwt->salt_len = esalt_len;

  /**
   * verify some data
   */

  // we need to do this kind of check, otherwise an eventual matching hash from the potfile overwrites the kern_type with an eventual invalid one

  if (hashconfig->kern_type == (u32) -1)
  {
      // it would be more accurate to base64 decode the header_pos buffer and then to string match HS256 - same goes for the other algorithms

    if (signature_len == 43)
    {
      hashconfig->kern_type = KERN_TYPE_JWT_HS256;
    }
    else if (signature_len == 64)
    {
      hashconfig->kern_type = KERN_TYPE_JWT_HS384;
    }
    else if (signature_len == 86)
    {
      hashconfig->kern_type = KERN_TYPE_JWT_HS512;
    }
    else
    {
      return (PARSER_HASH_LENGTH);
    }
  }
  else
  {
    if ((hashconfig->kern_type == KERN_TYPE_JWT_HS256) && (signature_len == 43))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_JWT_HS384) && (signature_len == 64))
    {
      // OK
    }
    else if ((hashconfig->kern_type == KERN_TYPE_JWT_HS512) && (signature_len == 86))
    {
      // OK
    }
    else
    {
      return (PARSER_HASH_LENGTH);
    }
  }

  // salt
  //
  // Create a hash of the esalt because esalt buffer can change somewhere behind salt->salt_buf size
  // Not a regular MD5 but good enough

  u32 hash[4];

  hash[0] = 0;
  hash[1] = 1;
  hash[2] = 2;
  hash[3] = 3;

  u32 block[16];

  memset (block, 0, sizeof (block));

  for (int i = 0; i < 1024; i += 16)
  {
    for (int j = 0; j < 16; j++)
    {
      block[j] = jwt->salt_buf[i + j];

      md5_64 (block, hash);
    }
  }

  salt->salt_buf[0] = hash[0];
  salt->salt_buf[1] = hash[1];
  salt->salt_buf[2] = hash[2];
  salt->salt_buf[3] = hash[3];

  salt->salt_len = 16;

  // hash

  u8 tmp_buf[100] = { 0 };

  base64_decode (base64url_to_int, signature_pos, signature_len, tmp_buf);

  if (signature_len == 43)
  {
    memcpy (hash_buf->digest, tmp_buf, 32);

    u32 *digest = (u32 *) hash_buf->digest;

    digest[0] = byte_swap_32 (digest[0]);
    digest[1] = byte_swap_32 (digest[1]);
    digest[2] = byte_swap_32 (digest[2]);
    digest[3] = byte_swap_32 (digest[3]);
    digest[4] = byte_swap_32 (digest[4]);
    digest[5] = byte_swap_32 (digest[5]);
    digest[6] = byte_swap_32 (digest[6]);
    digest[7] = byte_swap_32 (digest[7]);
  }
  else if (signature_len == 64)
  {
    memcpy (hash_buf->digest, tmp_buf, 48);

    u64 *digest = (u64 *) hash_buf->digest;

    digest[0] = byte_swap_64 (digest[0]);
    digest[1] = byte_swap_64 (digest[1]);
    digest[2] = byte_swap_64 (digest[2]);
    digest[3] = byte_swap_64 (digest[3]);
    digest[4] = byte_swap_64 (digest[4]);
    digest[5] = byte_swap_64 (digest[5]);
  }
  else if (signature_len == 86)
  {
    memcpy (hash_buf->digest, tmp_buf, 64);

    u64 *digest = (u64 *) hash_buf->digest;

    digest[0] = byte_swap_64 (digest[0]);
    digest[1] = byte_swap_64 (digest[1]);
    digest[2] = byte_swap_64 (digest[2]);
    digest[3] = byte_swap_64 (digest[3]);
    digest[4] = byte_swap_64 (digest[4]);
    digest[5] = byte_swap_64 (digest[5]);
    digest[6] = byte_swap_64 (digest[6]);
    digest[7] = byte_swap_64 (digest[7]);
  }

  return (PARSER_OK);
}

int electrum_wallet13_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig)
{
  u32 *digest = (u32 *) hash_buf->digest;

  salt_t *salt = hash_buf->salt;

  electrum_wallet_t *electrum_wallet = (electrum_wallet_t *) hash_buf->esalt;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ELECTRUM_WALLET;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 32;
  token.len_max[2] = 32;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer (input_buf, input_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt_type

  const u8 *salt_type_pos = token.buf[1];

  const u32 salt_type = hc_strtoul ((const char *) salt_type_pos, NULL, 10);

  if ((salt_type == 1) || (salt_type == 2))
  {
    // all ok
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  electrum_wallet->salt_type = salt_type;

  // iv

  const u8 *iv_pos = token.buf[2];

  electrum_wallet->iv[0] = hex_to_u32 ((const u8 *) &iv_pos[ 0]);
  electrum_wallet->iv[1] = hex_to_u32 ((const u8 *) &iv_pos[ 8]);
  electrum_wallet->iv[2] = hex_to_u32 ((const u8 *) &iv_pos[16]);
  electrum_wallet->iv[3] = hex_to_u32 ((const u8 *) &iv_pos[24]);

  // encrypted

  const u8 *encrypted_pos = token.buf[3];

  electrum_wallet->encrypted[0] = hex_to_u32 ((const u8 *) &encrypted_pos[ 0]);
  electrum_wallet->encrypted[1] = hex_to_u32 ((const u8 *) &encrypted_pos[ 8]);
  electrum_wallet->encrypted[2] = hex_to_u32 ((const u8 *) &encrypted_pos[16]);
  electrum_wallet->encrypted[3] = hex_to_u32 ((const u8 *) &encrypted_pos[24]);

  // salt fake

  salt->salt_buf[0] = electrum_wallet->iv[0];
  salt->salt_buf[1] = electrum_wallet->iv[1];
  salt->salt_buf[2] = electrum_wallet->iv[2];
  salt->salt_buf[3] = electrum_wallet->iv[3];
  salt->salt_buf[4] = electrum_wallet->encrypted[0];
  salt->salt_buf[5] = electrum_wallet->encrypted[1];
  salt->salt_buf[6] = electrum_wallet->encrypted[2];
  salt->salt_buf[7] = electrum_wallet->encrypted[3];

  salt->salt_len = 32;

  // hash fake

  digest[0] = electrum_wallet->iv[0];
  digest[1] = electrum_wallet->iv[1];
  digest[2] = electrum_wallet->iv[2];
  digest[3] = electrum_wallet->iv[3];
  digest[4] = electrum_wallet->encrypted[0];
  digest[5] = electrum_wallet->encrypted[1];
  digest[6] = electrum_wallet->encrypted[2];
  digest[7] = electrum_wallet->encrypted[3];

  return (PARSER_OK);
}

int ascii_digest (hashcat_ctx_t *hashcat_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos)
{
  if (hash_mode == 22)
  {
    char username[30] = { 0 };

    memcpy (username, salt.salt_buf, salt.salt_len - 22);

    char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };

    u16 *ptr = (u16 *) digest_buf;

    tmp_buf[ 0] = sig[0];
    tmp_buf[ 1] = int_to_base64 (((ptr[1]) >> 12) & 0x3f);
    tmp_buf[ 2] = int_to_base64 (((ptr[1]) >>  6) & 0x3f);
    tmp_buf[ 3] = int_to_base64 (((ptr[1]) >>  0) & 0x3f);
    tmp_buf[ 4] = int_to_base64 (((ptr[0]) >> 12) & 0x3f);
    tmp_buf[ 5] = int_to_base64 (((ptr[0]) >>  6) & 0x3f);
    tmp_buf[ 6] = sig[1];
    tmp_buf[ 7] = int_to_base64 (((ptr[0]) >>  0) & 0x3f);
    tmp_buf[ 8] = int_to_base64 (((ptr[3]) >> 12) & 0x3f);
    tmp_buf[ 9] = int_to_base64 (((ptr[3]) >>  6) & 0x3f);
    tmp_buf[10] = int_to_base64 (((ptr[3]) >>  0) & 0x3f);
    tmp_buf[11] = int_to_base64 (((ptr[2]) >> 12) & 0x3f);
    tmp_buf[12] = sig[2];
    tmp_buf[13] = int_to_base64 (((ptr[2]) >>  6) & 0x3f);
    tmp_buf[14] = int_to_base64 (((ptr[2]) >>  0) & 0x3f);
    tmp_buf[15] = int_to_base64 (((ptr[5]) >> 12) & 0x3f);
    tmp_buf[16] = int_to_base64 (((ptr[5]) >>  6) & 0x3f);
    tmp_buf[17] = sig[3];
    tmp_buf[18] = int_to_base64 (((ptr[5]) >>  0) & 0x3f);
    tmp_buf[19] = int_to_base64 (((ptr[4]) >> 12) & 0x3f);
    tmp_buf[20] = int_to_base64 (((ptr[4]) >>  6) & 0x3f);
    tmp_buf[21] = int_to_base64 (((ptr[4]) >>  0) & 0x3f);
    tmp_buf[22] = int_to_base64 (((ptr[7]) >> 12) & 0x3f);
    tmp_buf[23] = sig[4];
    tmp_buf[24] = int_to_base64 (((ptr[7]) >>  6) & 0x3f);
    tmp_buf[25] = int_to_base64 (((ptr[7]) >>  0) & 0x3f);
    tmp_buf[26] = int_to_base64 (((ptr[6]) >> 12) & 0x3f);
    tmp_buf[27] = int_to_base64 (((ptr[6]) >>  6) & 0x3f);
    tmp_buf[28] = int_to_base64 (((ptr[6]) >>  0) & 0x3f);
    tmp_buf[29] = sig[5];

    snprintf (out_buf, out_size, "%s:%s",
      tmp_buf,
      username);
  }
  else if (hash_mode == 101)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "{SHA}%s", ptr_plain);
  }
  else if (hash_mode == 111)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);
    memcpy (tmp_buf + 20, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "{SSHA}%s", ptr_plain);
  }
  else if (hash_mode == 112)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      (char *) salt.salt_buf);
  }
  else if ((hash_mode == 122) || (hash_mode == 125))
  {
    snprintf (out_buf, out_size, "%s%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 124)
  {
    snprintf (out_buf, out_size, "sha1$%s$%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 131)
  {
    snprintf (out_buf, out_size, "0x0100%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      0u, 0u, 0u, 0u, 0u,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 132)
  {
    snprintf (out_buf, out_size, "0x0100%s%08x%08x%08x%08x%08x",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 133)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "%s", ptr_plain);
  }
  else if (hash_mode == 141)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, ptr_salt);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    memcpy (tmp_buf, digest_buf, 20);

    memset (tmp_buf + 20, 0, sizeof (tmp_buf) - 20);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 20, (u8 *) ptr_plain);

    ptr_plain[27] = 0;

    snprintf (out_buf, out_size, "%s*0*%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1411)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    memcpy (tmp_buf, digest_buf, 32);
    memcpy (tmp_buf + 32, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 32 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "%s%s", SIGNATURE_SHA256B64S, ptr_plain);
  }
  else if (hash_mode == 1421)
  {
    u8 *salt_ptr = (u8 *) salt.salt_buf;

    snprintf (out_buf, out_size, "%c%c%c%c%c%c%08x%08x%08x%08x%08x%08x%08x%08x",
      salt_ptr[0],
      salt_ptr[1],
      salt_ptr[2],
      salt_ptr[3],
      salt_ptr[4],
      salt_ptr[5],
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 1441)
  {
    memcpy (tmp_buf, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, salt.salt_len, ptr_salt);

    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);

    memcpy (tmp_buf, digest_buf, 32);

    memset (tmp_buf + 32, 0, sizeof (tmp_buf) - 32);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 32, (u8 *) ptr_plain);

    ptr_plain[43] = 0;

    snprintf (out_buf, out_size, "%s*1*%s*%s", SIGNATURE_EPISERVER, ptr_salt, ptr_plain);
  }
  else if (hash_mode == 1711)
  {
    // the encoder is a bit too intelligent, it expects the input data in the wrong BOM

    digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
    digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
    digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
    digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
    digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
    digest_buf64[5] = byte_swap_64 (digest_buf64[5]);
    digest_buf64[6] = byte_swap_64 (digest_buf64[6]);
    digest_buf64[7] = byte_swap_64 (digest_buf64[7]);

    memcpy (tmp_buf, digest_buf, 64);
    memcpy (tmp_buf + 64, salt.salt_buf, salt.salt_len);

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 64 + salt.salt_len, (u8 *) ptr_plain);

    snprintf (out_buf, out_size, "%s%s", SIGNATURE_SHA512B64S, ptr_plain);
  }
  else if (hash_mode == 1722)
  {
    u32 *ptr = digest_buf;

    snprintf (out_buf, out_size, "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      ptr[ 1], ptr[ 0],
      ptr[ 3], ptr[ 2],
      ptr[ 5], ptr[ 4],
      ptr[ 7], ptr[ 6],
      ptr[ 9], ptr[ 8],
      ptr[11], ptr[10],
      ptr[13], ptr[12],
      ptr[15], ptr[14]);
  }
  else if (hash_mode == 1731)
  {
    u32 *ptr = digest_buf;

    snprintf (out_buf, out_size, "0x0200%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
  }
  else if (hash_mode == 4400)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]));
  }
  else if (hash_mode == 4700)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 4900)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 7000)
  {
    // salt

    memcpy (tmp_buf, salt.salt_buf, 12);

    // digest

    memcpy (tmp_buf + 12, digest_buf, 20);

    // base64 encode (salt + SHA1)

    base64_encode (int_to_base64, (const u8 *) tmp_buf, 12 + 20, (u8 *) ptr_plain);

    ptr_plain[44] = 0;

    snprintf (out_buf, out_size, "%s%s",
      SIGNATURE_FORTIGATE,
      ptr_plain);
  }
  else if ((hash_mode == 7700) || (hash_mode == 7701))
  {
    snprintf (out_buf, out_size, "%s$%08X%08X",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1]);
  }
  else if ((hash_mode == 7800) || (hash_mode == 7801))
  {
    snprintf (out_buf, out_size, "%s$%08X%08X%08X%08X%08X",
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 7900)
  {
    drupal7_encode ((unsigned char *) digest_buf64, (unsigned char *) ptr_plain);

    // ugly hack start

    char *tmp = (char *) salt.salt_buf_pc;

    ptr_plain[42] = tmp[0];

    // ugly hack end

    ptr_plain[43] = 0;

    snprintf (out_buf, out_size, "%s%s%s", (char *) salt.salt_sign, (char *) salt.salt_buf, ptr_plain);
  }
  else if (hash_mode == 8000)
  {
    snprintf (out_buf, out_size, "0xc007%s%08x%08x%08x%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 8100)
  {
    salt.salt_buf[0] = byte_swap_32 (salt.salt_buf[0]);
    salt.salt_buf[1] = byte_swap_32 (salt.salt_buf[1]);

    snprintf (out_buf, out_size, "1%s%08x%08x%08x%08x%08x",
      (unsigned char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4]);
  }
  else if (hash_mode == 8300)
  {
    char digest_buf_c[34] = { 0 };

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);

    base32_encode (int_to_itoa32, (const u8 *) digest_buf, 20, (u8 *) digest_buf_c);

    digest_buf_c[32] = 0;

    // domain

    const u32 salt_pc_len = salt.salt_len_pc;

    char domain_buf_c[33] = { 0 };

    memcpy (domain_buf_c, (char *) salt.salt_buf_pc, salt_pc_len);

    for (u32 i = 0; i < salt_pc_len; i++)
    {
      const char next = domain_buf_c[i];

      domain_buf_c[i] = '.';

      i += next;
    }

    domain_buf_c[salt_pc_len] = 0;

    // final

    snprintf (out_buf, out_size, "%s:%s:%s:%u", digest_buf_c, domain_buf_c, (char *) salt.salt_buf, salt.salt_iter);
  }
  else if (hash_mode == 2612)
  {
    snprintf (out_buf, out_size, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_PHPS,
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 3711)
  {
    char *salt_ptr = (char *) salt.salt_buf;

    salt_ptr[salt.salt_len - 1] = 0;

    snprintf (out_buf, out_size, "%s%s$%08x%08x%08x%08x",
      SIGNATURE_MEDIAWIKI_B,
      salt_ptr,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);
  }
  else if (hash_mode == 8800)
  {
    androidfde_t *androidfdes = (androidfde_t *) esalts_buf;

    androidfde_t *androidfde = &androidfdes[digest_cur];

    char tmp[3073] = { 0 };

    for (u32 i = 0, j = 0; i < 384; i += 1, j += 8)
    {
      sprintf (tmp + j, "%08x", androidfde->data[i]);
    }

    tmp[3072] = 0;

    snprintf (out_buf, out_size, "%s16$%08x%08x%08x%08x$16$%08x%08x%08x%08x$%s",
      SIGNATURE_ANDROIDFDE,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]),
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      tmp);
  }
  else if (hash_mode == 9200)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *) esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256  = &pbkdf2_sha256s[digest_cur];

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    tmp_buf[43] = 0; // cut it here

    // output

    snprintf (out_buf, out_size, "%s%s$%s", SIGNATURE_CISCO8, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 9400)
  {
    office2007_t *office2007s = (office2007_t *) esalts_buf;

    office2007_t *office2007 = &office2007s[digest_cur];

    snprintf (out_buf, out_size, "%s*%d*%d*%u*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2007,
      2007,
      20,
      office2007->keySize,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2007->encryptedVerifier[0],
      office2007->encryptedVerifier[1],
      office2007->encryptedVerifier[2],
      office2007->encryptedVerifier[3],
      office2007->encryptedVerifierHash[0],
      office2007->encryptedVerifierHash[1],
      office2007->encryptedVerifierHash[2],
      office2007->encryptedVerifierHash[3],
      office2007->encryptedVerifierHash[4]);
  }
  else if (hash_mode == 9500)
  {
    office2010_t *office2010s = (office2010_t *) esalts_buf;

    office2010_t *office2010 = &office2010s[digest_cur];

    snprintf (out_buf, out_size, "%s*%d*%d*%d*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_OFFICE2010,
      2010,
      100000,
      128,
      16,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      office2010->encryptedVerifier[0],
      office2010->encryptedVerifier[1],
      office2010->encryptedVerifier[2],
      office2010->encryptedVerifier[3],
      office2010->encryptedVerifierHash[0],
      office2010->encryptedVerifierHash[1],
      office2010->encryptedVerifierHash[2],
      office2010->encryptedVerifierHash[3],
      office2010->encryptedVerifierHash[4],
      office2010->encryptedVerifierHash[5],
      office2010->encryptedVerifierHash[6],
      office2010->encryptedVerifierHash[7]);
  }
  else if (hash_mode == 10000)
  {
    // salt

    pbkdf2_sha256_t *pbkdf2_sha256s = (pbkdf2_sha256_t *) esalts_buf;

    pbkdf2_sha256_t *pbkdf2_sha256  = &pbkdf2_sha256s[digest_cur];

    unsigned char *salt_buf_ptr = (unsigned char *) pbkdf2_sha256->salt_buf;

    // hash

    digest_buf[0] = byte_swap_32 (digest_buf[0]);
    digest_buf[1] = byte_swap_32 (digest_buf[1]);
    digest_buf[2] = byte_swap_32 (digest_buf[2]);
    digest_buf[3] = byte_swap_32 (digest_buf[3]);
    digest_buf[4] = byte_swap_32 (digest_buf[4]);
    digest_buf[5] = byte_swap_32 (digest_buf[5]);
    digest_buf[6] = byte_swap_32 (digest_buf[6]);
    digest_buf[7] = byte_swap_32 (digest_buf[7]);
    digest_buf[8] = 0; // needed for base64_encode ()

    base64_encode (int_to_base64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

    // output

    snprintf (out_buf, out_size, "%s$%u$%s$%s", SIGNATURE_DJANGOPBKDF2, salt.salt_iter + 1, salt_buf_ptr, tmp_buf);
  }
  else if (hash_mode == 10100)
  {
    snprintf (out_buf, out_size, "%08x%08x:%d:%d:%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      2,
      4,
      byte_swap_32 (salt.salt_buf[0]),
      byte_swap_32 (salt.salt_buf[1]),
      byte_swap_32 (salt.salt_buf[2]),
      byte_swap_32 (salt.salt_buf[3]));
  }
  else if (hash_mode == 10200)
  {
    cram_md5_t *cram_md5s = (cram_md5_t *) esalts_buf;

    cram_md5_t *cram_md5 = &cram_md5s[digest_cur];

    // challenge

    char challenge[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) salt.salt_buf, salt.salt_len, (u8 *) challenge);

    // response

    int tmp_len = snprintf (tmp_buf, sizeof (tmp_buf), "%s %08x%08x%08x%08x",
      (char *) cram_md5->user,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]);

    char response[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) response);

    snprintf (out_buf, out_size, "%s%s$%s", SIGNATURE_CRAM_MD5, challenge, response);
  }
  else if (hash_mode == 10300)
  {
    memcpy (tmp_buf +  0, digest_buf, 20);
    memcpy (tmp_buf + 20, salt.salt_buf, salt.salt_len);

    u32 tmp_len = 20 + salt.salt_len;

    // base64 encode it

    char base64_encoded[100] = { 0 };

    base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) base64_encoded);

    snprintf (out_buf, out_size, "%s%u}%s", SIGNATURE_SAPH_SHA1, salt.salt_iter + 1, base64_encoded);
  }
  else if (hash_mode == 10600)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 10700)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 10900)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 11100)
  {
    u32 salt_challenge = salt.salt_buf[0];

    salt_challenge = byte_swap_32 (salt_challenge);

    unsigned char *user_name = (unsigned char *) (salt.salt_buf + 1);

    snprintf (out_buf, out_size, "%s%s*%08x*%08x%08x%08x%08x",
        SIGNATURE_POSTGRESQL_AUTH,
        user_name,
        salt_challenge,
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
  }
  else if (hash_mode == 11200)
  {
    snprintf (out_buf, out_size, "%s%s*%08x%08x%08x%08x%08x",
        SIGNATURE_MYSQL_AUTH,
        (unsigned char *) salt.salt_buf,
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
  }
  else if (hash_mode == 11400)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 11700 || hash_mode == 11750 || hash_mode == 11760)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7]);
  }
  else if (hash_mode == 11800 || hash_mode == 11850 || hash_mode == 11860)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[ 0]),
      byte_swap_32 (digest_buf[ 1]),
      byte_swap_32 (digest_buf[ 2]),
      byte_swap_32 (digest_buf[ 3]),
      byte_swap_32 (digest_buf[ 4]),
      byte_swap_32 (digest_buf[ 5]),
      byte_swap_32 (digest_buf[ 6]),
      byte_swap_32 (digest_buf[ 7]),
      byte_swap_32 (digest_buf[ 8]),
      byte_swap_32 (digest_buf[ 9]),
      byte_swap_32 (digest_buf[10]),
      byte_swap_32 (digest_buf[11]),
      byte_swap_32 (digest_buf[12]),
      byte_swap_32 (digest_buf[13]),
      byte_swap_32 (digest_buf[14]),
      byte_swap_32 (digest_buf[15]));
  }
  else if (hash_mode == 11900)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 12001)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 12100)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 12200)
  {
    u32 *ptr_digest = digest_buf;

    snprintf (out_buf, out_size, "%s0$1$%08x%08x$%08x%08x",
      SIGNATURE_ECRYPTFS,
      salt.salt_buf[0],
      salt.salt_buf[1],
      ptr_digest[0],
      ptr_digest[1]);
  }
  else if (hash_mode == 12300)
  {
    u32 *ptr_digest = digest_buf;

    snprintf (out_buf, out_size, "%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
      ptr_digest[ 0], ptr_digest[ 1],
      ptr_digest[ 2], ptr_digest[ 3],
      ptr_digest[ 4], ptr_digest[ 5],
      ptr_digest[ 6], ptr_digest[ 7],
      ptr_digest[ 8], ptr_digest[ 9],
      ptr_digest[10], ptr_digest[11],
      ptr_digest[12], ptr_digest[13],
      ptr_digest[14], ptr_digest[15],
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3]);
  }
  else if (hash_mode == 12700)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 12800)
  {
    const u8 *ptr = (const u8 *) salt.salt_buf;

    snprintf (out_buf, out_size, "%s,%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,%u,%08x%08x%08x%08x%08x%08x%08x%08x",
      SIGNATURE_MS_DRSR,
      ptr[0],
      ptr[1],
      ptr[2],
      ptr[3],
      ptr[4],
      ptr[5],
      ptr[6],
      ptr[7],
      ptr[8],
      ptr[9],
      salt.salt_iter + 1,
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]),
      byte_swap_32 (digest_buf[5]),
      byte_swap_32 (digest_buf[6]),
      byte_swap_32 (digest_buf[7])
    );
  }
  else if (hash_mode == 12900)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
      salt.salt_buf[ 4],
      salt.salt_buf[ 5],
      salt.salt_buf[ 6],
      salt.salt_buf[ 7],
      salt.salt_buf[ 8],
      salt.salt_buf[ 9],
      salt.salt_buf[10],
      salt.salt_buf[11],
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]),
      byte_swap_32 (digest_buf[5]),
      byte_swap_32 (digest_buf[6]),
      byte_swap_32 (digest_buf[7]),
      salt.salt_buf[ 0],
      salt.salt_buf[ 1],
      salt.salt_buf[ 2],
      salt.salt_buf[ 3]
    );
  }
  else if (hash_mode == 13200)
  {
    snprintf (out_buf, out_size, "%s*1*%u*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT,
      salt.salt_iter,
      salt.salt_buf[0],
      salt.salt_buf[1],
      salt.salt_buf[2],
      salt.salt_buf[3],
      salt.salt_buf[4],
      salt.salt_buf[5],
      salt.salt_buf[6],
      salt.salt_buf[7],
      salt.salt_buf[8],
      salt.salt_buf[9]);
  }
  else if (hash_mode == 13300)
  {
    snprintf (out_buf, out_size, "%s%08x%08x%08x%08x",
      SIGNATURE_AXCRYPT_SHA1,
              digest_buf[0],
              digest_buf[1],
              digest_buf[2],
              digest_buf[3]);
  }
  else if (hash_mode == 13600)
  {
    zip2_t *zip2s = (zip2_t *) esalts_buf;

    zip2_t *zip2 = &zip2s[digest_cur];

    const u32 salt_len = zip2->salt_len;

    char salt_tmp[32 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->salt_buf;

      sprintf (salt_tmp + j, "%02x", ptr[i]);
    }

    const u32 data_len = zip2->data_len;

    char data_tmp[8192 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < data_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->data_buf;

      sprintf (data_tmp + j, "%02x", ptr[i]);
    }

    const u32 auth_len = zip2->auth_len;

    char auth_tmp[20 + 1] = { 0 };

    for (u32 i = 0, j = 0; i < auth_len; i += 1, j += 2)
    {
      const u8 *ptr = (const u8 *) zip2->auth_buf;

      sprintf (auth_tmp + j, "%02x", ptr[i]);
    }

    snprintf (out_buf, out_size, "%s*%u*%u*%u*%s*%x*%u*%s*%s*%s",
      SIGNATURE_ZIP2_START,
      zip2->type,
      zip2->mode,
      zip2->magic,
      salt_tmp,
      zip2->verify_bytes,
      zip2->compress_length,
      data_tmp,
      auth_tmp,
      SIGNATURE_ZIP2_STOP);
  }
  else if (hash_mode == 13800)
  {
    win8phone_t *esalts = (win8phone_t *) esalts_buf;

    win8phone_t *esalt = &esalts[digest_cur];

    char buf[256 + 1] = { 0 };

    for (int i = 0, j = 0; i < 32; i += 1, j += 8)
    {
      sprintf (buf + j, "%08x", esalt->salt_buf[i]);
    }

    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x:%s",
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3],
      digest_buf[4],
      digest_buf[5],
      digest_buf[6],
      digest_buf[7],
      buf);
  }
  else if (hash_mode == 14400)
  {
    snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
      byte_swap_32 (digest_buf[0]),
      byte_swap_32 (digest_buf[1]),
      byte_swap_32 (digest_buf[2]),
      byte_swap_32 (digest_buf[3]),
      byte_swap_32 (digest_buf[4]));
  }
  else if (hash_mode == 14700)
  {
    // WPKY

    itunes_backup_t *itunes_backups = (itunes_backup_t *) esalts_buf;
    itunes_backup_t *itunes_backup  = &itunes_backups[digest_cur];

    u32 wkpy_u32[10];

    wkpy_u32[0] = byte_swap_32 (itunes_backup->wpky[0]);
    wkpy_u32[1] = byte_swap_32 (itunes_backup->wpky[1]);
    wkpy_u32[2] = byte_swap_32 (itunes_backup->wpky[2]);
    wkpy_u32[3] = byte_swap_32 (itunes_backup->wpky[3]);
    wkpy_u32[4] = byte_swap_32 (itunes_backup->wpky[4]);
    wkpy_u32[5] = byte_swap_32 (itunes_backup->wpky[5]);
    wkpy_u32[6] = byte_swap_32 (itunes_backup->wpky[6]);
    wkpy_u32[7] = byte_swap_32 (itunes_backup->wpky[7]);
    wkpy_u32[8] = byte_swap_32 (itunes_backup->wpky[8]);
    wkpy_u32[9] = byte_swap_32 (itunes_backup->wpky[9]);

    u8 wpky[80 + 1];

    u32_to_hex (wkpy_u32[0], wpky +  0);
    u32_to_hex (wkpy_u32[1], wpky +  8);
    u32_to_hex (wkpy_u32[2], wpky + 16);
    u32_to_hex (wkpy_u32[3], wpky + 24);
    u32_to_hex (wkpy_u32[4], wpky + 32);
    u32_to_hex (wkpy_u32[5], wpky + 40);
    u32_to_hex (wkpy_u32[6], wpky + 48);
    u32_to_hex (wkpy_u32[7], wpky + 56);
    u32_to_hex (wkpy_u32[8], wpky + 64);
    u32_to_hex (wkpy_u32[9], wpky + 72);

    wpky[80] = 0;

    snprintf (out_buf, out_size, "%s*%u*%s*%u*%s**",
      SIGNATURE_ITUNES_BACKUP,
      salt.salt_sign[0],
      wpky,
      salt.salt_iter + 1,
      (char *) salt.salt_buf);
  }
  else if (hash_mode == 14800)
  {
    // WPKY

    itunes_backup_t *itunes_backups = (itunes_backup_t *) esalts_buf;
    itunes_backup_t *itunes_backup  = &itunes_backups[digest_cur];

    u32 wkpy_u32[10];

    wkpy_u32[0] = byte_swap_32 (itunes_backup->wpky[0]);
    wkpy_u32[1] = byte_swap_32 (itunes_backup->wpky[1]);
    wkpy_u32[2] = byte_swap_32 (itunes_backup->wpky[2]);
    wkpy_u32[3] = byte_swap_32 (itunes_backup->wpky[3]);
    wkpy_u32[4] = byte_swap_32 (itunes_backup->wpky[4]);
    wkpy_u32[5] = byte_swap_32 (itunes_backup->wpky[5]);
    wkpy_u32[6] = byte_swap_32 (itunes_backup->wpky[6]);
    wkpy_u32[7] = byte_swap_32 (itunes_backup->wpky[7]);
    wkpy_u32[8] = byte_swap_32 (itunes_backup->wpky[8]);
    wkpy_u32[9] = byte_swap_32 (itunes_backup->wpky[9]);

    u8 wpky[80 + 1];

    u32_to_hex (wkpy_u32[0], wpky +  0);
    u32_to_hex (wkpy_u32[1], wpky +  8);
    u32_to_hex (wkpy_u32[2], wpky + 16);
    u32_to_hex (wkpy_u32[3], wpky + 24);
    u32_to_hex (wkpy_u32[4], wpky + 32);
    u32_to_hex (wkpy_u32[5], wpky + 40);
    u32_to_hex (wkpy_u32[6], wpky + 48);
    u32_to_hex (wkpy_u32[7], wpky + 56);
    u32_to_hex (wkpy_u32[8], wpky + 64);
    u32_to_hex (wkpy_u32[9], wpky + 72);

    wpky[80] = 0;

    // DPSL

    u32 dpsl_u32[5];

    dpsl_u32[0] = byte_swap_32 (itunes_backup->dpsl[0]);
    dpsl_u32[1] = byte_swap_32 (itunes_backup->dpsl[1]);
    dpsl_u32[2] = byte_swap_32 (itunes_backup->dpsl[2]);
    dpsl_u32[3] = byte_swap_32 (itunes_backup->dpsl[3]);
    dpsl_u32[4] = byte_swap_32 (itunes_backup->dpsl[4]);

    u8 dpsl[80 + 1];

    u32_to_hex (dpsl_u32[0], dpsl +  0);
    u32_to_hex (dpsl_u32[1], dpsl +  8);
    u32_to_hex (dpsl_u32[2], dpsl + 16);
    u32_to_hex (dpsl_u32[3], dpsl + 24);
    u32_to_hex (dpsl_u32[4], dpsl + 32);

    dpsl[40] = 0;

    snprintf (out_buf, out_size, "%s*%u*%s*%u*%s*%u*%s",
      SIGNATURE_ITUNES_BACKUP,
      salt.salt_sign[0],
      wpky,
      salt.salt_iter2 + 1,
      (char *) salt.salt_buf,
      salt.salt_iter + 1,
      dpsl);
  }
  else if (hash_mode == 15100)
  {
    // encode the digest:

    netbsd_sha1crypt_encode ((unsigned char *) digest_buf, salt.salt_sign[0], (unsigned char *) ptr_plain);

    // output:

    snprintf (out_buf, out_size, "$sha1$%u$%s$%s",
      salt.salt_iter + 1,
      (char *) salt.salt_buf,
      ptr_plain);
  }
  else if (hash_mode == 15200)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 15500)
  {
    jks_sha1_t *jks_sha1s = (jks_sha1_t *) esalts_buf;

    jks_sha1_t *jks_sha1 = &jks_sha1s[digest_cur];

    char enc_key[16384 + 1] = { 0 };

    u8 *ptr = (u8 *) jks_sha1->enc_key_buf;

    for (u32 i = 0, j = 0; i < jks_sha1->enc_key_len; i += 1, j += 2)
    {
      sprintf (enc_key + j, "%02X", ptr[i]);
    }

    u8 *der = (u8 *) jks_sha1->der;

    snprintf (out_buf, out_size, "%s*%08X%08X%08X%08X%08X*%08X%08X%08X%08X%08X*%s*%02X*%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X*%s",
      SIGNATURE_JKS_SHA1,
      byte_swap_32 (jks_sha1->checksum[0]),
      byte_swap_32 (jks_sha1->checksum[1]),
      byte_swap_32 (jks_sha1->checksum[2]),
      byte_swap_32 (jks_sha1->checksum[3]),
      byte_swap_32 (jks_sha1->checksum[4]),
      byte_swap_32 (jks_sha1->iv[0]),
      byte_swap_32 (jks_sha1->iv[1]),
      byte_swap_32 (jks_sha1->iv[2]),
      byte_swap_32 (jks_sha1->iv[3]),
      byte_swap_32 (jks_sha1->iv[4]),
      enc_key,
      der[ 0],
      der[ 6],
      der[ 7],
      der[ 8],
      der[ 9],
      der[10],
      der[11],
      der[12],
      der[13],
      der[14],
      der[15],
      der[16],
      der[17],
      der[18],
      der[19],
      (char *) jks_sha1->alias
    );
  }
  else if (hash_mode == 16100)
  {
    tacacs_plus_t *tacacs_pluss = (tacacs_plus_t *) esalts_buf;

    tacacs_plus_t *tacacs_plus = &tacacs_pluss[digest_cur];

    char ct_data[256 + 1] = { 0 };

    u8 *ct_data_ptr = (u8 *) tacacs_plus->ct_data_buf;

    for (u32 i = 0, j = 0; i < tacacs_plus->ct_data_len; i += 1, j += 2)
    {
      sprintf (ct_data + j, "%02x", ct_data_ptr[i]);
    }

    u8 *session_ptr  = (u8 *) tacacs_plus->session_buf;
    u8 *sequence_ptr = (u8 *) tacacs_plus->sequence_buf;

    snprintf (out_buf, out_size, "%s%02x%02x%02x%02x$%s$%02x%02x",
      SIGNATURE_TACACS_PLUS,
      session_ptr[0],
      session_ptr[1],
      session_ptr[2],
      session_ptr[3],
      ct_data,
      sequence_ptr[0],
      sequence_ptr[1]);
  }
  else if (hash_mode == 16200)
  {
    apple_secure_notes_t *apple_secure_notess = (apple_secure_notes_t *) esalts_buf;

    apple_secure_notes_t *apple_secure_notes = &apple_secure_notess[digest_cur];

    snprintf (out_buf, out_size, "%s*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
      SIGNATURE_APPLE_SECURE_NOTES,
      apple_secure_notes->Z_PK,
      apple_secure_notes->ZCRYPTOITERATIONCOUNT,
      byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[0]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[1]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[2]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[3]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[0]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[1]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[2]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[3]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[4]),
      byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[5]));
  }
  else if (hash_mode == 16300)
  {
    ethereum_presale_t *ethereum_presales = (ethereum_presale_t *) esalts_buf;
    ethereum_presale_t *ethereum_presale  = &ethereum_presales[digest_cur];

    // get the initialization vector:

    u8 encseed[1248 + 1] = { 0 };

    u32 iv[4];

    iv[0] = byte_swap_32 (ethereum_presale->iv[0]);
    iv[1] = byte_swap_32 (ethereum_presale->iv[1]);
    iv[2] = byte_swap_32 (ethereum_presale->iv[2]);
    iv[3] = byte_swap_32 (ethereum_presale->iv[3]);

    u32_to_hex (iv[0], encseed +  0);
    u32_to_hex (iv[1], encseed +  8);
    u32_to_hex (iv[2], encseed + 16);
    u32_to_hex (iv[3], encseed + 24);

    // get the raw enc_seed (without iv):

    u32 *enc_seed_ptr = ethereum_presale->enc_seed;

    for (u32 i = 0, j = 32; i < ethereum_presale->enc_seed_len / 4; i++, j += 8)
    {
      u32 tmp = enc_seed_ptr[i];

      tmp = byte_swap_32 (tmp);

      u32_to_hex (tmp, encseed + j);
    }

    const u32 max_hex_len = (16 + ethereum_presale->enc_seed_len) * 2; // 16 bytes IV + encrypted seed (in hex)

    const u32 max_pos = MIN (sizeof (encseed) - 1, max_hex_len);

    encseed[max_pos] = 0;

    // output:

    snprintf (out_buf, out_size, "%s*%s*%s*%08x%08x%08x%08x",
      SIGNATURE_ETHEREUM_PRESALE,
      encseed,
      (char *) salt.salt_buf,
      digest_buf[0],
      digest_buf[1],
      digest_buf[2],
      digest_buf[3]
    );
  }
  else if (hash_mode == 16400)
  {
    hashinfo_t **hashinfo_ptr = hash_info;
    char        *hash_buf     = hashinfo_ptr[digest_cur]->orighash;

    snprintf (out_buf, out_size, "%s", hash_buf);
  }
  else if (hash_mode == 16500)
  {
    jwt_t *jwts = (jwt_t *) esalts_buf;

    jwt_t *jwt = &jwts[digest_cur];

    if (hashconfig->kern_type == KERN_TYPE_JWT_HS256)
    {
      digest_buf[0] = byte_swap_32 (digest_buf[0]);
      digest_buf[1] = byte_swap_32 (digest_buf[1]);
      digest_buf[2] = byte_swap_32 (digest_buf[2]);
      digest_buf[3] = byte_swap_32 (digest_buf[3]);
      digest_buf[4] = byte_swap_32 (digest_buf[4]);
      digest_buf[5] = byte_swap_32 (digest_buf[5]);
      digest_buf[6] = byte_swap_32 (digest_buf[6]);
      digest_buf[7] = byte_swap_32 (digest_buf[7]);

      memset (tmp_buf, 0, sizeof (tmp_buf));

      memcpy (tmp_buf, digest_buf, 32);

      base64_encode (int_to_base64url, (const u8 *) tmp_buf, 32, (u8 *) ptr_plain);

      ptr_plain[43] = 0;
    }
    else if (hashconfig->kern_type == KERN_TYPE_JWT_HS384)
    {
      digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
      digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
      digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
      digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
      digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
      digest_buf64[5] = byte_swap_64 (digest_buf64[5]);

      memset (tmp_buf, 0, sizeof (tmp_buf));

      memcpy (tmp_buf, digest_buf64, 48);

      base64_encode (int_to_base64url, (const u8 *) tmp_buf, 48, (u8 *) ptr_plain);

      ptr_plain[64] = 0;
    }
    else if (hashconfig->kern_type == KERN_TYPE_JWT_HS512)
    {
      digest_buf64[0] = byte_swap_64 (digest_buf64[0]);
      digest_buf64[1] = byte_swap_64 (digest_buf64[1]);
      digest_buf64[2] = byte_swap_64 (digest_buf64[2]);
      digest_buf64[3] = byte_swap_64 (digest_buf64[3]);
      digest_buf64[4] = byte_swap_64 (digest_buf64[4]);
      digest_buf64[5] = byte_swap_64 (digest_buf64[5]);
      digest_buf64[6] = byte_swap_64 (digest_buf64[6]);
      digest_buf64[7] = byte_swap_64 (digest_buf64[7]);

      memset (tmp_buf, 0, sizeof (tmp_buf));

      memcpy (tmp_buf, digest_buf64, 64);

      base64_encode (int_to_base64url, (const u8 *) tmp_buf, 64, (u8 *) ptr_plain);

      ptr_plain[86] = 0;
    }

    snprintf (out_buf, out_size, "%s.%s",
      (char *) jwt->salt_buf,
      (char *) ptr_plain);
  }
  else if (hash_mode == 16600)
  {
    electrum_wallet_t *electrum_wallets = (electrum_wallet_t *) esalts_buf;

    electrum_wallet_t *electrum_wallet = &electrum_wallets[digest_cur];

    snprintf (out_buf, out_size, "%s%d*%08x%08x%08x%08x*%08x%08x%08x%08x",
      SIGNATURE_ELECTRUM_WALLET,
      electrum_wallet->salt_type,
      byte_swap_32 (electrum_wallet->iv[0]),
      byte_swap_32 (electrum_wallet->iv[1]),
      byte_swap_32 (electrum_wallet->iv[2]),
      byte_swap_32 (electrum_wallet->iv[3]),
      byte_swap_32 (electrum_wallet->encrypted[0]),
      byte_swap_32 (electrum_wallet->encrypted[1]),
      byte_swap_32 (electrum_wallet->encrypted[2]),
      byte_swap_32 (electrum_wallet->encrypted[3]));
  }
  else
  {
    if (hash_type == HASH_TYPE_MD4)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_MD5)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_SHA1)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_SHA224)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6]);
    }
    else if (hash_type == HASH_TYPE_SHA256)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4],
        digest_buf[5],
        digest_buf[6],
        digest_buf[7]);
    }
    else if (hash_type == HASH_TYPE_SHA384)
    {
      u32 *ptr = digest_buf;

      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10]);
    }
    else if (hash_type == HASH_TYPE_SHA512)
    {
      u32 *ptr = digest_buf;

      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        ptr[ 1], ptr[ 0],
        ptr[ 3], ptr[ 2],
        ptr[ 5], ptr[ 4],
        ptr[ 7], ptr[ 6],
        ptr[ 9], ptr[ 8],
        ptr[11], ptr[10],
        ptr[13], ptr[12],
        ptr[15], ptr[14]);
    }
    else if (hash_type == HASH_TYPE_RIPEMD160)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3],
        digest_buf[4]);
    }
    else if (hash_type == HASH_TYPE_WHIRLPOOL)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
        digest_buf[ 0],
        digest_buf[ 1],
        digest_buf[ 2],
        digest_buf[ 3],
        digest_buf[ 4],
        digest_buf[ 5],
        digest_buf[ 6],
        digest_buf[ 7],
        digest_buf[ 8],
        digest_buf[ 9],
        digest_buf[10],
        digest_buf[11],
        digest_buf[12],
        digest_buf[13],
        digest_buf[14],
        digest_buf[15]);
    }
    else if (hash_type == HASH_TYPE_MYSQL)
    {
      snprintf (out_buf, out_size, "%08x%08x",
        digest_buf[0],
        digest_buf[1]);
    }
    else if (hash_type == HASH_TYPE_LOTUS5)
    {
      snprintf (out_buf, out_size, "%08x%08x%08x%08x",
        digest_buf[0],
        digest_buf[1],
        digest_buf[2],
        digest_buf[3]);
    }
    else if (hash_type == HASH_TYPE_LOTUS6)
    {
      digest_buf[ 0] = byte_swap_32 (digest_buf[ 0]);
      digest_buf[ 1] = byte_swap_32 (digest_buf[ 1]);
      digest_buf[ 2] = byte_swap_32 (digest_buf[ 2]);
      digest_buf[ 3] = byte_swap_32 (digest_buf[ 3]);

      char buf[16] = { 0 };

      memcpy (buf + 0, salt.salt_buf, 5);
      memcpy (buf + 5, digest_buf, 9);

      buf[3] -= -4;

      base64_encode (int_to_lotus64, (const u8 *) buf, 14, (u8 *) tmp_buf);

      tmp_buf[18] = salt.salt_buf_pc[7];
      tmp_buf[19] = 0;

      snprintf (out_buf, out_size, "(G%s)", tmp_buf);
    }
    else if (hash_type == HASH_TYPE_LOTUS8)
    {
      char buf[52] = { 0 };

      // salt

      memcpy (buf + 0, salt.salt_buf, 16);

      buf[3] -= -4;

      // iteration

      snprintf (buf + 16, 11, "%010u", salt.salt_iter + 1);

      // chars

      buf[26] = salt.salt_buf_pc[0];
      buf[27] = salt.salt_buf_pc[1];

      // digest

      memcpy (buf + 28, digest_buf, 8);

      base64_encode (int_to_lotus64, (const u8 *) buf, 36, (u8 *) tmp_buf);

      tmp_buf[49] = 0;

      snprintf (out_buf, out_size, "(H%s)", tmp_buf);
    }
  }
}

int hashconfig_init (hashcat_ctx_t *hashcat_ctx)
{
    case    22:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = netscreen_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00022;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    30:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00030;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    40:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00040;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    50:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00050;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case    60:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00060;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;



    case   111:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1b64s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00111;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   112:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = oracles_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00112;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   120:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00120;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   121:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_LOWER;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00121;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   122:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = macos1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00122;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   124:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = djangosha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00124;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   125:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = arubaos_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00125;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   130:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00130;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   131:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = mssql2000_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00131;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   132:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = mssql2005_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00132;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   133:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = peoplesoft_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00133;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   140:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00140;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   141:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_BASE64;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = episerver_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00141;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   150:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00150;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case   160:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA1_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_00160;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1410:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01410;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1411:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256b64s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01411;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1420:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01420;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1421:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = hmailserver_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01421;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1430:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWUSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01430;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1440:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01440;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1441:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_BASE64;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = episerver4_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01441;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1450:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA256_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01450;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1460:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA256_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sha256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_01460;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1600:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PREFERED_THREAD;
                 hashconfig->kern_type      = KERN_TYPE_APR1CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5apr1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_01600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1710:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01710;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1711:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512b64s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01711;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1720:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01720;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1722:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_SLTPW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = macos512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01722;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1730:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLTU;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01730;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1731:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_PWSLTU;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = mssql2012_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01731;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1740:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA512_SLTPWU;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01740;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1750:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA512_PW;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01750;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  1760:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_HMACSHA512_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = sha512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 14;
                 hashconfig->dgst_pos1      = 15;
                 hashconfig->dgst_pos2      = 6;
                 hashconfig->dgst_pos3      = 7;
                 hashconfig->st_hash        = ST_HASH_01760;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2600:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_VIRTUAL;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2611:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02611;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2612:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = phps_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02612;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  2711:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD55_PWSLT2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = vb30_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_02711;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  3710:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_03710;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  3711:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = mediawiki_b_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_03711;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  3800:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_PW_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_03800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4010:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_SLT_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04010;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4110:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SLT_MD5_PW_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04110;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4300:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_VIRTUAL;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_MD5U5_PWSLT1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4400:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_MD5_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4500:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA11;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04500;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4520:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04520;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4521:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = redmine_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04521;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4522:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_SHA1_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = punbb_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04522;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4700:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_MD5;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  4900:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_SLT_PW_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_04900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  6000:  hashconfig->hash_type      = HASH_TYPE_RIPEMD160;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_RIPEMD160;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = ripemd160_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_06000;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  6100:  hashconfig->hash_type      = HASH_TYPE_WHIRLPOOL;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_WHIRLPOOL;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = whirlpool_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_06100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  7000:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_FORTIGATE;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = fortigate_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_07000;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  7700:  hashconfig->hash_type      = HASH_TYPE_SAPB;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_SAPB;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = sapb_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_07700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  7701:  hashconfig->hash_type      = HASH_TYPE_SAPB;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_UPPER
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_SAPB_MANGLED;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = sapb_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_07701;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  7800:  hashconfig->hash_type      = HASH_TYPE_SAPG;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_SAPG;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sapg_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_07800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  7801:  hashconfig->hash_type      = HASH_TYPE_SAPG;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_UPPER;
                 hashconfig->kern_type      = KERN_TYPE_SAPG_MANGLED;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sapg_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_07801;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  7900:  hashconfig->hash_type      = HASH_TYPE_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_DRUPAL7;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = drupal7_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_07900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8000:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_SYBASEASE;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = sybasease_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_08000;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8100:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE;
                 hashconfig->kern_type      = KERN_TYPE_NETSCALER;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = netscaler_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_PREPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_08100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_HEX
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_NSEC3;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = nsec3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_08300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8400:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_WBB3;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = wbb3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_08400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8600:  hashconfig->hash_type      = HASH_TYPE_LOTUS5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LOTUS5;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = lotus5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_08600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8700:  hashconfig->hash_type      = HASH_TYPE_LOTUS6;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LOTUS6;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = lotus6_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_08700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  8800:  hashconfig->hash_type      = HASH_TYPE_ANDROIDFDE;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ANDROIDFDE;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = androidfde_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_08800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  9100:  hashconfig->hash_type      = HASH_TYPE_LOTUS8;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_LOTUS8;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = lotus8_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_09100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  9200:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = cisco8_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_09200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  9400:  hashconfig->hash_type      = HASH_TYPE_OFFICE2007;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_OFFICE2007;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = office2007_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_09400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  9500:  hashconfig->hash_type      = HASH_TYPE_OFFICE2010;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_OFFICE2010;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = office2010_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_09500;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case  9900:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_RADMIN2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = radmin2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_09900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10000:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = djangopbkdf2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_10000;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10100:  hashconfig->hash_type      = HASH_TYPE_SIPHASH;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SIPHASH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = siphash_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_10100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10200:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS14;
                 hashconfig->kern_type      = KERN_TYPE_HMACMD5_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = crammd5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_10200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SAPH_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = saph_sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_10300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10600:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_SHA256_PWSLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = pdf17l3_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_10600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10700:  hashconfig->hash_type      = HASH_TYPE_PDFU32;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PDF17L8;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = pdf17l8_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_10700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 10900:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA256;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = pbkdf2_sha256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_10900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11100:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_ADD80;
                 hashconfig->kern_type      = KERN_TYPE_POSTGRESQL_AUTH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = postgresql_auth_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_11100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11200:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_MYSQL_AUTH;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = mysql_auth_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_11200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11400:  hashconfig->hash_type      = HASH_TYPE_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_SIP_AUTH;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = sip_auth_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_11400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11700:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_STREEBOG_256;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = streebog_256_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11750:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_256_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = streebog_256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11750;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11760:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_256;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_256_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = streebog_256s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11760;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11800:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_STREEBOG_512;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = streebog_512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11850:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_512_PW;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = streebog_512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11850;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11860:  hashconfig->hash_type      = HASH_TYPE_STREEBOG_512;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_PT_ADD01;
                 hashconfig->kern_type      = KERN_TYPE_HMAC_STREEBOG_512_SLT;
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = streebog_512s_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11860;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 11900:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_MD5;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_MD5;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = pbkdf2_md5_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_11900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12001:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_32;
                 hashconfig->parse_func     = atlassian_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12001;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12100:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA512;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_BASE64
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_PBKDF2_SHA512;
                 hashconfig->dgst_size      = DGST_SIZE_8_16;
                 hashconfig->parse_func     = pbkdf2_sha512_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12200:  hashconfig->hash_type      = HASH_TYPE_ECRYPTFS;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ECRYPTFS;
                 hashconfig->dgst_size      = DGST_SIZE_8_8;
                 hashconfig->parse_func     = ecryptfs_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12300:  hashconfig->hash_type      = HASH_TYPE_ORACLET;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ORACLET;
                 hashconfig->dgst_size      = DGST_SIZE_8_16;
                 hashconfig->parse_func     = oraclet_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_USES_BITS_64
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12700:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_MYWALLET;
                 hashconfig->dgst_size      = DGST_SIZE_4_5; // because kernel uses _SHA1_
                 hashconfig->parse_func     = mywallet_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12800:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_MS_DRSR;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = ms_drsr_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 12900:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ANDROIDFDE_SAMSUNG;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = androidfde_samsung_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_12900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 13200:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_AXCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = axcrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_13200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 13300:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_SHA1_AXCRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1axcrypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_NOT_SALTED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 3;
                 hashconfig->dgst_pos3      = 2;
                 hashconfig->st_hash        = ST_HASH_13300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 13600:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_ZIP2;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = zip2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_13600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 13800:  hashconfig->hash_type      = HASH_TYPE_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16LE;
                 hashconfig->kern_type      = KERN_TYPE_WIN8PHONE;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = win8phone_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 7;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 6;
                 hashconfig->st_hash        = ST_HASH_13800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 13900:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_OPENCART;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = opencart_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_13900;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 14400:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_GENERIC;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_SHA1CX;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = sha1cx_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_EARLY_SKIP;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_14400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 14700:  hashconfig->hash_type      = HASH_TYPE_ITUNES_BACKUP_9;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_ITUNES_BACKUP_9;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // we actually do not have a digest
                 hashconfig->parse_func     = itunes_backup_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_14700;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 14800:  hashconfig->hash_type      = HASH_TYPE_ITUNES_BACKUP_10;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX
                                            | OPTS_TYPE_INIT2
                                            | OPTS_TYPE_LOOP2;
                 hashconfig->kern_type      = KERN_TYPE_ITUNES_BACKUP_10;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // we actually do not have a digest
                 hashconfig->parse_func     = itunes_backup_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_14800;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 15100:  hashconfig->hash_type      = HASH_TYPE_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_NETBSD_SHA1CRYPT;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = netbsd_sha1crypt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_15100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 15200:  hashconfig->hash_type      = HASH_TYPE_AES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_MYWALLET;
                 hashconfig->dgst_size      = DGST_SIZE_4_5; // because kernel uses _SHA1_
                 hashconfig->parse_func     = mywalletv2_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_15200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 15500:  hashconfig->hash_type      = HASH_TYPE_JKS_SHA1;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_UTF16BE
                                            | OPTS_TYPE_ST_ADD80
                                            | OPTS_TYPE_ST_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_JKS_SHA1;
                 hashconfig->dgst_size      = DGST_SIZE_4_5;
                 hashconfig->parse_func     = jks_sha1_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_APPENDED_SALT;
                 hashconfig->dgst_pos0      = 3;
                 hashconfig->dgst_pos1      = 4;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_15500;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 16100:  hashconfig->hash_type      = HASH_TYPE_TACACS_PLUS;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_TACACS_PLUS;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = tacacs_plus_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_16100;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 16200:  hashconfig->hash_type      = HASH_TYPE_APPLE_SECURE_NOTES;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE;
                 hashconfig->kern_type      = KERN_TYPE_APPLE_SECURE_NOTES;
                 hashconfig->dgst_size      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
                 hashconfig->parse_func     = apple_secure_notes_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_16200;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 16300:  hashconfig->hash_type      = HASH_TYPE_PBKDF2_SHA256;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_OUTSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_ST_HEX;
                 hashconfig->kern_type      = KERN_TYPE_ETHEREUM_PRESALE;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = ethereum_presale_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_16300;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 16400:  hashconfig->hash_type      = HASH_TYPE_CRAM_MD5_DOVECOT;
                 hashconfig->salt_type      = SALT_TYPE_NONE;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_LE
                                            | OPTS_TYPE_HASH_COPY;
                 hashconfig->kern_type      = KERN_TYPE_CRAM_MD5_DOVECOT;
                 hashconfig->dgst_size      = DGST_SIZE_4_4;
                 hashconfig->parse_func     = crammd5_dovecot_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT
                                            | OPTI_TYPE_PRECOMPUTE_MERKLE
                                            | OPTI_TYPE_MEET_IN_MIDDLE
                                            | OPTI_TYPE_EARLY_SKIP
                                            | OPTI_TYPE_NOT_ITERATED
                                            | OPTI_TYPE_RAW_HASH;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 3;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 1;
                 hashconfig->st_hash        = ST_HASH_16400;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 16500:  hashconfig->hash_type      = HASH_TYPE_JWT;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE;
                 hashconfig->kern_type      = (u32) -1; // this gets overwritten from within parser
                 hashconfig->dgst_size      = DGST_SIZE_4_16;
                 hashconfig->parse_func     = jwt_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_NOT_ITERATED;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = NULL;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;

    case 16600:  hashconfig->hash_type      = HASH_TYPE_ELECTRUM_WALLET;
                 hashconfig->salt_type      = SALT_TYPE_EMBEDDED;
                 hashconfig->attack_exec    = ATTACK_EXEC_INSIDE_KERNEL;
                 hashconfig->opts_type      = OPTS_TYPE_PT_GENERATE_BE
                                            | OPTS_TYPE_PT_ADD80
                                            | OPTS_TYPE_PT_ADDBITS15;
                 hashconfig->kern_type      = KERN_TYPE_ELECTRUM_WALLET13;
                 hashconfig->dgst_size      = DGST_SIZE_4_8;
                 hashconfig->parse_func     = electrum_wallet13_parse_hash;
                 hashconfig->opti_type      = OPTI_TYPE_ZERO_BYTE
                                            | OPTI_TYPE_PRECOMPUTE_INIT;
                 hashconfig->dgst_pos0      = 0;
                 hashconfig->dgst_pos1      = 1;
                 hashconfig->dgst_pos2      = 2;
                 hashconfig->dgst_pos3      = 3;
                 hashconfig->st_hash        = ST_HASH_16600;
                 hashconfig->st_pass        = ST_PASS_HASHCAT_PLAIN;
                 break;


  }

  // esalt_size

  switch (hashconfig->hash_mode)
  {
    case  8800: hashconfig->esalt_size = sizeof (androidfde_t);         break;
    case  9200: hashconfig->esalt_size = sizeof (pbkdf2_sha256_t);      break;
    case  9400: hashconfig->esalt_size = sizeof (office2007_t);         break;
    case  9500: hashconfig->esalt_size = sizeof (office2010_t);         break;
    case 10000: hashconfig->esalt_size = sizeof (pbkdf2_sha256_t);      break;
    case 10200: hashconfig->esalt_size = sizeof (cram_md5_t);           break;
    case 10600: hashconfig->esalt_size = sizeof (pdf_t);                break;
    case 10700: hashconfig->esalt_size = sizeof (pdf_t);                break;
    case 10900: hashconfig->esalt_size = sizeof (pbkdf2_sha256_t);      break;
    case 11400: hashconfig->esalt_size = sizeof (sip_t);                break;
    case 11900: hashconfig->esalt_size = sizeof (pbkdf2_md5_t);         break;
    case 12001: hashconfig->esalt_size = sizeof (pbkdf2_sha1_t);        break;
    case 12100: hashconfig->esalt_size = sizeof (pbkdf2_sha512_t);      break;
    case 13600: hashconfig->esalt_size = sizeof (zip2_t);               break;
    case 13800: hashconfig->esalt_size = sizeof (win8phone_t);          break;
    case 14700: hashconfig->esalt_size = sizeof (itunes_backup_t);      break;
    case 14800: hashconfig->esalt_size = sizeof (itunes_backup_t);      break;
    case 15500: hashconfig->esalt_size = sizeof (jks_sha1_t);           break;
    case 16100: hashconfig->esalt_size = sizeof (tacacs_plus_t);        break;
    case 16200: hashconfig->esalt_size = sizeof (apple_secure_notes_t); break;
    case 16300: hashconfig->esalt_size = sizeof (ethereum_presale_t);   break;
    case 16500: hashconfig->esalt_size = sizeof (jwt_t);                break;
    case 16600: hashconfig->esalt_size = sizeof (electrum_wallet_t);    break;
  }

  // tmp_size

  switch (hashconfig->hash_mode)
  {
    case  7900: hashconfig->tmp_size = sizeof (drupal7_tmp_t);            break;
    case  8800: hashconfig->tmp_size = sizeof (androidfde_tmp_t);         break;
    case  9100: hashconfig->tmp_size = sizeof (lotus8_tmp_t);             break;
    case  9200: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
    case  9400: hashconfig->tmp_size = sizeof (office2007_tmp_t);         break;
    case  9500: hashconfig->tmp_size = sizeof (office2010_tmp_t);         break;
    case 10000: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
    case 10200: hashconfig->tmp_size = sizeof (cram_md5_t);               break;
    case 10300: hashconfig->tmp_size = sizeof (saph_sha1_tmp_t);          break;
    case 10700: hashconfig->tmp_size = sizeof (pdf17l8_tmp_t);            break;
    case 10900: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
    case 11900: hashconfig->tmp_size = sizeof (pbkdf2_md5_tmp_t);         break;
    case 12001: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);        break;
    case 12100: hashconfig->tmp_size = sizeof (pbkdf2_sha512_tmp_t);      break;
    case 12200: hashconfig->tmp_size = sizeof (ecryptfs_tmp_t);           break;
    case 12300: hashconfig->tmp_size = sizeof (oraclet_tmp_t);            break;
    case 12700: hashconfig->tmp_size = sizeof (mywallet_tmp_t);           break;
    case 12800: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
    case 12900: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
    case 13200: hashconfig->tmp_size = sizeof (axcrypt_tmp_t);            break;
    case 13600: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);        break;
    case 14700: hashconfig->tmp_size = sizeof (pbkdf2_sha1_tmp_t);        break;
    case 14800: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
    case 15100: hashconfig->tmp_size = sizeof (pbkdf1_sha1_tmp_t);        break;
    case 15200: hashconfig->tmp_size = sizeof (mywallet_tmp_t);           break;
    case 16200: hashconfig->tmp_size = sizeof (apple_secure_notes_tmp_t); break;
    case 16300: hashconfig->tmp_size = sizeof (pbkdf2_sha256_tmp_t);      break;
  };
}

u32 default_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // pw_max : should be set to default at the time this is executed

  u32 pw_max = hashconfig->pw_max;

  if (optimized_kernel == true)
  {
    switch (hashconfig->hash_mode)
    {
      case  7000: pw_max = MIN (pw_max, 19); // pure kernel available
                  break;
      case 10700: pw_max = MIN (pw_max, 16); // pure kernel available
                  break;
      case 14400: pw_max = MIN (pw_max, 24); // todo
                  break;
      case 15500: pw_max = MIN (pw_max, 16); // todo
                  break;
    }
  }
  else
  {
    switch (hashconfig->hash_mode)
    {
      case 10700: pw_max = 127; // https://www.pdflib.com/knowledge-base/pdf-password-security/encryption/
                  break;
      case 16400: pw_max = 64; // HMAC-MD5 and `doveadm pw` are different for password more than 64 bytes
                  break;
    }
  }

  // pw_max : all modes listed in the following switch cases are
  //          the maximum possible password length of the related system
  //          plus the opencl kernels which eventually allows cracking of passwords of up length PW_MAX for free (no speed drop).
  //          some modes have a self-set and some have
  //          underlaying algorithms specific hard maximum password length
  //          these limits override all previous restrictions, always

  switch (hashconfig->hash_mode)
  {
    case   112: pw_max = 30;      break; // https://www.toadworld.com/platforms/oracle/b/weblog/archive/2013/11/12/oracle-12c-passwords
    case  7700: pw_max = 8;       break; // https://www.daniel-berlin.de/security/sap-sec/password-hash-algorithms/
    case  7800: pw_max = 40;      break; // https://www.daniel-berlin.de/security/sap-sec/password-hash-algorithms/
    case  7900: pw_max = PW_MAX;  break;
    case  8000: pw_max = 30;      break; // http://infocenter.sybase.com/help/index.jsp?topic=/com.sybase.infocenter.dc31654.1570/html/sag1/CIHIBDBA.htm
    case  8600: pw_max = 16;      break; // Lotus Notes/Domino 5 limits itself to 16
    case  8700: pw_max = 64;      break; // https://www.ibm.com/support/knowledgecenter/en/SSKTWP_8.5.3/com.ibm.notes85.client.doc/fram_limits_of_notes_r.html
    case  8800: pw_max = PW_MAX;  break;
    case  9100: pw_max = 64;      break; // https://www.ibm.com/support/knowledgecenter/en/SSKTWP_8.5.3/com.ibm.notes85.client.doc/fram_limits_of_notes_r.html
    case  9200: pw_max = PW_MAX;  break;
    case  9400: pw_max = PW_MAX;  break;
    case  9500: pw_max = PW_MAX;  break;
    case  9900: pw_max = 100;     break; // RAdmin2 sets w[25] = 0x80
    case 10000: pw_max = PW_MAX;  break;
    case 10300: pw_max = 40;      break; // https://www.daniel-berlin.de/security/sap-sec/password-hash-algorithms/
    case 10600: pw_max = 127;     break; // https://www.pdflib.com/knowledge-base/pdf-password-security/encryption/
    case 10900: pw_max = PW_MAX;  break;
    case 11900: pw_max = PW_MAX;  break;
    case 12001: pw_max = PW_MAX;  break;
    case 12200: pw_max = PW_MAX;  break;
    case 12300: pw_max = PW_MAX;  break;
    case 12700: pw_max = PW_MAX;  break;
    case 12800: pw_max = PW_MAX;  break;
    case 12900: pw_max = PW_MAX;  break;
    case 13200: pw_max = PW_MAX;  break;
    case 13600: pw_max = PW_MAX;  break;
    case 14700: pw_max = PW_MAX;  break;
    case 14800: pw_max = PW_MAX;  break;
    case 15100: pw_max = PW_MAX;  break;
  }

  return pw_max;
}

#ifndef _RAR_HEADERS_
#define _RAR_HEADERS_

#define  SIZEOF_MARKHEAD3        7 // Size of RAR 4.x archive mark header.
#define  SIZEOF_MAINHEAD14       7 // Size of RAR 1.4 main archive header.
#define  SIZEOF_MAINHEAD3       13 // Size of RAR 4.x main archive header.
#define  SIZEOF_FILEHEAD14      21 // Size of RAR 1.4 file header.
#define  SIZEOF_FILEHEAD3       32 // Size of RAR 3.0 file header.
#define  SIZEOF_SHORTBLOCKHEAD   7
#define  SIZEOF_LONGBLOCKHEAD   11
#define  SIZEOF_SUBBLOCKHEAD    14
#define  SIZEOF_COMMHEAD        13
#define  SIZEOF_PROTECTHEAD     26
#define  SIZEOF_UOHEAD          18
#define  SIZEOF_STREAMHEAD      26

#define  VER_PACK               29U
#define  VER_PACK5              50U // It is stored as 0, but we subtract 50 when saving an archive.
#define  VER_UNPACK             29U
#define  VER_UNPACK5            50U // It is stored as 0, but we add 50 when reading an archive.
#define  VER_UNKNOWN          9999U // Just some large value.

#define  MHD_VOLUME         0x0001U

// Old style main archive comment embed into main archive header. Must not
// be used in new archives anymore.
#define  MHD_COMMENT        0x0002U

#define  MHD_LOCK           0x0004U
#define  MHD_SOLID          0x0008U
#define  MHD_PACK_COMMENT   0x0010U
#define  MHD_NEWNUMBERING   0x0010U
#define  MHD_AV             0x0020U
#define  MHD_PROTECT        0x0040U
#define  MHD_PASSWORD       0x0080U
#define  MHD_FIRSTVOLUME    0x0100U

#define  LHD_SPLIT_BEFORE   0x0001U
#define  LHD_SPLIT_AFTER    0x0002U
#define  LHD_PASSWORD       0x0004U

// Old style file comment embed into file header. Must not be used
// in new archives anymore.
#define  LHD_COMMENT        0x0008U

// For non-file subheaders it denotes 'subblock having a parent file' flag.
#define  LHD_SOLID          0x0010U


#define  LHD_WINDOWMASK     0x00e0U
#define  LHD_WINDOW64       0x0000U
#define  LHD_WINDOW128      0x0020U
#define  LHD_WINDOW256      0x0040U
#define  LHD_WINDOW512      0x0060U
#define  LHD_WINDOW1024     0x0080U
#define  LHD_WINDOW2048     0x00a0U
#define  LHD_WINDOW4096     0x00c0U
#define  LHD_DIRECTORY      0x00e0U

#define  LHD_LARGE          0x0100U
#define  LHD_UNICODE        0x0200U
#define  LHD_SALT           0x0400U
#define  LHD_VERSION        0x0800U
#define  LHD_EXTTIME        0x1000U

#define  SKIP_IF_UNKNOWN    0x4000U
#define  LONG_BLOCK         0x8000U

#define  EARC_NEXT_VOLUME   0x0001U // Not last volume.
#define  EARC_DATACRC       0x0002U // Store CRC32 of RAR archive (now is used only in volumes).
#define  EARC_REVSPACE      0x0004U // Reserve space for end of REV file 7 byte record.
#define  EARC_VOLNUMBER     0x0008U // Store a number of current volume.

enum HEADER_TYPE {
  // RAR 5.0 header types.
  HEAD_MARK=0x00, HEAD_MAIN=0x01, HEAD_FILE=0x02, HEAD_SERVICE=0x03,
  HEAD_CRYPT=0x04, HEAD_ENDARC=0x05, HEAD_UNKNOWN=0xff,

  // RAR 1.5 - 4.x header types.
  HEAD3_MARK=0x72,HEAD3_MAIN=0x73,HEAD3_FILE=0x74,HEAD3_CMT=0x75,
  HEAD3_AV=0x76,HEAD3_OLDSERVICE=0x77,HEAD3_PROTECT=0x78,HEAD3_SIGN=0x79,
  HEAD3_SERVICE=0x7a,HEAD3_ENDARC=0x7b
};


// RAR 2.9 and earlier.
enum { EA_HEAD=0x100,UO_HEAD=0x101,MAC_HEAD=0x102,BEEA_HEAD=0x103,
       NTACL_HEAD=0x104,STREAM_HEAD=0x105 };


// Internal implementation, depends on archive format version.
enum HOST_SYSTEM {
  // RAR 5.0 host OS
  HOST5_WINDOWS=0,HOST5_UNIX=1,

  // RAR 3.0 host OS.
  HOST_MSDOS=0,HOST_OS2=1,HOST_WIN32=2,HOST_UNIX=3,HOST_MACOS=4,
  HOST_BEOS=5,HOST_MAX
};

// Unified archive format independent implementation.
enum HOST_SYSTEM_TYPE {
  HSYS_WINDOWS, HSYS_UNIX, HSYS_UNKNOWN
};


// We also use these values in extra field, so do not modify them.
enum FILE_SYSTEM_REDIRECT {
  FSREDIR_NONE=0, FSREDIR_UNIXSYMLINK, FSREDIR_WINSYMLINK, FSREDIR_JUNCTION,
  FSREDIR_HARDLINK, FSREDIR_FILECOPY
};


#define SUBHEAD_TYPE_CMT      L"CMT"
#define SUBHEAD_TYPE_QOPEN    L"QO"
#define SUBHEAD_TYPE_ACL      L"ACL"
#define SUBHEAD_TYPE_STREAM   L"STM"
#define SUBHEAD_TYPE_UOWNER   L"UOW"
#define SUBHEAD_TYPE_AV       L"AV"
#define SUBHEAD_TYPE_RR       L"RR"
#define SUBHEAD_TYPE_OS2EA    L"EA2"

/* new file inherits a subblock when updating a host file */
#define SUBHEAD_FLAGS_INHERITED    0x80000000

#define SUBHEAD_FLAGS_CMT_UNICODE  0x00000001


struct MarkHeader
{
  byte Mark[8];

  // Following fields are virtual and not present in real blocks.
  uint HeadSize;
};


struct BaseBlock
{
  uint HeadCRC;  // 'ushort' for RAR 1.5.
  HEADER_TYPE HeaderType; // 1 byte for RAR 1.5.
  uint Flags;    // 'ushort' for RAR 1.5.
  uint HeadSize; // 'ushort' for RAR 1.5, up to 2 MB for RAR 5.0.

  bool SkipIfUnknown;

  void Reset()
  {
    SkipIfUnknown=false;
  }
};


struct BlockHeader:BaseBlock
{
  uint DataSize;
};


struct MainHeader:BaseBlock
{
  ushort HighPosAV;
  uint PosAV;
  bool CommentInHeader;
  bool PackComment; // For RAR 1.4 archive format only.
  bool Locator;
  uint64 QOpenOffset;  // Offset of quick list record.
  uint64 QOpenMaxSize; // Maximum size of QOpen offset in locator extra field.
  uint64 RROffset;     // Offset of recovery record.
  uint64 RRMaxSize;    // Maximum size of RR offset in locator extra field.
  void Reset();
};


struct FileHeader:BlockHeader
{
  byte HostOS;
  uint UnpVer; // It is 1 byte in RAR29 and bit field in RAR5.
  byte Method;
  union {
    uint FileAttr;
    uint SubFlags;
  };
  wchar FileName[NM];

  Array<byte> SubData;

  RarTime mtime;
  RarTime ctime;
  RarTime atime;

  int64 PackSize;
  int64 UnpSize;
  int64 MaxSize; // Reserve packed and unpacked size bytes for vint of this size.

  HashValue FileHash;

  uint FileFlags;

  bool SplitBefore;
  bool SplitAfter;

  bool UnknownUnpSize;

  bool Encrypted;
  CRYPT_METHOD CryptMethod;
  bool SaltSet;
  byte Salt[SIZE_SALT50];
  byte InitV[SIZE_INITV];
  bool UsePswCheck;
  byte PswCheck[SIZE_PSWCHECK];

  // Use HMAC calculated from HashKey and checksum instead of plain checksum.
  bool UseHashKey;

  // Key to convert checksum to HMAC. Derived from password with PBKDF2
  // using additional iterations.
  byte HashKey[SHA256_DIGEST_SIZE];

  uint Lg2Count; // Log2 of PBKDF2 repetition count.

  bool Solid;
  bool Dir;
  bool CommentInHeader; // RAR 2.0 file comment.
  bool Version;   // name.ext;ver file name containing the version number.
  size_t WinSize;
  bool Inherited; // New file inherits a subblock when updating a host file (for subblocks only).

  // 'true' if file sizes use 8 bytes instead of 4. Not used in RAR 5.0.
  bool LargeFile;
  
  // 'true' for HEAD_SERVICE block, which is a child of preceding file block.
  // RAR 4.x uses 'solid' flag to indicate child subheader blocks in archives.
  bool SubBlock;

  HOST_SYSTEM_TYPE HSType;

  FILE_SYSTEM_REDIRECT RedirType;
  wchar RedirName[NM];
  bool DirTarget;

  bool UnixOwnerSet,UnixOwnerNumeric,UnixGroupNumeric;
  char UnixOwnerName[256],UnixGroupName[256];
#ifdef _UNIX
  uid_t UnixOwnerID;
  gid_t UnixGroupID;
#else // Need these Unix fields in Windows too for 'list' command.
  uint UnixOwnerID;
  uint UnixGroupID;
#endif

  void Reset(size_t SubDataSize=0);

  bool CmpName(const wchar *Name)
  {
    return(wcscmp(FileName,Name)==0);
  }

  FileHeader& operator = (FileHeader &hd);
};


struct EndArcHeader:BaseBlock
{
  // Optional CRC32 of entire archive up to start of EndArcHeader block.
  // Present in RAR 4.x archives if EARC_DATACRC flag is set.
  uint ArcDataCRC;  
  
  uint VolNumber; // Optional number of current volume.

  // 7 additional zero bytes can be stored here if EARC_REVSPACE is set.

  bool NextVolume; // Not last volume.
  bool DataCRC;
  bool RevSpace;
  bool StoreVolNumber;
  void Reset()
  {
    BaseBlock::Reset();
    NextVolume=false;
    DataCRC=false;
    RevSpace=false;
    StoreVolNumber=false;
  }
};


struct CryptHeader:BaseBlock
{
  bool UsePswCheck;
  uint Lg2Count; // Log2 of PBKDF2 repetition count.
  byte Salt[SIZE_SALT50];
  byte PswCheck[SIZE_PSWCHECK];
};


// SubBlockHeader and its successors were used in RAR 2.x format.
// RAR 4.x uses FileHeader with HEAD_SERVICE HeaderType for subblocks.
struct SubBlockHeader:BlockHeader
{
  ushort SubType;
  byte Level;
};


struct CommentHeader:BaseBlock
{
  ushort UnpSize;
  byte UnpVer;
  byte Method;
  ushort CommCRC;
};


struct ProtectHeader:BlockHeader
{
  byte Version;
  ushort RecSectors;
  uint TotalBlocks;
  byte Mark[8];
};


struct UnixOwnersHeader:SubBlockHeader
{
  ushort OwnerNameSize;
  ushort GroupNameSize;
/* dummy */
  char OwnerName[256];
  char GroupName[256];
};


struct EAHeader:SubBlockHeader
{
  uint UnpSize;
  byte UnpVer;
  byte Method;
  uint EACRC;
};


struct StreamHeader:SubBlockHeader
{
  uint UnpSize;
  byte UnpVer;
  byte Method;
  uint StreamCRC;
  ushort StreamNameSize;
  char StreamName[260];
};


#endif

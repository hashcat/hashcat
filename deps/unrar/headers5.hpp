#ifndef _RAR_HEADERS5_
#define _RAR_HEADERS5_

#define  SIZEOF_MARKHEAD5        8  // RAR 5.0 signature length.
#define  SIZEOF_SHORTBLOCKHEAD5  7  // Smallest RAR 5.0 block size.

// RAR 5.0 block flags common for all blocks.

// Additional extra area is present in the end of block header.
#define HFL_EXTRA           0x0001
// Additional data area is present in the end of block header.
#define HFL_DATA            0x0002
// Unknown blocks with this flag must be skipped when updating an archive.
#define HFL_SKIPIFUNKNOWN   0x0004
// Data area of this block is continuing from previous volume.
#define HFL_SPLITBEFORE     0x0008
// Data area of this block is continuing in next volume.
#define HFL_SPLITAFTER      0x0010
// Block depends on preceding file block.
#define HFL_CHILD           0x0020
// Preserve a child block if host is modified.
#define HFL_INHERITED       0x0040

// RAR 5.0 main archive header specific flags.
#define MHFL_VOLUME         0x0001 // Volume.
#define MHFL_VOLNUMBER      0x0002 // Volume number field is present. True for all volumes except first.
#define MHFL_SOLID          0x0004 // Solid archive.
#define MHFL_PROTECT        0x0008 // Recovery record is present.
#define MHFL_LOCK           0x0010 // Locked archive.

// RAR 5.0 file header specific flags.
#define FHFL_DIRECTORY      0x0001 // Directory.
#define FHFL_UTIME          0x0002 // Time field in Unix format is present.
#define FHFL_CRC32          0x0004 // CRC32 field is present.
#define FHFL_UNPUNKNOWN     0x0008 // Unknown unpacked size.

// RAR 5.0 end of archive header specific flags.
#define EHFL_NEXTVOLUME     0x0001 // Not last volume.

// RAR 5.0 archive encryption header specific flags.
#define CHFL_CRYPT_PSWCHECK 0x0001 // Password check data is present.


// RAR 5.0 file compression flags.
#define FCI_ALGO_BIT0       0x0001 // Version of compression algorithm.
#define FCI_ALGO_BIT1       0x0002 // 0 .. 63.
#define FCI_ALGO_BIT2       0x0004
#define FCI_ALGO_BIT3       0x0008
#define FCI_ALGO_BIT4       0x0010
#define FCI_ALGO_BIT5       0x0020
#define FCI_SOLID           0x0040 // Solid flag.
#define FCI_METHOD_BIT0     0x0080 // Compression method.
#define FCI_METHOD_BIT1     0x0100 // 0 .. 5 (6 and 7 are not used).
#define FCI_METHOD_BIT2     0x0200
#define FCI_DICT_BIT0       0x0400 // Dictionary size.
#define FCI_DICT_BIT1       0x0800 // 128 KB .. 4 GB.
#define FCI_DICT_BIT2       0x1000
#define FCI_DICT_BIT3       0x2000

// Main header extra field values.
#define MHEXTRA_LOCATOR       0x01 // Position of quick list and other blocks.

// Flags for MHEXTRA_LOCATOR.
#define MHEXTRA_LOCATOR_QLIST 0x01 // Quick open offset is present.
#define MHEXTRA_LOCATOR_RR    0x02 // Recovery record offset is present.

// File and service header extra field values.
#define FHEXTRA_CRYPT         0x01 // Encryption parameters.
#define FHEXTRA_HASH          0x02 // File hash.
#define FHEXTRA_HTIME         0x03 // High precision file time.
#define FHEXTRA_VERSION       0x04 // File version information.
#define FHEXTRA_REDIR         0x05 // File system redirection (links, etc.).
#define FHEXTRA_UOWNER        0x06 // Unix owner and group information.
#define FHEXTRA_SUBDATA       0x07 // Service header subdata array.


// Hash type values for FHEXTRA_HASH.
#define FHEXTRA_HASH_BLAKE2    0x00

// Flags for FHEXTRA_HTIME.
#define FHEXTRA_HTIME_UNIXTIME 0x01 // Use Unix time_t format.
#define FHEXTRA_HTIME_MTIME    0x02 // mtime is present.
#define FHEXTRA_HTIME_CTIME    0x04 // ctime is present.
#define FHEXTRA_HTIME_ATIME    0x08 // atime is present.
#define FHEXTRA_HTIME_UNIX_NS  0x10 // Unix format with nanosecond precision.

// Flags for FHEXTRA_CRYPT.
#define FHEXTRA_CRYPT_PSWCHECK 0x01 // Store password check data.
#define FHEXTRA_CRYPT_HASHMAC  0x02 // Use MAC for unpacked data checksums.

// Flags for FHEXTRA_REDIR.
#define FHEXTRA_REDIR_DIR      0x01 // Link target is directory.

// Flags for FHEXTRA_UOWNER.
#define FHEXTRA_UOWNER_UNAME   0x01 // User name string is present.
#define FHEXTRA_UOWNER_GNAME   0x02 // Group name string is present.
#define FHEXTRA_UOWNER_NUMUID  0x04 // Numeric user ID is present.
#define FHEXTRA_UOWNER_NUMGID  0x08 // Numeric group ID is present.

#endif

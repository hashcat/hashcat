#ifndef _RAR_COMPRESS_
#define _RAR_COMPRESS_

// Combine pack and unpack constants to class to avoid polluting global
// namespace with numerous short names.
class PackDef
{
  public:
    // Maximum LZ match length we can encode even for short distances.
    static const uint MAX_LZ_MATCH = 0x1001;

    // We increment LZ match length for longer distances, because shortest
    // matches are not allowed for them. Maximum length increment is 3
    // for distances larger than 256KB (0x40000). Here we define the maximum
    // incremented LZ match. Normally packer does not use it, but we must be
    // ready to process it in corrupt archives.
    static const uint MAX_INC_LZ_MATCH = MAX_LZ_MATCH + 3;

    static const uint MAX3_LZ_MATCH = 0x101; // Maximum match length for RAR v3.
    static const uint LOW_DIST_REP_COUNT = 16;

    static const uint NC    = 306; /* alphabet = {0, 1, 2, ..., NC - 1} */
    static const uint DC    = 64;
    static const uint LDC   = 16;
    static const uint RC    = 44;
    static const uint HUFF_TABLE_SIZE = NC + DC + RC + LDC;
    static const uint BC    = 20;

    static const uint NC30  = 299; /* alphabet = {0, 1, 2, ..., NC - 1} */
    static const uint DC30  = 60;
    static const uint LDC30 = 17;
    static const uint RC30  = 28;
    static const uint BC30  = 20;
    static const uint HUFF_TABLE_SIZE30 = NC30 + DC30 + RC30 + LDC30;

    static const uint NC20  = 298; /* alphabet = {0, 1, 2, ..., NC - 1} */
    static const uint DC20  = 48;
    static const uint RC20  = 28;
    static const uint BC20  = 19;
    static const uint MC20  = 257;

    // Largest alphabet size among all values listed above.
    static const uint LARGEST_TABLE_SIZE = 306;

    enum {
      CODE_HUFFMAN, CODE_LZ, CODE_REPEATLZ, CODE_CACHELZ, CODE_STARTFILE,
      CODE_ENDFILE, CODE_FILTER, CODE_FILTERDATA
    };
};


enum FilterType {
  // These values must not be changed, because we use them directly
  // in RAR5 compression and decompression code.
  FILTER_DELTA=0, FILTER_E8, FILTER_E8E9, FILTER_ARM, 
  FILTER_AUDIO, FILTER_RGB, FILTER_ITANIUM, FILTER_PPM, FILTER_NONE
};

#endif

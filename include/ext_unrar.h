/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_EXT_UNRAR_H
#define HC_EXT_UNRAR_H

// What hashcat asks UnRAR for on behalf of a hash line, next to what it asks the LZMA SDK and zlib
// for in ext_lzma.h and ext_zlib.h. One RAR3 block unpacked into a buffer the caller owns, which is
// the whole of what a module wants out of an archiver. The declaration was written out inside the
// one module that calls it and repeated at the definition, with nothing in between saying it was
// meant to be called from there at all.

#ifdef __cplusplus
extern "C" {
#endif

HC_PLUGIN_API unsigned int hc_decompress_rar (unsigned char *Win, unsigned char *Inp, unsigned char *VM, unsigned char *PPM, const unsigned int OutputSize, const unsigned char *Input, const unsigned int PackSize, const unsigned int UnpackSize, const unsigned char *Key, const unsigned char *IV, unsigned int *unpack_failed);

#ifdef __cplusplus
}
#endif

#endif // HC_EXT_UNRAR_H

#ifndef _RAR_SHA1_
#define _RAR_SHA1_

typedef struct {
    uint32 state[5];
    uint64 count;
    unsigned char buffer[64];
} sha1_context;

void sha1_init( sha1_context * c );
void sha1_process(sha1_context * c, const byte *data, size_t len);
void sha1_process_rar29(sha1_context *context, const unsigned char *data, size_t len);
void sha1_done( sha1_context * c, uint32 digest[5] );

#endif

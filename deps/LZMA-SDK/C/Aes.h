/* Aes.h -- AES encryption / decryption
2018-04-28 : Igor Pavlov : Public domain */

#ifndef __AES_H
#define __AES_H

#include "7zTypes.h"

EXTERN_C_BEGIN

#define AES_BLOCK_SIZE 16

/* Call AesGenTables one time before other AES functions */
void AesGenTables(void);

/* UInt32 pointers must be 16-byte aligned */

/* 16-byte (4 * 32-bit words) blocks: 1 (IV) + 1 (keyMode) + 15 (AES-256 roundKeys) */
#define AES_NUM_IVMRK_WORDS ((1 + 1 + 15) * 4)

/* aes - 16-byte aligned pointer to keyMode+roundKeys sequence */
/* keySize = 16 or 24 or 32 (bytes) */
typedef void (MY_FAST_CALL *AES_SET_KEY_FUNC)(UInt32 *aes, const Byte *key, unsigned keySize);
void MY_FAST_CALL Aes_SetKey_Enc(UInt32 *aes, const Byte *key, unsigned keySize);
void MY_FAST_CALL Aes_SetKey_Dec(UInt32 *aes, const Byte *key, unsigned keySize);

/* ivAes - 16-byte aligned pointer to iv+keyMode+roundKeys sequence: UInt32[AES_NUM_IVMRK_WORDS] */
void AesCbc_Init(UInt32 *ivAes, const Byte *iv); /* iv size is AES_BLOCK_SIZE */

/* data - 16-byte aligned pointer to data */
/* numBlocks - the number of 16-byte blocks in data array */
typedef void (MY_FAST_CALL *AES_CODE_FUNC)(UInt32 *ivAes, Byte *data, size_t numBlocks);

extern AES_CODE_FUNC g_AesCbc_Decode;
#ifndef _SFX
extern AES_CODE_FUNC g_AesCbc_Encode;
extern AES_CODE_FUNC g_AesCtr_Code;
#define k_Aes_SupportedFunctions_HW     (1 << 2)
#define k_Aes_SupportedFunctions_HW_256 (1 << 3)
extern UInt32 g_Aes_SupportedFunctions_Flags;
#endif


#define DECLARE__AES_CODE_FUNC(funcName) \
    void MY_FAST_CALL funcName(UInt32 *ivAes, Byte *data, size_t numBlocks);

DECLARE__AES_CODE_FUNC (AesCbc_Encode)
DECLARE__AES_CODE_FUNC (AesCbc_Decode)
DECLARE__AES_CODE_FUNC (AesCtr_Code)

DECLARE__AES_CODE_FUNC (AesCbc_Encode_HW)
DECLARE__AES_CODE_FUNC (AesCbc_Decode_HW)
DECLARE__AES_CODE_FUNC (AesCtr_Code_HW)

DECLARE__AES_CODE_FUNC (AesCbc_Decode_HW_256)
DECLARE__AES_CODE_FUNC (AesCtr_Code_HW_256)

EXTERN_C_END

#endif

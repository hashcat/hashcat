/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HCFPGA_IFACE_H
#define HCFPGA_IFACE_H

#include <stdint.h>

#define HCFPGA_EK_WORDS           18

#define HCFPGA_H2C_TAG            0xbc
#define HCFPGA_PW_MAX             72

#define HCFPGA_H2C_HDR_BYTES      8
#define HCFPGA_H2C_REC_BYTES_MAX  (HCFPGA_H2C_HDR_BYTES + HCFPGA_PW_MAX)

#define HCFPGA_H2C_REC_BYTES(len) (HCFPGA_H2C_HDR_BYTES + ((((len) + 3) / 4) * 4))

#define HCFPGA_C2H_REC_BYTES      32

#define HCFPGA_FLAG_OK            0x0000
#define HCFPGA_FLAG_CORE_ERR      0x0001

#define HCFPGA_FLAG_EOB           0x8000

#define HCFPGA_CMP_BITS           128
#define HCFPGA_CMP_WORDS          4

#define HCFPGA_CMP_INDEX(d0)      ((d0) & 0x7f)

typedef struct hcfpga_c2h_rec
{
  uint32_t ekid;

  uint8_t  digest[24];

  uint16_t core_id;
  uint16_t flags;

} hcfpga_c2h_rec_t;

static inline uint32_t hcfpga_h2c_put (void *buf, const uint32_t ekid, const uint8_t *pw, const uint32_t pw_len)
{
  uint32_t *w = (uint32_t *) buf;

  const uint32_t words = (pw_len + 3) / 4;

  w[0] = ((uint32_t) HCFPGA_H2C_TAG << 24) | pw_len;
  w[1] = ekid;

  for (uint32_t i = 0; i < words; i++)
  {
    uint32_t val = 0;

    for (uint32_t k = 0; k < 4; k++)
    {
      const uint32_t at = (i * 4) + k;

      const uint8_t c = (at < pw_len) ? pw[at] : 0;

      val = (val << 8) | c;
    }

    w[2 + i] = val;
  }

  const uint32_t result = HCFPGA_H2C_HDR_BYTES + (words * 4);

  return result;
}

#define HCFPGA_CSR_CTRL           0x00
#define HCFPGA_CSR_SALT0          0x04
#define HCFPGA_CSR_SALT1          0x08
#define HCFPGA_CSR_SALT2          0x0c
#define HCFPGA_CSR_SALT3          0x10
#define HCFPGA_CSR_ITER_COUNT     0x14
#define HCFPGA_CSR_STATUS         0x18
#define HCFPGA_CSR_CORE_COUNT     0x1c

#define HCFPGA_CSR_CMP_BM0        0x20
#define HCFPGA_CSR_CMP_BM1        0x24
#define HCFPGA_CSR_CMP_BM2        0x28
#define HCFPGA_CSR_CMP_BM3        0x2c

#define HCFPGA_CSR_BATCH_TARGET   0x30

#define HCFPGA_CSR_PAD_RECS       0x34

#define HCFPGA_CSR_RETIRED        0x38

#define HCFPGA_CTRL_FRAMING_RESET 0x00000001

#endif

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`ifndef HCFPGA_IFACE_VH
`define HCFPGA_IFACE_VH

`define HCFPGA_ZTEX_MARK_BYTES 8192

`define HCFPGA_H2C_TAG         8'hbc
`define HCFPGA_PW_MAX          72
`define HCFPGA_EK_WORDS        18

`define HCFPGA_C2H_REC_BYTES   32

`define HCFPGA_FLAG_OK         16'h0000
`define HCFPGA_FLAG_CORE_ERR   16'h0001

`define HCFPGA_FLAG_EOB        16'h8000

`define HCFPGA_CMP_BITS        128

`endif

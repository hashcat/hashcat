/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_ztex_regs #(
  parameter        NUM_CORES    = 24,
  parameter        CORE_CLK_MHZ = 100,

  parameter [31:0] BUILD_STAMP  = 32'd0,

  parameter [31:0] ABI_VERSION  = 32'd1
)(
  input  wire        clk,
  input  wire        rst,

  input  wire [7:0]  in_addr,
  input  wire [31:0] in_data,
  input  wire        in_strobe,
  input  wire [7:0]  out_addr,
  output reg  [31:0] out_data,
  input  wire        out_strobe,

  output reg  [31:0] salt0,
  output reg  [31:0] salt1,
  output reg  [31:0] salt2,
  output reg  [31:0] salt3,
  output reg  [31:0] iter_count,
  output wire        framing_reset,
  output wire        mode_dump,

  output reg  [127:0] cmp_bitmap,
  output reg  [31:0]  batch_target,
  output reg  [15:0]  pad_recs,

  output reg  [1:0]   cfg_kind,

  output reg         cfg_toggle,

  input  wire [31:0] frame_status,

  input  wire [31:0] die_temp,

  input  wire [31:0] dbg_in_words,
  input  wire [31:0] dbg_in_halves,
  input  wire [31:0] dbg_out_words,

  input  wire [31:0] dbg_flagb_low,
  input  wire [31:0] dbg_flagb_fall,
  input  wire [31:0] dbg_resend,

  input  wire [31:0] dbg_if_out_low,
  input  wire [31:0] dbg_arm,
  input  wire [31:0] dbg_pktend,
  input  wire [31:0] dbg_arm_wait
);

  `include "hcfpga_ztex_iface.vh"

  reg [31:0] ctrl;

  assign framing_reset = ctrl[`HCFPGA_ZTEX_CTRL_FRAMING_RESET];
  assign mode_dump     = ctrl[`HCFPGA_ZTEX_CTRL_MODE_DUMP];

  always @(posedge clk)
  begin
    if (rst == 1'b1)
    begin
      ctrl       <= 32'd1;
      salt0      <= 32'd0;
      salt1      <= 32'd0;
      salt2      <= 32'd0;
      salt3      <= 32'd0;
      iter_count <= 32'd0;
      cfg_toggle <= 1'b0;

      cmp_bitmap   <= {128{1'b1}};
      batch_target <= 32'd0;
      pad_recs     <= 16'd1;
      cfg_kind     <= 2'd0;
    end
    else if (in_strobe == 1'b1)
    begin
      cfg_toggle <= ~cfg_toggle;
      cfg_kind   <= `HCFPGA_ZTEX_KIND_PLAIN;

      case (in_addr)
        `HCFPGA_ZTEX_REG_CTRL:       ctrl       <= in_data;
        `HCFPGA_ZTEX_REG_SALT0:      salt0      <= in_data;
        `HCFPGA_ZTEX_REG_SALT1:      salt1      <= in_data;
        `HCFPGA_ZTEX_REG_SALT2:      salt2      <= in_data;
        `HCFPGA_ZTEX_REG_SALT3:      salt3      <= in_data;
        `HCFPGA_ZTEX_REG_ITER_COUNT: iter_count <= in_data;

        `HCFPGA_ZTEX_REG_CMP_BM0:    cmp_bitmap[ 31:  0] <= in_data;
        `HCFPGA_ZTEX_REG_CMP_BM1:    cmp_bitmap[ 63: 32] <= in_data;
        `HCFPGA_ZTEX_REG_CMP_BM2:    cmp_bitmap[ 95: 64] <= in_data;

        `HCFPGA_ZTEX_REG_CMP_BM3:
        begin
          cmp_bitmap[127: 96] <= in_data;
          cfg_kind            <= `HCFPGA_ZTEX_KIND_CMP_LOAD;
        end

        `HCFPGA_ZTEX_REG_BATCH_TARGET:
        begin
          batch_target <= in_data;
          cfg_kind     <= `HCFPGA_ZTEX_KIND_BATCH_ARM;
        end

        `HCFPGA_ZTEX_REG_PAD_RECS:   pad_recs <= in_data[15:0];

        default:                     ;
      endcase
    end
  end

  always @(posedge clk)
  begin
    if (out_strobe == 1'b1)
    begin
      case (out_addr)
        `HCFPGA_ZTEX_REG_CTRL:       out_data <= ctrl;
        `HCFPGA_ZTEX_REG_SALT0:      out_data <= salt0;
        `HCFPGA_ZTEX_REG_SALT1:      out_data <= salt1;
        `HCFPGA_ZTEX_REG_SALT2:      out_data <= salt2;
        `HCFPGA_ZTEX_REG_SALT3:      out_data <= salt3;
        `HCFPGA_ZTEX_REG_ITER_COUNT: out_data <= iter_count;

        `HCFPGA_ZTEX_REG_STATUS:     out_data <= frame_status;
        `HCFPGA_ZTEX_REG_CORE_COUNT: out_data <= NUM_CORES;

        `HCFPGA_ZTEX_REG_CMP_BM0:    out_data <= cmp_bitmap[ 31:  0];
        `HCFPGA_ZTEX_REG_CMP_BM1:    out_data <= cmp_bitmap[ 63: 32];
        `HCFPGA_ZTEX_REG_CMP_BM2:    out_data <= cmp_bitmap[ 95: 64];
        `HCFPGA_ZTEX_REG_CMP_BM3:    out_data <= cmp_bitmap[127: 96];

        `HCFPGA_ZTEX_REG_BATCH_TARGET: out_data <= batch_target;
        `HCFPGA_ZTEX_REG_PAD_RECS:     out_data <= { 16'd0, pad_recs };

        `HCFPGA_ZTEX_REG_MAGIC:      out_data <= `HCFPGA_ZTEX_MAGIC;
        `HCFPGA_ZTEX_REG_ABI:        out_data <= ABI_VERSION;
        `HCFPGA_ZTEX_REG_ALGO_LO:    out_data <= `HCFPGA_ZTEX_ALGO_LO;
        `HCFPGA_ZTEX_REG_ALGO_HI:    out_data <= `HCFPGA_ZTEX_ALGO_HI;
        `HCFPGA_ZTEX_REG_CLK_MHZ:    out_data <= CORE_CLK_MHZ;
        `HCFPGA_ZTEX_REG_BUILD:      out_data <= BUILD_STAMP;
        `HCFPGA_ZTEX_REG_TEMP:       out_data <= die_temp;

        `HCFPGA_ZTEX_REG_IN_WORDS:   out_data <= dbg_in_words;
        `HCFPGA_ZTEX_REG_IN_HALVES:  out_data <= dbg_in_halves;
        `HCFPGA_ZTEX_REG_OUT_WORDS:  out_data <= dbg_out_words;

        `HCFPGA_ZTEX_REG_FLAGB_LOW:  out_data <= dbg_flagb_low;
        `HCFPGA_ZTEX_REG_FLAGB_FALL: out_data <= dbg_flagb_fall;
        `HCFPGA_ZTEX_REG_RESEND:     out_data <= dbg_resend;

        `HCFPGA_ZTEX_REG_IF_OUT_LOW: out_data <= dbg_if_out_low;
        `HCFPGA_ZTEX_REG_ARM:        out_data <= dbg_arm;
        `HCFPGA_ZTEX_REG_PKTEND:     out_data <= dbg_pktend;
        `HCFPGA_ZTEX_REG_ARM_WAIT:   out_data <= dbg_arm_wait;

        default:                     out_data <= 32'd0;
      endcase
    end
  end

endmodule

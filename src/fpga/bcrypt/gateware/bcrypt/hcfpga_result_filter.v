/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_result_filter (
  input  wire CLK,
  input  wire rst,

  input  wire       bm_we,
  input  wire [6:0] bm_addr,
  input  wire       bm_din,

  input  wire core_empty,
  input  wire core_dout,
  output reg  core_rd_en = 0,

  input  wire f_rd_en,
  output reg  f_empty = 1,
  output reg  f_dout  = 0
);

  localparam integer IDX_LO = 64;

  localparam F_IDLE = 0, F_HDR = 1, F_CAP = 2, F_LOOK = 3, F_READY = 4,
             F_OUT_HDR = 5, F_OUT_ST = 6, F_OUT_DATA = 7;

  reg [2:0] state = F_IDLE;

  reg [8:0] bitcnt = 0;

  reg cd_r = 0;

  always @(posedge CLK)
    cd_r <= core_dout;

  reg [255:0] sr = 0;

  wire sr_shift = ((state == F_CAP) || (state == F_OUT_DATA));
  wire sr_in    = (state == F_CAP) ? cd_r : 1'b0;

  always @(posedge CLK)
  begin
    if (sr_shift == 1'b1) sr <= { sr[254:0], sr_in };
  end

  reg [6:0] idx = 0;

  reg bm [0:127];

  always @(posedge CLK)
  begin
    if (bm_we == 1'b1) bm[bm_addr] <= bm_din;
  end

  reg hit = 0;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      state      <= F_IDLE;
      bitcnt     <= 0;
      core_rd_en <= 0;
      f_empty    <= 1;
      f_dout     <= 0;
      hit        <= 0;
    end
    else
    begin
      core_rd_en <= 0;
      f_dout     <= 0;

      case (state)
      F_IDLE:
      begin
        f_empty <= 1;

        if (core_empty == 1'b0)
        begin
          core_rd_en <= 1;
          state      <= F_HDR;
        end
      end

      F_HDR:
      begin
        if (cd_r == 1'b1)
        begin
          bitcnt <= 0;
          state  <= F_CAP;
        end
      end

      F_CAP:
      begin
        if ((bitcnt >= IDX_LO) && (bitcnt <= (IDX_LO + 6))) idx <= { cd_r, idx[6:1] };

        if (bitcnt == 9'd255) state <= F_LOOK;

        bitcnt <= bitcnt + 1'b1;
      end

      F_LOOK:
      begin
        hit   <= bm[idx];
        state <= F_READY;
      end

      F_READY:
      begin
        f_empty <= 0;

        if (f_rd_en == 1'b1)
        begin
          f_empty <= 1;
          state   <= F_OUT_HDR;
        end
      end

      F_OUT_HDR:
      begin
        f_dout <= 1'b1;
        state  <= F_OUT_ST;
      end

      F_OUT_ST:
      begin
        f_dout <= hit;

        if (hit == 1'b1)
        begin
          bitcnt <= 0;
          state  <= F_OUT_DATA;
        end
        else
        begin
          state <= F_IDLE;
        end
      end

      F_OUT_DATA:
      begin
        f_dout <= sr[255];

        if (bitcnt == 9'd255) state <= F_IDLE;

        bitcnt <= bitcnt + 1'b1;
      end

      default:
      begin
        state <= F_IDLE;
      end

      endcase
    end
  end

endmodule

module hcfpga_cmp_bcast (
  input  wire         CLK,
  input  wire         rst,

  input  wire [127:0] bitmap,

  input  wire         load,

  output reg          bm_we   = 0,
  output reg  [6:0]   bm_addr = 0,
  output reg          bm_din  = 0
);

  reg [6:0] n = 0;

  reg walking = 0;
  reg ones    = 0;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      walking <= 1;
      ones    <= 1;
      n       <= 0;
      bm_we   <= 0;
      bm_addr <= 0;
      bm_din  <= 0;
    end
    else if (load == 1'b1)
    begin
      walking <= 1;
      ones    <= 0;
      n       <= 0;
      bm_we   <= 0;
    end
    else if (walking == 1'b1)
    begin
      bm_we   <= 1;
      bm_addr <= n;
      bm_din  <= (ones == 1'b1) ? 1'b1 : bitmap[n];

      n <= n + 1'b1;

      if (n == 7'd127) walking <= 1'b0;
    end
    else
    begin
      bm_we <= 0;
    end
  end

endmodule

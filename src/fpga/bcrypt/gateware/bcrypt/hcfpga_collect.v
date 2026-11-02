/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_collect #(
  parameter NUM_CORES = 4,

  parameter WITH_CMP = 1,

  parameter CORE_BASE = 0
)(
  input  wire CLK,
  input  wire rst,

  input  wire [NUM_CORES-1:0] core_empty,
  input  wire [NUM_CORES-1:0] core_dout,
  output reg  [NUM_CORES-1:0] core_rd_en = 0,

  output reg  retire = 0,

  output wire [7:0] m_data,
  output wire       m_valid,
  input  wire       m_ready,
  output wire       m_last
);

  localparam CW = (NUM_CORES <= 1) ? 1 : $clog2(NUM_CORES);

  localparam C_POLL = 0, C_RDEN = 1, C_WAIT_HDR = 2, C_STATUS = 3, C_CAPTURE = 4, C_BUILD = 5, C_EMIT = 6;

  reg [2:0]        state = C_POLL;
  reg [CW-1:0]     rd_core = 0;
  reg [8:0]        bitcnt = 0;
  reg [255:0]      cap = 0;

  reg dout_r = 0;
  always @(posedge CLK)
    dout_r <= core_dout[rd_core];

  reg [255:0] frame = 0;
  reg [5:0]   bytecnt = 0;
  reg         emitting = 0;

  assign m_data  = frame[7:0];
  assign m_valid = emitting;
  assign m_last  = emitting & (bytecnt == 6'd31);

  wire [31:0] ekid = { cap[16 +: 16], cap[0 +: 16] };

  wire [31:0] D0 = { cap[ 5*16 +: 16], cap[ 4*16 +: 16] };
  wire [31:0] D1 = { cap[ 7*16 +: 16], cap[ 6*16 +: 16] };
  wire [31:0] D2 = { cap[ 9*16 +: 16], cap[ 8*16 +: 16] };
  wire [31:0] D3 = { cap[11*16 +: 16], cap[10*16 +: 16] };
  wire [31:0] D4 = { cap[13*16 +: 16], cap[12*16 +: 16] };
  wire [31:0] D5 = { cap[15*16 +: 16], cap[14*16 +: 16] };

  wire [15:0] core_id = CORE_BASE[15:0] + rd_core;
  wire [15:0] flags   = 16'h0000;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      state     <= C_POLL;
      rd_core   <= 0;
      core_rd_en <= 0;
      bitcnt    <= 0;
      emitting  <= 0;
      bytecnt   <= 0;
      retire    <= 0;
    end
    else
    begin
      core_rd_en <= 0;
      retire     <= 0;

      case (state)
      C_POLL:
      begin
        if (core_empty[rd_core] == 1'b0)
          state <= C_RDEN;
        else
          rd_core <= (rd_core == NUM_CORES-1) ? {CW{1'b0}} : rd_core + 1'b1;
      end

      C_RDEN:
      begin
        core_rd_en[rd_core] <= 1;
        state <= C_WAIT_HDR;
      end

      C_WAIT_HDR:
      begin
        if (dout_r == 1'b1)
        begin
          bitcnt <= 0;
          state  <= (WITH_CMP != 0) ? C_STATUS : C_CAPTURE;
        end
      end

      C_STATUS:
      begin
        if (dout_r == 1'b1)
        begin
          state <= C_CAPTURE;
        end
        else
        begin
          retire  <= 1;
          rd_core <= (rd_core == NUM_CORES-1) ? {CW{1'b0}} : rd_core + 1'b1;
          state   <= C_POLL;
        end
      end

      C_CAPTURE:
      begin
        cap[bitcnt] <= dout_r;
        if (bitcnt == 9'd255)
          state <= C_BUILD;
        else
          bitcnt <= bitcnt + 1'b1;
      end

      C_BUILD:
      begin
        frame <= {
          flags[15:8],   flags[7:0],
          core_id[15:8], core_id[7:0],
          D5[7:0], D5[15:8], D5[23:16], D5[31:24],
          D4[7:0], D4[15:8], D4[23:16], D4[31:24],
          D3[7:0], D3[15:8], D3[23:16], D3[31:24],
          D2[7:0], D2[15:8], D2[23:16], D2[31:24],
          D1[7:0], D1[15:8], D1[23:16], D1[31:24],
          D0[7:0], D0[15:8], D0[23:16], D0[31:24],
          ekid[31:24], ekid[23:16], ekid[15:8], ekid[7:0]
        };
        bytecnt  <= 0;
        emitting <= 1;
        state    <= C_EMIT;
      end

      C_EMIT:
      begin
        if (m_ready == 1'b1)
        begin
          if (bytecnt == 6'd31)
          begin
            emitting <= 0;

            retire <= 1;

            rd_core <= (rd_core == NUM_CORES-1) ? {CW{1'b0}} : rd_core + 1'b1;
            state   <= C_POLL;
          end
          else
          begin
            frame   <= frame >> 8;
            bytecnt <= bytecnt + 1'b1;
          end
        end
      end

      endcase
    end
  end

endmodule

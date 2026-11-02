/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module ztex_fx2_model #(
  parameter integer OUT_BUF_WORDS  = 256,

  parameter integer OUT_BUFS       = 2,

  parameter integer FLAG_LATENCY   = 0,

  parameter integer FLAGA_LATENCY  = 0,
  parameter integer EMPTY_DRIVE    = 0,

  parameter integer HOST_DRAIN_CYC = 8,

  parameter integer Q_DEPTH        = 65536
)(
  input  wire        ifclk,

  inout  wire [15:0] fd,
  input  wire        SLWR,
  input  wire        SLRD,
  input  wire        SLOE,
  input  wire        FIFOADDR0,
  input  wire        FIFOADDR1,
  input  wire        PKTEND,
  output wire        FLAGA,
  output wire        FLAGB
);

  reg [15:0] h2c [0:Q_DEPTH-1];
  integer    over_read = 0;

  integer    h2c_wr = 0;
  integer    h2c_rd = 0;

  reg [15:0] c2h [0:Q_DEPTH-1];
  integer    c2h_wr     = 0;
  integer    c2h_commit = 0;
  integer    c2h_fill   = 0;

  integer    pktends    = 0;
  integer    zlps       = 0;
  integer    bad_addr   = 0;

  integer    dropped    = 0;

  parameter integer PKT_MAX = 4096;

  integer    pkt_len [0:PKT_MAX-1];
  integer    pkt_end [0:PKT_MAX-1];
  integer    pkt_cnt = 0;

  integer    committed = 0;
  integer    drain_cnt = 0;

  reg        host_stopped = 1'b0;

  integer    collected = 0;

  integer    flagb_low_cyc = 0;
  integer    max_committed = 0;

  wire h2c_avail = (h2c_rd < h2c_wr);

  reg [15:0] h2c_last = 16'd0;

  wire [15:0] h2c_empty_val = (EMPTY_DRIVE == 0) ? 16'hxxxx : h2c_last;

  assign fd = (SLOE == 1'b0) ? (h2c_avail ? h2c[h2c_rd] : h2c_empty_val) : 16'hzzzz;

  wire out_space = (committed < OUT_BUFS);

  reg [FLAG_LATENCY:0] flagb_pipe = { (FLAG_LATENCY+1) { 1'b1 } };

  reg [FLAGA_LATENCY:0] flaga_pipe = 0;

  assign FLAGA = (FLAGA_LATENCY == 0) ? h2c_avail : flaga_pipe[FLAGA_LATENCY];
  assign FLAGB = flagb_pipe[FLAG_LATENCY];

  always @(posedge ifclk)
  begin
    if (out_space == 1'b0) flagb_low_cyc = flagb_low_cyc + 1;

    if (committed > max_committed) max_committed = committed;

    if ((SLOE == 1'b1) && (SLWR == 1'b0))
    begin
      if ({ FIFOADDR1, FIFOADDR0 } !== 2'd0) bad_addr = bad_addr + 1;

      if (out_space == 1'b0)
      begin
        dropped = dropped + 1;
      end
      else
      begin
        c2h[c2h_wr] = fd;
        c2h_wr      = c2h_wr + 1;
        c2h_fill    = c2h_fill + 1;

        if (c2h_fill == OUT_BUF_WORDS)
        begin
          c2h_commit = c2h_wr;
          c2h_fill   = 0;
          committed  = committed + 1;

          if (pkt_cnt < PKT_MAX)
          begin
            pkt_len[pkt_cnt] = OUT_BUF_WORDS * 2;
            pkt_end[pkt_cnt] = 0;
          end

          pkt_cnt = pkt_cnt + 1;
        end
      end
    end

    if ((SLOE == 1'b1) && (PKTEND == 1'b0))
    begin
      pktends = pktends + 1;

      if (out_space == 1'b0)
      begin
        dropped = dropped + 1;
      end
      else
      begin
        if (pkt_cnt < PKT_MAX)
        begin
          pkt_len[pkt_cnt] = c2h_fill * 2;
          pkt_end[pkt_cnt] = 1;
        end

        pkt_cnt = pkt_cnt + 1;

        committed = committed + 1;

        if (c2h_fill == 0)
        begin
          zlps = zlps + 1;
        end
        else
        begin
          c2h_commit = c2h_wr;
          c2h_fill   = 0;
        end
      end
    end

    if ((SLOE == 1'b0) && (SLRD == 1'b0))
    begin
      if ({ FIFOADDR1, FIFOADDR0 } !== 2'd2) bad_addr = bad_addr + 1;

      if (h2c_avail == 1'b0) over_read = over_read + 1;

      if (h2c_avail == 1'b1)
      begin
        h2c_last = h2c[h2c_rd];

        h2c_rd <= h2c_rd + 1;
      end
    end

    flagb_pipe = (flagb_pipe << 1) | out_space;

    flaga_pipe = (flaga_pipe << 1) | h2c_avail;

    if (host_stopped == 1'b1)
    begin
      drain_cnt = 0;
    end
    else if (committed > 0)
    begin
      if (drain_cnt >= HOST_DRAIN_CYC)
      begin
        committed = committed - 1;
        drain_cnt = 0;
        collected = collected + 1;
      end
      else
      begin
        drain_cnt = drain_cnt + 1;
      end
    end
    else
    begin
      drain_cnt = 0;
    end
  end

endmodule

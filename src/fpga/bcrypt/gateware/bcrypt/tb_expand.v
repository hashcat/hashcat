/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module tb_expand;

  parameter integer FEED_GROUP = 0;
  parameter integer FEED_SHARD = 0;
  parameter integer WITH_DUMP  = 1;
  parameter integer WITH_CMP   = 1;
  parameter integer DIN_BITS   = 8;

  parameter integer NUM_CORES_DIST = 0;
  parameter integer INIT_BATCH     = 0;
  parameter integer COLLECT_GROUP  = 0;

  localparam NUM_CORES = 4;
  localparam NCAND     = 8;

  reg CLK = 0;
  always #5 CLK = ~CLK;
  reg rst = 1;

  reg  [31:0] s_data = 0;
  reg         s_valid = 0;
  wire        s_ready;

  wire [31:0] frame_status;

  wire [7:0]  m_data;
  wire        m_valid;
  reg         m_ready = 1;
  wire        m_last;

  hcfpga_top #(.NUM_CORES(NUM_CORES), .NUM_CORES_DIST(NUM_CORES_DIST), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS), .FEED_GROUP(FEED_GROUP), .FEED_SHARD(FEED_SHARD), .COLLECT_GROUP(COLLECT_GROUP), .WITH_DUMP(WITH_DUMP), .WITH_CMP(WITH_CMP)) dut (
    .CLK(CLK), .rst(rst), .mode_dump(1'b0),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(1'b0),
    .frame_status(frame_status),
    .salt0(32'h00010203), .salt1(32'h04050607), .salt2(32'h08090a0b), .salt3(32'h0c0d0e0f),
    .iter_count(32'd1),

    .cmp_bitmap({128{1'b1}}), .cmp_load(1'b0),
    .batch_target(32'd0), .batch_arm(1'b0), .pad_recs(16'd1), .retired_cnt(),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  reg [31:0] pwbuf [0:7][0:17];
  reg [7:0]  pwlen [0:7];
  reg [7:0]  gold  [0:7][0:23];

  integer i, j;

  initial begin
    for (i = 0; i < 8; i = i + 1)
    begin
      pwlen[i] = 0;

      for (j = 0; j < 18; j = j + 1) pwbuf[i][j] = 32'hdeadbeef;
    end
  end

  `include "tb_expand_vectors.vh"

  localparam [31:0] EKID_BASE = 32'h00000100;

  localparam [7:0] H2C_TAG = 8'hbc;

  task push_word (input [31:0] d);
    begin
      s_data <= d; s_valid <= 1;
      @(posedge CLK);
      while (s_ready !== 1'b1) @(posedge CLK);
      s_valid <= 0;
    end
  endtask

  task send_cand (input integer c);
    integer k, nw;
    begin
      nw = (pwlen[c] + 3) / 4;

      push_word ({H2C_TAG, 16'd0, pwlen[c]});
      push_word (EKID_BASE + c);

      for (k = 0; k < nw; k = k + 1) push_word (pwbuf[c][k]);
    end
  endtask

  reg [7:0]  rx [0:31];
  integer    rxpos = 0, nframe = 0, nbad = 0, idx, digok, kk;
  reg [31:0] r_ekid;
  reg [15:0] r_core;
  reg [NCAND-1:0] seen = 0;

  always @(posedge CLK)
  begin
    if (m_valid & m_ready)
    begin
      rx[rxpos] = m_data;
      if (rxpos == 31)
      begin
        rxpos = 0;
        r_ekid = { rx[3], rx[2], rx[1], rx[0] };
        r_core = { rx[29], rx[28] };
        idx = r_ekid - EKID_BASE;
        digok = 1;
        if (idx < 0 || idx >= NCAND) begin nbad=nbad+1; $display("[tb] frame %0d ekid=%08x OUT OF RANGE", nframe, r_ekid); end
        else begin
          for (kk=0; kk<24; kk=kk+1) if (rx[4+kk] !== gold[idx][kk]) digok = 0;
          if (seen[idx]) begin nbad=nbad+1; $display("[tb]   duplicate ekid %08x", r_ekid); end
          seen[idx] = 1;
          if (digok == 0) nbad = nbad + 1;
          $display("[tb] frame %0d: ekid=%08x -> cand%0d len=%0d core_id=%0d digest=%s",
                   nframe, r_ekid, idx, pwlen[idx], r_core, digok ? "OK" : "*** WRONG EXPANSION ***");
        end
        nframe = nframe + 1;
      end
      else rxpos = rxpos + 1;
    end
  end

  initial begin
    repeat (8) @(posedge CLK);
    rst = 0;
    repeat (4) @(posedge CLK);
    for (i=0; i<NCAND; i=i+1) send_cand(i);
    while (nframe < NCAND) @(posedge CLK);
    repeat (20) @(posedge CLK);
    $display("[tb] %0d frames, %0d bad, seen=%b, frame_status=%08x", nframe, nbad, seen, frame_status);

    if (frame_status[0] !== 1'b0) begin nbad = nbad + 1; $display("[tb] framing slip reported on a clean stream"); end

    if (nbad == 0 && seen == {NCAND{1'b1}})
      $display("[tb] OVERALL *** PASS *** expander: every length expands as the software reference does");
    else
      $display("[tb] OVERALL *** FAIL ***");
    $finish;
  end

  initial begin
    #20000000;
    $display("[tb] TIMEOUT %0d/%0d (seen=%b)", nframe, NCAND, seen);
    $finish;
  end

endmodule

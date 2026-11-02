/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module tb_feed_throughput;

  parameter integer FEED_GROUP = 0;
  parameter integer FEED_SHARD = 0;
  parameter integer WITH_DUMP  = 1;
  parameter integer WITH_CMP   = 1;
  parameter integer DIN_BITS   = 8;

  parameter integer NUM_CORES_DIST = 0;
  parameter integer INIT_BATCH     = 0;
  parameter integer COLLECT_GROUP  = 0;
  parameter integer NUM_CORES = 16;
  parameter integer ITERS     = 1;
  parameter integer MEASURE   = 200;
  parameter integer WARMUP    = 64;

  reg CLK = 0;
  always #5 CLK = ~CLK;
  reg rst = 1;

  reg  [31:0] s_data  = 0;
  reg         s_valid = 0;
  wire        s_ready;
  wire [7:0]  m_data;
  wire        m_valid;
  reg         m_ready = 1;
  wire        m_last;

  hcfpga_top #(.NUM_CORES(NUM_CORES), .NUM_CORES_DIST(NUM_CORES_DIST), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS), .FEED_GROUP(FEED_GROUP), .FEED_SHARD(FEED_SHARD), .COLLECT_GROUP(COLLECT_GROUP), .WITH_DUMP(WITH_DUMP), .WITH_CMP(WITH_CMP)) dut (
    .CLK(CLK), .rst(rst), .mode_dump(1'b0),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(1'b0),
    .frame_status(),
    .salt0(32'h00010203), .salt1(32'h04050607), .salt2(32'h08090a0b), .salt3(32'h0c0d0e0f),
    .iter_count(ITERS),

    .cmp_bitmap({128{1'b1}}), .cmp_load(1'b0),
    .batch_target(32'd0), .batch_arm(1'b0), .pad_recs(16'd1), .retired_cnt(),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  localparam integer PW_LEN_TEST = 72;
  localparam [7:0]   H2C_TAG     = 8'hbc;

  reg [31:0] pw [0:17];
  integer w;
  initial for (w = 0; w < 18; w = w + 1) pw[w] = 32'h63616e64 + w;

  task push_word (input [31:0] d);
    begin
      s_data <= d; s_valid <= 1;
      @(posedge CLK);
      while (s_ready !== 1'b1) @(posedge CLK);
      s_valid <= 0;
    end
  endtask

  integer sent = 0;

  task send_cand;
    integer k;
    begin
      push_word ({H2C_TAG, 16'd0, 8'd PW_LEN_TEST});
      push_word (32'h00000100 + sent);
      for (k = 0; k < ((PW_LEN_TEST + 3) / 4); k = k + 1) push_word (pw[k]);
      sent = sent + 1;
    end
  endtask

  integer rxpos = 0, nframe = 0;

  always @(posedge CLK)
  begin
    if (m_valid & m_ready)
    begin
      if (rxpos == 31) begin rxpos = 0; nframe = nframe + 1; end
      else rxpos = rxpos + 1;
    end
  end

  integer busy = 0, init_cyc = 0, data_cyc = 0, bcasts = 0, served = 0;
  integer t0 = 0, f0 = 0, measuring = 0;

  integer bcast_all = 0;

  reg  [1:0] prev_state = 0;

  localparam integer FCORES = (FEED_SHARD == 0) ? NUM_CORES : FEED_SHARD;

  generate
  if (FEED_SHARD == 0)
  begin : fi
    wire [1:0]         fstate = dut.feed.single.f.state;
    wire               fsrc   = dut.feed.single.f.src_init;
    wire               fcand  = dut.feed.single.f.cand_valid;
    wire [FCORES-1:0]  fwren  = dut.feed.single.f.c_wr_en_q;
  end
  else
  begin : fi
    wire [1:0]         fstate = dut.feed.sharded.eng[0].f.state;
    wire               fsrc   = dut.feed.sharded.eng[0].f.src_init;
    wire               fcand  = dut.feed.sharded.eng[0].f.cand_valid;
    wire [FCORES-1:0]  fwren  = dut.feed.sharded.eng[0].f.c_wr_en_q;
  end
  endgenerate

  wire [1:0] fstate = fi.fstate;
  wire       fsrc   = fi.fsrc;

  integer c;
  integer popc;

  integer init_q = 0, crypt_q = 0;
  integer qi, qc;

  integer idle_nocand = 0, idle_idle = 0;

  always @(posedge CLK)
  begin
    if ((fstate == 2'd1) && (prev_state != 2'd1) && fsrc) bcast_all = bcast_all + 1;

    if (measuring)
    begin
      if (fstate == 2'd1)
      begin
        busy = busy + 1;
        if (fsrc) init_cyc = init_cyc + 1;
        else      data_cyc = data_cyc + 1;
      end

      if (fstate == 2'd0)
      begin
        if ((|dut.cores.crypt_ready) && !fi.fcand) idle_nocand = idle_nocand + 1;
        else if (!(|dut.cores.crypt_ready) && !(|dut.cores.init_ready)) idle_idle = idle_idle + 1;
      end

      qi = 0; qc = 0;
      for (c = 0; c < NUM_CORES; c = c + 1)
      begin
        if (dut.cores.init_ready[c])  qi = qi + 1;
        if (dut.cores.crypt_ready[c]) qc = qc + 1;
      end
      init_q  = init_q  + qi;
      crypt_q = crypt_q + qc;

      if ((fstate == 2'd1) && (prev_state != 2'd1) && fsrc)
      begin
        bcasts = bcasts + 1;
        popc = 0;
        for (c = 0; c < FCORES; c = c + 1) if (fi.fwren[c]) popc = popc + 1;
        served = served + popc;
      end
    end
    prev_state <= fstate;
  end

  initial begin
    repeat (8) @(posedge CLK);
    rst = 0;
    repeat (4) @(posedge CLK);
    forever send_cand;
  end

  real cyc_per_frame;
  real util;
  real per_bcast;

  integer bmark;

  initial begin
    repeat (8) @(posedge CLK);

    while (nframe < WARMUP) @(posedge CLK);

    bmark = bcast_all;
    while (bcast_all == bmark) @(posedge CLK);

    t0 = $time / 10;
    f0 = nframe;
    measuring = 1;

    while (nframe < (WARMUP + MEASURE)) @(posedge CLK);

    bmark = bcast_all;
    while (bcast_all == bmark) @(posedge CLK);

    measuring = 0;

    cyc_per_frame = ($time / 10 - t0) * 1.0 / (nframe - f0);
    util          = busy * 100.0 / ($time / 10 - t0);
    per_bcast     = (bcasts > 0) ? (served * 1.0 / bcasts) : 0.0;

    $display ("");
    $display ("[tb] cores=%0d iters=%0d frames=%0d", NUM_CORES, ITERS, nframe - f0);
    $display ("[tb] cycles per candidate ....: %0.1f", cyc_per_frame);
    $display ("[tb] feeder utilisation ......: %0.1f %%", util);
    $display ("[tb]   of which init .........: %0.1f %%", init_cyc * 100.0 / ($time / 10 - t0));
    $display ("[tb]   of which data .........: %0.1f %%", data_cyc * 100.0 / ($time / 10 - t0));
    $display ("[tb] init broadcasts .........: %0d", bcasts);
    $display ("[tb] cores served per broadcast: %0.2f", per_bcast);
    $display ("[tb] avg cores waiting in init_ready .: %0.2f of %0d", init_q  * 1.0 / ($time/10 - t0), NUM_CORES);
    $display ("[tb] avg cores waiting in crypt_ready : %0.2f of %0d", crypt_q * 1.0 / ($time/10 - t0), NUM_CORES);
    $display ("[tb] D_CHECK idle, NO CANDIDATE .....: %0.1f %%  <- if high, the bench starves it", idle_nocand * 100.0 / ($time/10 - t0));
    $display ("[tb] D_CHECK idle, no work available : %0.1f %%", idle_idle * 100.0 / ($time/10 - t0));

    if (bcasts < 10)
    begin
      $display ("[tb] *** WINDOW TOO SHORT: only %0d broadcasts. Not a steady state, do NOT use this. ***", bcasts);
      $display ("[tb] *** raise MEASURE to at least %0d frames ***", 10 * ((per_bcast > 1.0) ? $rtoi(per_bcast) : 1));
    end

    $display ("");
    $finish;
  end

endmodule

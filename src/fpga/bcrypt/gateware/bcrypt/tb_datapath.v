/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module tb_datapath;

  parameter integer CSLOW = 1;

  parameter integer FEED_GROUP = 0;
  parameter integer FEED_SHARD = 0;
  parameter integer WITH_DUMP  = 1;
  parameter integer WITH_CMP   = 1;
  parameter integer DIN_BITS   = 8;

  parameter integer NUM_CORES_DIST = 0;
  parameter integer INIT_BATCH     = 0;
  parameter integer COLLECT_GROUP  = 0;

  parameter integer NUM_CORES = 4;
  parameter integer NCAND     = 8;

  parameter integer CHECK_ALL_CORES = 0;

  reg CLK = 0;
  always #5 CLK = ~CLK;

  reg CLK_CORE = 1;
  always #2.5 CLK_CORE = ~CLK_CORE;
  reg rst = 1;

  reg  [31:0] s_data = 0;
  reg         s_valid = 0;
  wire        s_ready;
  reg         s_last = 0;

  wire [31:0] frame_status;

  wire [7:0]  m_data;
  wire        m_valid;
  reg         m_ready = 1;
  wire        m_last;

  hcfpga_top #(.NUM_CORES(NUM_CORES), .NUM_CORES_DIST(NUM_CORES_DIST), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS), .FEED_GROUP(FEED_GROUP), .FEED_SHARD(FEED_SHARD), .COLLECT_GROUP(COLLECT_GROUP), .WITH_DUMP(WITH_DUMP), .WITH_CMP(WITH_CMP), .CSLOW(CSLOW)) dut (
    .CLK(CLK), .CLK_CORE(CLK_CORE), .rst(rst), .mode_dump(1'b0),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(frame_status),
    .salt0(32'h00010203), .salt1(32'h04050607), .salt2(32'h08090a0b), .salt3(32'h0c0d0e0f),
    .iter_count(32'd1),

    .cmp_bitmap({128{1'b1}}), .cmp_load(1'b0),
    .batch_target(32'd0), .batch_arm(1'b0), .pad_recs(16'd1), .retired_cnt(),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  reg [31:0] pw [0:1];
  integer i;
  initial begin
    pw[0]=32'h70617373; pw[1]=32'h776f7264;
  end

  localparam [7:0] PW_LEN  = 8'd8;
  localparam [7:0] H2C_TAG = 8'hbc;

  reg [7:0] gold [0:23];
  initial begin
    gold[ 0]=8'h60; gold[ 1]=8'hdd; gold[ 2]=8'h2b; gold[ 3]=8'ha5;
    gold[ 4]=8'h52; gold[ 5]=8'h48; gold[ 6]=8'hce; gold[ 7]=8'h07;
    gold[ 8]=8'hc3; gold[ 9]=8'h1f; gold[10]=8'ha6; gold[11]=8'h71;
    gold[12]=8'hb9; gold[13]=8'h26; gold[14]=8'hcd; gold[15]=8'he8;
    gold[16]=8'h83; gold[17]=8'h47; gold[18]=8'he5; gold[19]=8'hbb;
    gold[20]=8'hb5; gold[21]=8'h77; gold[22]=8'h02; gold[23]=8'h77;
  end

  localparam [31:0] EKID_BASE = 32'h00000100;

  task push_word (input [31:0] d, input last);
    begin
      s_data <= d; s_valid <= 1; s_last <= last;
      @(posedge CLK);
      while (s_ready !== 1'b1) @(posedge CLK);
      s_valid <= 0; s_last <= 0;
    end
  endtask

  task send_record (input [31:0] ekid);
    integer j;
    begin
      push_word({H2C_TAG, 16'd0, PW_LEN}, 1'b0);
      push_word(ekid, 1'b0);
      push_word(pw[0], 1'b0);
      push_word(pw[1], 1'b1);
    end
  endtask

  reg [7:0]  rx [0:31];
  integer    rxpos = 0;
  integer    nframe = 0;
  integer    nbad = 0;
  reg [NCAND-1:0] seen = 0;

  reg [31:0] r_ekid;
  reg [15:0] r_core;
  integer    idx, digok, kk;

  reg [NUM_CORES-1:0] core_seen = 0;

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
        digok = 1;
        for (kk=0; kk<24; kk=kk+1) if (rx[4+kk] !== gold[kk]) digok = 0;
        idx = r_ekid - EKID_BASE;
        $display("[tb] frame %0d: ekid=%08x core_id=%0d digest=%s", nframe, r_ekid, r_core,
                 digok ? "OK" : "BAD");
        if (digok == 0) nbad = nbad + 1;
        if (r_core >= NUM_CORES) begin nbad = nbad + 1; $display("[tb]   core_id out of range!"); end
        else core_seen[r_core] = 1;
        if (idx < 0 || idx >= NCAND) begin nbad = nbad + 1; $display("[tb]   ekid out of range!"); end
        else begin
          if (seen[idx]) begin nbad = nbad + 1; $display("[tb]   duplicate ekid!"); end
          seen[idx] = 1;
        end
        nframe = nframe + 1;
      end
      else
        rxpos = rxpos + 1;
    end
  end

  initial begin
    repeat (8) @(posedge CLK);
    rst = 0;
    repeat (4) @(posedge CLK);

    for (i=0; i<NCAND; i=i+1) send_record(EKID_BASE + i);

    while (nframe < NCAND) @(posedge CLK);
    repeat (20) @(posedge CLK);

    $display("[tb] collected %0d frames, %0d bad, seen=%b", nframe, nbad, seen);

    $display("[tb] cores of %0d that returned a frame: %b", NUM_CORES, core_seen);

    if (CHECK_ALL_CORES != 0)
    begin
      if (core_seen == {NUM_CORES{1'b1}})
        $display("[tb] COVERAGE *** PASS *** every core in the array returned a frame");
      else
        $display("[tb] COVERAGE *** FAIL *** some core never returned a frame, so it was never fed");
    end

    $display("[tb] frame_status=%08x  last_seen=%b frame_slip=%b slip_count=%0d",
             frame_status, frame_status[1], frame_status[0], frame_status[15:8]);

    if (frame_status[1] !== 1'b1)
      $display("[tb] FRAMING *** FAIL *** buffer-end marker never reached the feeder");
    else if (frame_status[0] !== 1'b0)
      $display("[tb] FRAMING *** FAIL *** %0d record headers arrived without their tag", frame_status[15:8]);
    else
      $display("[tb] FRAMING *** PASS *** every record header carried its tag");

    if (nbad == 0 && seen == {NCAND{1'b1}} && frame_status[1] === 1'b1 && frame_status[0] === 1'b0
        && ((CHECK_ALL_CORES == 0) || (core_seen == {NUM_CORES{1'b1}})))
      $display("[tb] OVERALL *** PASS *** datapath: framing + ekid echo + core_id + digest verified");
    else
      $display("[tb] OVERALL *** FAIL ***");
    $finish;
  end

  initial begin
    #20000000;
    $display("[tb] TIMEOUT: collected %0d/%0d frames (seen=%b)", nframe, NCAND, seen);
    $finish;
  end

endmodule

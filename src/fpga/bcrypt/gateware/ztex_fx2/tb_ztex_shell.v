/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
`include "hcfpga_ztex_iface.vh"

module tb_ztex_shell;

  parameter integer NUM_CORES      = 4;
  parameter integer NUM_CORES_DIST = 0;
  parameter integer DIN_BITS       = 32;
  parameter integer FEED_GROUP     = 0;
  parameter integer COLLECT_GROUP  = 0;
  parameter integer WITH_DUMP      = 1;

  parameter integer CORE_CLK_MHZ      = 100;
  parameter integer MMCM_DIVCLK       = 1;
  parameter integer MMCM_MULT_MILLI   = 18750;
  parameter integer MMCM_OUTDIV_MILLI = 9000;

  parameter integer H2C_BLOCK_BYTES = 64;

  parameter integer NCAND = 8;

  parameter integer OUT_BUFS       = 2;
  parameter integer HOST_DRAIN_CYC = 8;
  parameter integer FLAG_LATENCY   = 2;

  parameter integer FLAGA_LATENCY  = 0;
  parameter integer EMPTY_DRIVE    = 0;

  parameter integer HOST_STOP_AT  = 0;
  parameter integer HOST_STOP_CYC = 0;

  parameter integer FEED_BURST   = 0;
  parameter integer FEED_GAP_CYC = 0;

  parameter integer TIMEOUT_NS = 40000000;

  reg fxclk_in = 1'b0;
  reg ifclk_in = 1'b0;

  always #10.416 fxclk_in = ~fxclk_in;
  always #10.417 ifclk_in = ~ifclk_in;

  reg reset = 1'b1;

  wire [15:0] fd;
  wire        SLWR;
  wire        SLRD;
  wire        SLOE;
  wire        FIFOADDR0;
  wire        FIFOADDR1;
  wire        PKTEND;
  wire        FLAGA;
  wire        FLAGB;

  reg  lsi_clk  = 1'b0;
  reg  lsi_mosi = 1'b0;
  reg  lsi_stop = 1'b0;
  wire lsi_miso;

  hcfpga_ztex_top #(
    .NUM_CORES(NUM_CORES),
    .NUM_CORES_DIST(NUM_CORES_DIST),
    .INIT_BATCH(0),
    .DIN_BITS(DIN_BITS),
    .FEED_GROUP(FEED_GROUP),
    .COLLECT_GROUP(COLLECT_GROUP),
    .WITH_DUMP(WITH_DUMP),
    .CORE_CLK_MHZ(CORE_CLK_MHZ),
    .MMCM_DIVCLK(MMCM_DIVCLK),
    .MMCM_MULT_MILLI(MMCM_MULT_MILLI),
    .MMCM_OUTDIV_MILLI(MMCM_OUTDIV_MILLI),
    .BUILD_STAMP(32'h68a0_0000),
    .H2C_BLOCK_BYTES(H2C_BLOCK_BYTES)
  ) dut (
    .fxclk_in(fxclk_in),
    .ifclk_in(ifclk_in),
    .reset(reset),

    .fd(fd),
    .SLWR(SLWR),
    .SLRD(SLRD),
    .SLOE(SLOE),
    .FIFOADDR0(FIFOADDR0),
    .FIFOADDR1(FIFOADDR1),
    .PKTEND(PKTEND),
    .FLAGA(FLAGA),
    .FLAGB(FLAGB),

    .lsi_clk(lsi_clk),
    .lsi_mosi(lsi_mosi),
    .lsi_miso(lsi_miso),
    .lsi_stop(lsi_stop)
  );

  ztex_fx2_model #(
    .OUT_BUFS(OUT_BUFS),
    .HOST_DRAIN_CYC(HOST_DRAIN_CYC),
    .FLAG_LATENCY(FLAG_LATENCY),
    .FLAGA_LATENCY(FLAGA_LATENCY),
    .EMPTY_DRIVE(EMPTY_DRIVE)
  ) fx2 (
    .ifclk(dut.ifclk),
    .fd(fd),
    .SLWR(SLWR),
    .SLRD(SLRD),
    .SLOE(SLOE),
    .FIFOADDR0(FIFOADDR0),
    .FIFOADDR1(FIFOADDR1),
    .PKTEND(PKTEND),
    .FLAGA(FLAGA),
    .FLAGB(FLAGB)
  );

  localparam integer LSI_DIV = 8;

  task lsi_edge (input mosi_val);
    integer k;
  begin
    lsi_mosi = mosi_val;

    for (k = 0; k < LSI_DIV; k = k + 1) @(posedge dut.ifclk);

    lsi_clk = ~lsi_clk;

    for (k = 0; k < LSI_DIV; k = k + 1) @(posedge dut.ifclk);
  end
  endtask

  task lsi_write (input [7:0] addr, input [31:0] data);
    integer k;
  begin
    lsi_stop = 1'b0;

    for (k = 0; k < 32; k = k + 1) lsi_edge (data[k]);
    for (k = 0; k <  8; k = k + 1) lsi_edge (addr[k]);

    lsi_stop = 1'b1;

    lsi_edge (1'b0);

    lsi_stop = 1'b0;

    lsi_edge (1'b0);
  end
  endtask

  reg [31:0] lsi_rx;

  task lsi_read (input [7:0] addr);
    integer k;
  begin
    lsi_stop = 1'b0;

    for (k = 0; k < 8; k = k + 1) lsi_edge (addr[k]);

    lsi_stop = 1'b1;

    lsi_edge (1'b1);

    for (k = 0; k < 32; k = k + 1)
    begin
      lsi_rx[k] = lsi_miso;

      lsi_edge (1'b1);
    end

    lsi_stop = 1'b0;

    lsi_edge (1'b0);
  end
  endtask

  localparam [7:0] PW_LEN  = 8'd8;
  localparam [7:0] H2C_TAG = 8'hbc;

  reg [31:0] pw [0:1];

  initial
  begin
    pw[0]=32'h70617373; pw[1]=32'h776f7264;
  end

  reg [7:0] gold [0:23];

  initial
  begin
    gold[ 0]=8'h60; gold[ 1]=8'hdd; gold[ 2]=8'h2b; gold[ 3]=8'ha5;
    gold[ 4]=8'h52; gold[ 5]=8'h48; gold[ 6]=8'hce; gold[ 7]=8'h07;
    gold[ 8]=8'hc3; gold[ 9]=8'h1f; gold[10]=8'ha6; gold[11]=8'h71;
    gold[12]=8'hb9; gold[13]=8'h26; gold[14]=8'hcd; gold[15]=8'he8;
    gold[16]=8'h83; gold[17]=8'h47; gold[18]=8'he5; gold[19]=8'hbb;
    gold[20]=8'hb5; gold[21]=8'h77; gold[22]=8'h02; gold[23]=8'h77;
  end

  localparam [31:0] EKID_BASE = 32'h00000100;

  task push_h2c (input [15:0] w);
  begin
    fx2.h2c[fx2.h2c_wr] = w;
    fx2.h2c_wr          = fx2.h2c_wr + 1;
  end
  endtask

  task send_record (input [31:0] ekid);
    integer j;

    reg [31:0] hdr;
  begin
    hdr = {H2C_TAG, 16'd0, PW_LEN};

    push_h2c (hdr[15:0]);
    push_h2c (hdr[31:16]);

    push_h2c (ekid[15:0]);
    push_h2c (ekid[31:16]);

    for (j = 0; j < ((PW_LEN + 3) / 4); j = j + 1)
    begin
      push_h2c (pw[j][15:0]);
      push_h2c (pw[j][31:16]);
    end
  end
  endtask

  integer nframe = 0;
  integer nbad   = 0;

  reg [NCAND-1:0] seen = 0;

  reg [7:0]  rx [0:31];
  reg [31:0] r_ekid;
  reg [15:0] r_core;
  reg [15:0] r_flags;

  integer taken = 0;
  integer digok;
  integer idx;
  integer kk;
  integer bytepos;

  reg [15:0] w;

  task drain;
    integer j;
  begin
    while (taken < fx2.c2h_commit)
    begin
      w = fx2.c2h[taken];

      taken = taken + 1;

      bytepos = ((taken - 1) * 2) % 32;

      rx[bytepos + 0] = w[7:0];
      rx[bytepos + 1] = w[15:8];

      if (bytepos == 30)
      begin
        r_ekid  = { rx[3],  rx[2],  rx[1],  rx[0]  };
        r_core  = { rx[29], rx[28] };
        r_flags = { rx[31], rx[30] };

        digok = 1;

        for (kk = 0; kk < 24; kk = kk + 1) if (rx[4 + kk] !== gold[kk]) digok = 0;

        idx = r_ekid - EKID_BASE;

        $display ("[tb] frame %0d: ekid=%08x core_id=%0d flags=%04x digest=%s", nframe, r_ekid, r_core, r_flags, digok ? "OK" : "BAD");

        if (digok == 0)         begin nbad = nbad + 1; end
        if (r_core >= NUM_CORES) begin nbad = nbad + 1; $display ("[tb]   core_id out of range!"); end

        if ((idx < 0) || (idx >= NCAND))
        begin
          nbad = nbad + 1;

          $display ("[tb]   ekid out of range!");
        end
        else
        begin
          if (seen[idx]) begin nbad = nbad + 1; $display ("[tb]   duplicate ekid!"); end

          seen[idx] = 1;
        end

        nframe = nframe + 1;
      end
    end
  end
  endtask

  integer p;
  integer pkt_bytes = 0;

  task show_packets;
  begin
    pkt_bytes = 0;

    $write ("[tb] packets a host would have read:");

    for (p = 0; (p < fx2.pkt_cnt) && (p < fx2.PKT_MAX); p = p + 1)
    begin
      $write (" %0d%s", fx2.pkt_len[p], (fx2.pkt_end[p] != 0) ? "s" : "");

      pkt_bytes = pkt_bytes + fx2.pkt_len[p];
    end

    $write ("\n");

    $display ("[tb] %0d packets, %0d bytes, %0d of them short. Wanted %0d bytes in %0d frames.", fx2.pkt_cnt, pkt_bytes, fx2.pktends, NCAND * 32, NCAND);

    $display ("[tb] fx2: %0d words written with no buffer to take them, %0d words still unsent", fx2.dropped, fx2.c2h_fill);
    $display ("[tb] fx2: FLAGB low for %0d cycles, deepest %0d of %0d buffers committed, host took %0d", fx2.flagb_low_cyc, fx2.max_committed, OUT_BUFS, fx2.collected);
  end
  endtask

  reg feed_go = 1'b0;

  integer f;
  integer g;

  initial
  begin
    wait (feed_go == 1'b1);

    if (FEED_BURST == 0)
    begin
      for (f = 0; f < NCAND; f = f + 1) send_record (EKID_BASE + f);
    end
    else
    begin
      for (f = 0; f < NCAND; f = f + 1)
      begin
        send_record (EKID_BASE + f);

        if (((f + 1) % FEED_BURST) == 0)
        begin
          for (g = 0; g < FEED_GAP_CYC; g = g + 1) @(posedge dut.ifclk);
        end
      end
    end
  end

  task show_pktend_state;
  begin
    $display ("[tb] pktend gate: SLWR=%b resend=%b DI_valid=%b FULL_FLAG=%b if_out=%b if_out_buf4=%b",
              dut.io.SLWR, dut.io.resend, dut.usb_di_valid, FLAGB, dut.io.if_out, dut.io.if_out_buf[4]);

    $display ("[tb] pktend arm : shell dirty=%b arm=%b idle=%0d   io arm_buf=%b auto=%b cnt=%0d",
              dut.pktend_dirty, dut.pktend_arm, dut.pktend_idle, dut.io.pktend_arm_buf, dut.io.pktend_auto, dut.io.pktend_cnt);

    $display ("[tb] fx2 state  : committed=%0d of %0d buffers, fill=%0d words, host_stopped=%b",
              fx2.committed, OUT_BUFS, fx2.c2h_fill, fx2.host_stopped);

    $display ("[tb] flagb regs : low=%0d falls=%0d resends=%0d   (model: low=%0d, dropped=%0d)",
              dut.dbg_flagb_low, dut.dbg_flagb_fall, dut.dbg_resend, fx2.flagb_low_cyc, fx2.dropped);

    $display ("[tb] flush regs : if_out_low=%0d arms=%0d pktends=%0d arm_wait=%0d   (model saw %0d short packets)",
              dut.dbg_if_out_low, dut.dbg_arm, dut.dbg_pktend, dut.dbg_arm_wait, fx2.pktends);
  end
  endtask

  initial
  begin
    if (HOST_STOP_AT > 0)
    begin
      wait (fx2.collected >= HOST_STOP_AT);

      $display ("[tb] %0t host stops collecting after %0d buffers", $time, fx2.collected);

      fx2.host_stopped = 1'b1;

      repeat (HOST_STOP_CYC) @(posedge dut.ifclk);

      $display ("[tb] %0t host starts collecting again", $time);

      fx2.host_stopped = 1'b0;
    end
  end

  integer i;
  integer ident_bad = 0;
  integer waited    = 0;

  reg [31:0] status_read;

  reg [31:0] flagb_low;
  reg [31:0] flagb_fall;
  reg [31:0] resends;

  reg [31:0] if_out_low;
  reg [31:0] arms;
  reg [31:0] pktends_reg;
  reg [31:0] arm_wait;

  initial
  begin
    repeat (64) @(posedge ifclk_in);

    reset = 1'b0;

    repeat (200) @(posedge dut.ifclk);

    lsi_read (8'h10);
    if (lsi_rx !== 32'h68636667) begin ident_bad = ident_bad + 1; $display ("[tb] MAGIC   read %08x, want 68636667", lsi_rx); end

    lsi_read (8'h11);
    if (lsi_rx !== 32'd1) begin ident_bad = ident_bad + 1; $display ("[tb] ABI     read %08x, want 1", lsi_rx); end

    lsi_read (8'h12);
    if (lsi_rx !== 32'h79726362) begin ident_bad = ident_bad + 1; $display ("[tb] ALGO_LO read %08x, want 79726362", lsi_rx); end

    lsi_read (8'h13);
    if (lsi_rx !== 32'h00007470) begin ident_bad = ident_bad + 1; $display ("[tb] ALGO_HI read %08x, want 00007470", lsi_rx); end

    lsi_read (8'h07);
    if (lsi_rx !== NUM_CORES) begin ident_bad = ident_bad + 1; $display ("[tb] CORES   read %08x, want %0d", lsi_rx, NUM_CORES); end

    lsi_read (8'h14);
    if (lsi_rx !== CORE_CLK_MHZ) begin ident_bad = ident_bad + 1; $display ("[tb] CLK     read %08x, want %0d", lsi_rx, CORE_CLK_MHZ); end

    lsi_read (8'h15);
    if (lsi_rx !== 32'h68a0_0000) begin ident_bad = ident_bad + 1; $display ("[tb] BUILD   read %08x, want 68a00000", lsi_rx); end

    lsi_read (8'h16);
    if (lsi_rx !== 32'h8000_09a0) begin ident_bad = ident_bad + 1; $display ("[tb] TEMP    read %08x, want 800009a0", lsi_rx); end

    if (ident_bad == 0) $display ("[tb] IDENT *** PASS *** magic, abi, algo, cores, clk, build and temperature all read back");

    lsi_write (8'h01, 32'h00010203);
    lsi_write (8'h02, 32'h04050607);
    lsi_write (8'h03, 32'h08090a0b);
    lsi_write (8'h04, 32'h0c0d0e0f);
    lsi_write (8'h05, 32'd1);

    lsi_read (8'h01);
    if (lsi_rx !== 32'h00010203) begin ident_bad = ident_bad + 1; $display ("[tb] SALT0 read back %08x", lsi_rx); end

    lsi_write (8'h00, 32'd0);

    repeat (200) @(posedge dut.clk_core);

    feed_go = 1'b1;

    while ((nframe < NCAND) && (waited < (TIMEOUT_NS / 21)))
    begin
      @(negedge dut.ifclk);

      waited = waited + 1;

      drain;
    end

    repeat (2000) @(negedge dut.ifclk);

    drain;

    $display ("[tb] collected %0d frames, %0d bad, seen=%b", nframe, nbad, seen);
    $display ("[tb] fx2: %0d short packets of which %0d empty, %0d wrong endpoint selections", fx2.pktends, fx2.zlps, fx2.bad_addr);

    $display ("[tb] fx2: %0d over reads, words taken while the inbound queue was empty", fx2.over_read);
    $display ("[tb] h2c: host wrote %0d half words, shell accepted %0d, slip_count %0d", fx2.h2c_wr, dut.dbg_in_halves, dut.frame_status_core[15:8]);
    show_packets;

    if (fx2.dropped > 0) $display ("[tb] the FULL_FLAG shadow was entered %0d times and every word came back", fx2.dropped);

    if (fx2.c2h_fill != 0)
    begin
      nbad = nbad + 1;

      $display ("[tb] FLUSH *** FAIL *** %0d bytes are still in the microcontroller's partial buffer", fx2.c2h_fill * 2);

      show_pktend_state;
    end

    if (fx2.pktends == 0) begin nbad = nbad + 1; $display ("[tb] FLUSH *** FAIL *** no buffer flush occurred"); end

    lsi_read (`HCFPGA_ZTEX_REG_FLAGB_LOW);
    flagb_low = lsi_rx;

    lsi_read (`HCFPGA_ZTEX_REG_FLAGB_FALL);
    flagb_fall = lsi_rx;

    lsi_read (`HCFPGA_ZTEX_REG_RESEND);
    resends = lsi_rx;

    $display ("[tb] flagb: low for %0d cycles, %0d falls, %0d resends", flagb_low, flagb_fall, resends);

    lsi_read (`HCFPGA_ZTEX_REG_IF_OUT_LOW);
    if_out_low = lsi_rx;

    lsi_read (`HCFPGA_ZTEX_REG_ARM);
    arms = lsi_rx;

    lsi_read (`HCFPGA_ZTEX_REG_PKTEND);
    pktends_reg = lsi_rx;

    lsi_read (`HCFPGA_ZTEX_REG_ARM_WAIT);
    arm_wait = lsi_rx;

    $display ("[tb] flush: if_out low %0d cycles, %0d arms, %0d pktends, %0d cycles waiting", if_out_low, arms, pktends_reg, arm_wait);

    if (pktends_reg !== fx2.pktends)
    begin
      nbad = nbad + 1;

      $display ("[tb] FLUSH *** FAIL *** the shell counted %0d flushes and the microcontroller saw %0d", pktends_reg, fx2.pktends);
    end

    if (arms > pktends_reg)
    begin
      nbad = nbad + 1;

      $display ("[tb] FLUSH *** FAIL *** %0d flushes were asked for and only %0d happened", arms, pktends_reg);
    end

    if ((fx2.flagb_low_cyc > 0) && (flagb_low == 0))
    begin
      nbad = nbad + 1;

      $display ("[tb] FLAGB *** FAIL *** the model held FLAGB low for %0d cycles and the shell counted none", fx2.flagb_low_cyc);
    end

    lsi_read (8'h06);

    status_read = lsi_rx;

    $display ("[tb] frame_status=%08x  last_seen=%b frame_slip=%b slip_count=%0d", status_read, status_read[1], status_read[0], status_read[15:8]);

    if (status_read[1] !== 1'b1)
      $display ("[tb] FRAMING *** FAIL *** the shell's buffer end marker never reached the feeder");
    else if (status_read[0] !== 1'b0)
      $display ("[tb] FRAMING *** FAIL *** %0d record headers arrived without their tag", status_read[15:8]);
    else
      $display ("[tb] FRAMING *** PASS *** every record header carried its tag");

    if (dut.dbg_in_halves != fx2.h2c_wr)
      $display ("[tb] H2C *** FAIL *** the shell took %0d half words, the host wrote %0d", dut.dbg_in_halves, fx2.h2c_wr);

    if ((nbad == 0) && (ident_bad == 0) && (seen == {NCAND{1'b1}}) && (fx2.bad_addr == 0) && (status_read[1] === 1'b1) && (status_read[0] === 1'b0) && (dut.dbg_in_halves == fx2.h2c_wr))
      $display ("[tb] OVERALL *** PASS *** ztex shell: lsi registers + width conversion + cdc + framing + flush + digest verified");
    else
      $display ("[tb] OVERALL *** FAIL ***");

    $finish;
  end

  initial
  begin
    #TIMEOUT_NS;

    show_packets;
    show_pktend_state;

    $display ("[tb] TIMEOUT: collected %0d/%0d frames (seen=%b)", nframe, NCAND, seen);
    $display ("[tb] OVERALL *** FAIL ***");

    $finish;
  end

endmodule

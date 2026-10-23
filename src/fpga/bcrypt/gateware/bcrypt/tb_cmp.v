/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module tb_cmp;

  parameter integer CSLOW = 1;

  parameter integer FEED_GROUP = 0;
  parameter integer FEED_SHARD = 0;
  parameter integer WITH_DUMP  = 1;
  parameter integer WITH_CMP   = 1;
  parameter integer DIN_BITS   = 8;

  parameter integer NUM_CORES_DIST = 0;
  parameter integer INIT_BATCH     = 0;
  parameter integer COLLECT_GROUP  = 0;

  parameter integer CMP_ALL = 0;

  parameter integer PAD_RECS = 4;

  parameter integer READY_DUTY = 0;

  localparam NUM_CORES = 4;
  localparam NCAND     = 8;

  localparam [15:0] PAD_RECS_W = PAD_RECS;

  reg CLK = 0;
  always #5 CLK = ~CLK;

  reg CLK_CORE = 1;
  always #2.5 CLK_CORE = ~CLK_CORE;
  reg rst = 1;

  reg  [31:0] s_data = 0;
  reg         s_valid = 0;
  wire        s_ready;
  wire [7:0]  m_data;
  wire        m_valid;
  reg         m_ready = 1;
  wire        m_last;

  reg [15:0]  ready_lfsr = 16'hace1;

  always @(posedge CLK)
  begin
    ready_lfsr <= { ready_lfsr[14:0], ready_lfsr[15] ^ ready_lfsr[13] ^ ready_lfsr[12] ^ ready_lfsr[10] };

    if (READY_DUTY != 0) m_ready <= (ready_lfsr[2:0] < READY_DUTY);
  end

  reg [127:0] cmp_bitmap = {128{1'b1}};
  reg         cmp_load   = 0;
  reg [31:0]  batch_target = 0;
  reg         batch_arm    = 0;

  wire [31:0] retired_cnt;

  hcfpga_top #(.NUM_CORES(NUM_CORES), .NUM_CORES_DIST(NUM_CORES_DIST), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS), .FEED_GROUP(FEED_GROUP), .FEED_SHARD(FEED_SHARD), .COLLECT_GROUP(COLLECT_GROUP), .WITH_DUMP(WITH_DUMP), .WITH_CMP(WITH_CMP), .CSLOW(CSLOW)) dut (
    .CLK(CLK), .CLK_CORE(CLK_CORE), .rst(rst), .mode_dump(1'b0),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(1'b0),
    .frame_status(),
    .salt0(32'h00010203), .salt1(32'h04050607), .salt2(32'h08090a0b), .salt3(32'h0c0d0e0f),
    .iter_count(32'd1),
    .cmp_bitmap(cmp_bitmap), .cmp_load(cmp_load),
    .batch_target(batch_target), .batch_arm(batch_arm), .pad_recs(PAD_RECS_W), .retired_cnt(retired_cnt),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

  reg [31:0] pw   [0:7][0:1];
  reg [7:0]  gold [0:7][0:23];
  integer i, j;

  initial begin
    pw[0][0]=32'h63616e64; pw[0][1]=32'h30303030;
    gold[0][ 0]=8'h29; gold[0][ 1]=8'haf; gold[0][ 2]=8'hb2; gold[0][ 3]=8'haa; gold[0][ 4]=8'h56; gold[0][ 5]=8'h18; gold[0][ 6]=8'h4c; gold[0][ 7]=8'h54; gold[0][ 8]=8'h89; gold[0][ 9]=8'hc2; gold[0][10]=8'hdc; gold[0][11]=8'hf2; gold[0][12]=8'hcf; gold[0][13]=8'h0c; gold[0][14]=8'h24; gold[0][15]=8'hda; gold[0][16]=8'h3c; gold[0][17]=8'h97; gold[0][18]=8'h48; gold[0][19]=8'hfd; gold[0][20]=8'h12; gold[0][21]=8'hcb; gold[0][22]=8'h11; gold[0][23]=8'h74;
    pw[1][0]=32'h63616e64; pw[1][1]=32'h30303031;
    gold[1][ 0]=8'h09; gold[1][ 1]=8'h59; gold[1][ 2]=8'h7a; gold[1][ 3]=8'h49; gold[1][ 4]=8'h11; gold[1][ 5]=8'hc7; gold[1][ 6]=8'hd8; gold[1][ 7]=8'h3b; gold[1][ 8]=8'h45; gold[1][ 9]=8'h32; gold[1][10]=8'hab; gold[1][11]=8'h56; gold[1][12]=8'hbf; gold[1][13]=8'h53; gold[1][14]=8'h36; gold[1][15]=8'h9c; gold[1][16]=8'h45; gold[1][17]=8'h66; gold[1][18]=8'hb3; gold[1][19]=8'h9a; gold[1][20]=8'h2a; gold[1][21]=8'h42; gold[1][22]=8'hd5; gold[1][23]=8'hcd;
    pw[2][0]=32'h63616e64; pw[2][1]=32'h30303032;
    gold[2][ 0]=8'hc2; gold[2][ 1]=8'ha2; gold[2][ 2]=8'h80; gold[2][ 3]=8'h58; gold[2][ 4]=8'h94; gold[2][ 5]=8'h8b; gold[2][ 6]=8'hef; gold[2][ 7]=8'h5b; gold[2][ 8]=8'h70; gold[2][ 9]=8'h80; gold[2][10]=8'h36; gold[2][11]=8'h64; gold[2][12]=8'h05; gold[2][13]=8'h83; gold[2][14]=8'h4a; gold[2][15]=8'hdd; gold[2][16]=8'hc9; gold[2][17]=8'h39; gold[2][18]=8'ha5; gold[2][19]=8'h12; gold[2][20]=8'hbb; gold[2][21]=8'h8b; gold[2][22]=8'hac; gold[2][23]=8'hf9;
    pw[3][0]=32'h63616e64; pw[3][1]=32'h30303033;
    gold[3][ 0]=8'h37; gold[3][ 1]=8'hc1; gold[3][ 2]=8'hf9; gold[3][ 3]=8'h14; gold[3][ 4]=8'hd5; gold[3][ 5]=8'hbe; gold[3][ 6]=8'hee; gold[3][ 7]=8'h58; gold[3][ 8]=8'hd8; gold[3][ 9]=8'h1a; gold[3][10]=8'h1d; gold[3][11]=8'h93; gold[3][12]=8'h90; gold[3][13]=8'h7b; gold[3][14]=8'hfd; gold[3][15]=8'hf7; gold[3][16]=8'h2d; gold[3][17]=8'heb; gold[3][18]=8'h20; gold[3][19]=8'ha8; gold[3][20]=8'h61; gold[3][21]=8'h01; gold[3][22]=8'h53; gold[3][23]=8'haf;
    pw[4][0]=32'h63616e64; pw[4][1]=32'h30303034;
    gold[4][ 0]=8'h1d; gold[4][ 1]=8'he2; gold[4][ 2]=8'h33; gold[4][ 3]=8'h5a; gold[4][ 4]=8'heb; gold[4][ 5]=8'h1f; gold[4][ 6]=8'h3b; gold[4][ 7]=8'hf0; gold[4][ 8]=8'hc9; gold[4][ 9]=8'h8d; gold[4][10]=8'h6c; gold[4][11]=8'h10; gold[4][12]=8'h7a; gold[4][13]=8'h6c; gold[4][14]=8'h3a; gold[4][15]=8'h29; gold[4][16]=8'h25; gold[4][17]=8'he2; gold[4][18]=8'h33; gold[4][19]=8'h70; gold[4][20]=8'h32; gold[4][21]=8'h66; gold[4][22]=8'h3e; gold[4][23]=8'h32;
    pw[5][0]=32'h63616e64; pw[5][1]=32'h30303035;
    gold[5][ 0]=8'h5b; gold[5][ 1]=8'hb1; gold[5][ 2]=8'h0a; gold[5][ 3]=8'he3; gold[5][ 4]=8'hda; gold[5][ 5]=8'h17; gold[5][ 6]=8'h08; gold[5][ 7]=8'h38; gold[5][ 8]=8'he9; gold[5][ 9]=8'h3e; gold[5][10]=8'h3b; gold[5][11]=8'hcb; gold[5][12]=8'h43; gold[5][13]=8'h7e; gold[5][14]=8'h2e; gold[5][15]=8'hc4; gold[5][16]=8'hff; gold[5][17]=8'h58; gold[5][18]=8'hba; gold[5][19]=8'hde; gold[5][20]=8'hef; gold[5][21]=8'hd0; gold[5][22]=8'h69; gold[5][23]=8'h7c;
    pw[6][0]=32'h63616e64; pw[6][1]=32'h30303036;
    gold[6][ 0]=8'hd9; gold[6][ 1]=8'h24; gold[6][ 2]=8'hb4; gold[6][ 3]=8'h3e; gold[6][ 4]=8'hfe; gold[6][ 5]=8'h12; gold[6][ 6]=8'h39; gold[6][ 7]=8'ha2; gold[6][ 8]=8'h65; gold[6][ 9]=8'h35; gold[6][10]=8'h9f; gold[6][11]=8'hcc; gold[6][12]=8'h27; gold[6][13]=8'hbc; gold[6][14]=8'h3c; gold[6][15]=8'h63; gold[6][16]=8'he3; gold[6][17]=8'h2e; gold[6][18]=8'h95; gold[6][19]=8'h87; gold[6][20]=8'h65; gold[6][21]=8'h56; gold[6][22]=8'hd3; gold[6][23]=8'hf0;
    pw[7][0]=32'h63616e64; pw[7][1]=32'h30303037;
    gold[7][ 0]=8'hc3; gold[7][ 1]=8'hd4; gold[7][ 2]=8'hcc; gold[7][ 3]=8'hf6; gold[7][ 4]=8'h5a; gold[7][ 5]=8'hc3; gold[7][ 6]=8'h5a; gold[7][ 7]=8'hc6; gold[7][ 8]=8'h56; gold[7][ 9]=8'h9d; gold[7][10]=8'h79; gold[7][11]=8'ha1; gold[7][12]=8'hef; gold[7][13]=8'h99; gold[7][14]=8'h5c; gold[7][15]=8'he3; gold[7][16]=8'hfd; gold[7][17]=8'ha6; gold[7][18]=8'hd5; gold[7][19]=8'h55; gold[7][20]=8'h94; gold[7][21]=8'h33; gold[7][22]=8'hc6; gold[7][23]=8'h81;
  end

  localparam integer SEL_A = 2;
  localparam integer SEL_B = 5;

  function [6:0] cand_index (input integer c);
    begin
      cand_index = gold[c][3] & 8'h7f;
    end
  endfunction

  reg [NCAND-1:0] want = 0;

  task build_bitmap;
    integer c;
    begin
      if (CMP_ALL != 0)
      begin
        cmp_bitmap = {128{1'b1}};
        want       = {NCAND{1'b1}};
      end
      else
      begin
        cmp_bitmap = 128'd0;
        want       = 0;

        cmp_bitmap[cand_index(SEL_A)] = 1'b1;
        cmp_bitmap[cand_index(SEL_B)] = 1'b1;

        for (c = 0; c < NCAND; c = c + 1)
        begin
          if (cmp_bitmap[cand_index(c)] == 1'b1) want[c] = 1'b1;
        end
      end
    end
  endtask

  localparam [31:0] EKID_BASE = 32'h00000100;

  task push_word (input [31:0] d);
    begin
      s_data <= d; s_valid <= 1;
      @(posedge CLK);
      while (s_ready !== 1'b1) @(posedge CLK);
      s_valid <= 0;
    end
  endtask

  localparam [7:0] PW_LEN  = 8'd8;
  localparam [7:0] H2C_TAG = 8'hbc;

  task send_cand (input integer c);
    integer k;
    begin
      push_word({H2C_TAG, 16'd0, PW_LEN});
      push_word(EKID_BASE + c);
      for (k=0; k<2; k=k+1) push_word(pw[c][k]);
    end
  endtask

  localparam [15:0] FLAG_EOB = 16'h8000;

  reg [7:0]  rx [0:31];
  integer    rxpos = 0, nrec = 0, nres = 0, neob = 0, nbad = 0, idx, digok, kk;
  reg [31:0] r_ekid;
  reg [15:0] r_core, r_flags;
  reg [NCAND-1:0] seen = 0;

  integer eob_count = -1;
  integer after_eob = 0;

  reg [15:0] last_flags = 0;

  always @(posedge CLK)
  begin
    if (m_valid & m_ready)
    begin
      rx[rxpos] = m_data;
      if (rxpos == 31)
      begin
        rxpos   = 0;
        r_ekid  = { rx[3], rx[2], rx[1], rx[0] };
        r_core  = { rx[29], rx[28] };
        r_flags = { rx[31], rx[30] };

        last_flags = r_flags;

        if (r_flags == FLAG_EOB)
        begin
          neob = neob + 1;

          if (eob_count < 0) eob_count = r_ekid;
          else if (r_ekid !== eob_count) begin nbad=nbad+1; $display("[tb]   padding record disagrees: %0d vs %0d", r_ekid, eob_count); end

          $display("[tb] rec %0d: END OF BATCH, %0d candidates processed", nrec, r_ekid);
        end
        else
        begin
          nres = nres + 1;

          if (eob_count >= 0) after_eob = after_eob + 1;

          idx   = r_ekid - EKID_BASE;
          digok = 1;

          if (idx < 0 || idx >= NCAND) begin nbad=nbad+1; $display("[tb] rec %0d ekid=%08x OUT OF RANGE", nrec, r_ekid); end
          else
          begin
            for (kk=0; kk<24; kk=kk+1) if (rx[4+kk] !== gold[idx][kk]) digok = 0;

            if (seen[idx]) begin nbad=nbad+1; $display("[tb]   duplicate ekid %08x", r_ekid); end
            seen[idx] = 1;

            if (digok == 0) nbad = nbad + 1;
            if (want[idx] == 1'b0) begin nbad=nbad+1; $display("[tb]   cand%0d was REJECTED by the bitmap and came back anyway", idx); end

            $display("[tb] rec %0d: ekid=%08x -> cand%0d index=%0d core_id=%0d digest=%s",
                     nrec, r_ekid, idx, cand_index(idx), r_core, digok ? "OK" : "*** WRONG ***");
          end
        end

        nrec = nrec + 1;
      end
      else rxpos = rxpos + 1;
    end
  end

  integer nwant = 0;
  integer quiet = 0;

  initial begin
    build_bitmap;

    for (j = 0; j < NCAND; j = j + 1) if (want[j] == 1'b1) nwant = nwant + 1;

    $display("[tb] CMP_ALL=%0d PAD_RECS=%0d, bitmap selects %0d of %0d candidates", CMP_ALL, PAD_RECS, nwant, NCAND);

    repeat (8) @(posedge CLK);
    rst = 0;

    repeat (200) @(posedge CLK);

    cmp_load <= 1'b1;
    @(posedge CLK);
    cmp_load <= 1'b0;
    @(posedge CLK);

    repeat (200) @(posedge CLK);

    batch_target <= NCAND;
    batch_arm    <= 1'b1;
    @(posedge CLK);
    batch_arm    <= 1'b0;
    @(posedge CLK);

    repeat (4) @(posedge CLK);

    for (i=0; i<NCAND; i=i+1) send_cand(i);

    while (neob == 0) @(posedge CLK);

    quiet = 0;

    while (quiet < 2000)
    begin
      @(posedge CLK);

      quiet = (m_valid == 1'b1) ? 0 : (quiet + 1);
    end

    $display("[tb] %0d records: %0d results, %0d end-of-batch. seen=%b want=%b retired_cnt=%0d",
             nrec, nres, neob, seen, want, retired_cnt);

    if (nres !== nwant) begin nbad=nbad+1; $display("[tb] *** %0d results, expected %0d", nres, nwant); end
    if (seen !== want)  begin nbad=nbad+1; $display("[tb] *** returned set %b, expected %b", seen, want); end

    if (eob_count !== NCAND) begin nbad=nbad+1; $display("[tb] *** end of batch reports %0d processed, expected %0d", eob_count, NCAND); end

    if (after_eob !== 0) begin nbad=nbad+1; $display("[tb] *** %0d results arrived AFTER the end-of-batch record", after_eob); end

    if ((nrec % PAD_RECS) !== 0)   begin nbad=nbad+1; $display("[tb] *** %0d records is not a multiple of the %0d record granule", nrec, PAD_RECS); end
    if (last_flags !== FLAG_EOB)   begin nbad=nbad+1; $display("[tb] *** last record carries flags %04x, not the end-of-batch flag", last_flags); end

    if (retired_cnt !== NCAND) begin nbad=nbad+1; $display("[tb] *** retired_cnt is %0d, expected %0d", retired_cnt, NCAND); end

    if (nbad == 0)
      $display("[tb] OVERALL *** PASS *** comparator: only selected candidates returned, batch closed and padded");
    else
      $display("[tb] OVERALL *** FAIL ***");

    $finish;
  end

  initial begin
    #20000000;
    $display("[tb] TIMEOUT nrec=%0d nres=%0d neob=%0d (seen=%b want=%b)", nrec, nres, neob, seen, want);
    $finish;
  end

endmodule

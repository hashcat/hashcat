/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module tb_core;

  reg mode_dump = 0;

  integer dm;
  reg [31:0] dumpw [0:1023];
  integer dj, dk, nz, ndiff, dfh, nmm;
  reg [31:0] memw [0:1023];

  reg trace_on = 0;
  integer tcyc = 0;
  reg [31:0] dbit;

  reg want_dump = 0;

  initial begin
    if ($value$plusargs("dump=%d", dm)) want_dump = (dm != 0);
  end

  always @(posedge CLK) begin
    if (trace_on && (tcyc < 260)) begin
      if (core.fsm.IP == 86)
        $display("[shf] dcnt=%0d Ltmp=%08x S_dout=%08x", core.dump_cnt, core.unit.Ltmp, core.unit.S_dout);
      $display("[trc] %3d IP=%3d E=%2d outcnt=%2d dcnt=%4d bank=%0d S_dout=%08x L_in=%08x Ltmp=%08x dout=%b",
        tcyc, core.fsm.IP, core.Extra_Controls, core.output_cnt, core.dump_cnt,
        core.dump_cnt[9:8], core.unit.S_dout, core.unit.L_in, core.unit.Ltmp, dout);
      tcyc = tcyc + 1;
    end
  end

  reg CLK = 0;
  always #5 CLK = ~CLK;

  reg rst = 1;

  parameter integer DIN_BITS = 8;

  parameter S_STYLE = "block";

  reg  [DIN_BITS-1:0] din = 0;
  reg  [3:0] byte_wr_en = 0;
  reg        start = 0;
  wire       init_ready, crypt_ready, empty, dout;
  reg        rd_en = 0;

  bcrypt_core #(.DIN_BITS(DIN_BITS), .S_STYLE(S_STYLE)) core (
    .CLK(CLK), .rst(rst), .mode_cmp(1'b0), .mode_dump(mode_dump),
    .din(din), .byte_wr_en(byte_wr_en), .start(start),
    .init_ready(init_ready), .crypt_ready(crypt_ready),
    .rd_en(rd_en), .empty(empty), .dout(dout)
  );

  reg [31:0] initimg [0:1053];
  reg [31:0] S [0:1023];

  reg [31:0] databatch [0:30];

  integer i;
  reg [255:0] cap;
  reg [15:0]  w [0:15];
  reg [31:0]  ekid_echo;
  reg [31:0]  D [0:5];
  reg [31:0]  Dsw [0:5];

  localparam [31:0] EKID = 32'hDEADBEEF;

  reg [7:0] gold [0:23];
  initial begin
    gold[ 0]=8'hcf; gold[ 1]=8'hf8; gold[ 2]=8'ha8; gold[ 3]=8'hac;
    gold[ 4]=8'h7b; gold[ 5]=8'hda; gold[ 6]=8'hdd; gold[ 7]=8'h00;
    gold[ 8]=8'h1b; gold[ 9]=8'h00; gold[10]=8'hd2; gold[11]=8'h6d;
    gold[12]=8'hf3; gold[13]=8'hc9; gold[14]=8'he4; gold[15]=8'hed;
    gold[16]=8'h0c; gold[17]=8'h49; gold[18]=8'h83; gold[19]=8'he3;
    gold[20]=8'h98; gold[21]=8'h1b; gold[22]=8'h1d; gold[23]=8'h0d;
  end

  task send_word (input [31:0] word, input is_first);
    begin
      if (DIN_BITS == 32)
      begin
        if (is_first)
        begin
          @(negedge CLK); din = word; byte_wr_en = 4'b0001; start = 1;
          @(negedge CLK); din = word; byte_wr_en = 4'b0110; start = 0;
          @(negedge CLK); din = word; byte_wr_en = 4'b1000; start = 0;
        end
        else
        begin
          @(negedge CLK); din = word; byte_wr_en = 4'b0111; start = 0;
          @(negedge CLK); din = word; byte_wr_en = 4'b1000; start = 0;
        end
      end
      else
      begin
        @(negedge CLK); din = word[7:0];   byte_wr_en = 4'b0001; start = is_first;
        @(negedge CLK); din = word[15:8];  byte_wr_en = 4'b0010; start = 0;
        @(negedge CLK); din = word[23:16]; byte_wr_en = 4'b0100;
        @(negedge CLK); din = word[31:24]; byte_wr_en = 4'b1000;
      end
    end
  endtask

  task idle_bus;
    begin
      @(negedge CLK); din = 0; byte_wr_en = 0; start = 0;
    end
  endtask

  initial begin
    $readmemh("../S_data.txt", S);

    initimg[ 0]=32'h243f6a88; initimg[ 1]=32'h85a308d3; initimg[ 2]=32'h13198a2e; initimg[ 3]=32'h03707344;
    initimg[ 4]=32'ha4093822; initimg[ 5]=32'h299f31d0; initimg[ 6]=32'h082efa98; initimg[ 7]=32'hec4e6c89;
    initimg[ 8]=32'h452821e6; initimg[ 9]=32'h38d01377; initimg[10]=32'hbe5466cf; initimg[11]=32'h34e90c6c;
    initimg[12]=32'hc0ac29b7; initimg[13]=32'hc97c50dd; initimg[14]=32'h3f84d5b5; initimg[15]=32'hb5470917;
    initimg[16]=32'h9216d5d9; initimg[17]=32'h8979fb1b;
    for (i=18; i<24; i=i+1) initimg[i] = 0;
    initimg[24]=32'h65616E42; initimg[25]=32'h4F727068; initimg[26]=32'h64657253;
    initimg[27]=32'h65686F6C; initimg[28]=32'h6F756274; initimg[29]=32'h63727944;
    for (i=0; i<1024; i=i+1) initimg[30+i] = S[i];

    databatch[ 0]=32'h70617373; databatch[ 1]=32'h776f7264; databatch[ 2]=32'h00706173; databatch[ 3]=32'h73776f72;
    databatch[ 4]=32'h64007061; databatch[ 5]=32'h7373776f; databatch[ 6]=32'h72640070; databatch[ 7]=32'h61737377;
    databatch[ 8]=32'h6f726400; databatch[ 9]=32'h70617373; databatch[10]=32'h776f7264; databatch[11]=32'h00706173;
    databatch[12]=32'h73776f72; databatch[13]=32'h64007061; databatch[14]=32'h7373776f; databatch[15]=32'h72640070;
    databatch[16]=32'h61737377; databatch[17]=32'h6f726400;
    databatch[18]=32'd64;
    databatch[19]=32'd32;
    databatch[20]=32'h00010203;
    databatch[21]=32'h04050607;
    databatch[22]=32'h08090a0b;
    databatch[23]=32'h0c0d0e0f;
    databatch[24]=EKID;
    databatch[25]=32'h00000000;
    for (i=26; i<31; i=i+1) databatch[i]=0;

    din=0; byte_wr_en=0; start=0; rd_en=0;
    repeat (8) @(negedge CLK);
    rst = 0;
    repeat (4) @(negedge CLK);

    wait (init_ready == 1'b1);
    $display("[tb] init_ready at %0t; streaming 1054 init words", $time);
    for (i=0; i<1054; i=i+1) send_word(initimg[i], i==0);
    idle_bus;

    wait (crypt_ready == 1'b1);
    $display("[tb] crypt_ready at %0t; streaming 31 data words", $time);
    for (i=0; i<31; i=i+1) send_word(databatch[i], i==0);
    idle_bus;

    $display("[tb] waiting for result (empty->0)...", $time);
    wait (empty == 1'b0);
    $display("[tb] empty=0 at %0t; pulsing rd_en", $time);
    mode_dump = want_dump;
    @(negedge CLK);
    if (mode_dump) trace_on = 1;
    @(negedge CLK); rd_en = 1;
    @(negedge CLK); rd_en = 0;

    @(posedge CLK);
    i = 0;
    while (dout !== 1'b1) begin
      @(posedge CLK);
      i = i + 1;
      if (i > 2000) begin $display("[tb] FAIL: no header bit"); $finish; end
    end
    $display("[tb] header at %0t (%0d cycles after rd_en)", $time, i);

    if (want_dump) begin
      for (dj = 0; dj < 1024; dj = dj + 1) begin
        dbit = 0;
        for (dk = 0; dk < 32; dk = dk + 1) begin
          @(posedge CLK);
          dbit[dk] = dout;
        end
        dumpw[dj] = dbit;
      end

      nz = 0; ndiff = 0;
      for (dj = 0; dj < 1024; dj = dj + 1) begin
        if (dumpw[dj] !== 32'h0) nz = nz + 1;
        if (dumpw[dj] !== initimg[30+dj]) ndiff = ndiff + 1;
      end

      $display("[tb] MEM S0[0..3] = %08x %08x %08x %08x",
        core.unit.S.sel.impl.S0[0], core.unit.S.sel.impl.S0[1], core.unit.S.sel.impl.S0[2], core.unit.S.sel.impl.S0[3]);
      $display("[tb] MEM S1[0..1] = %08x %08x   S2[0..1] = %08x %08x   S3[0..1] = %08x %08x",
        core.unit.S.sel.impl.S1[0], core.unit.S.sel.impl.S1[1], core.unit.S.sel.impl.S2[0], core.unit.S.sel.impl.S2[1],
        core.unit.S.sel.impl.S3[0], core.unit.S.sel.impl.S3[1]);
      $display("[tb] MEM P[0..3]  = %08x %08x %08x %08x",
        core.unit.P.PN[0], core.unit.P.PN[1], core.unit.P.PN[2], core.unit.P.PN[3]);

      $display("[tb] DUMP first 8 words: %08x %08x %08x %08x %08x %08x %08x %08x",
        dumpw[0], dumpw[1], dumpw[2], dumpw[3], dumpw[4], dumpw[5], dumpw[6], dumpw[7]);
      $display("[tb] DUMP init S[0..7] : %08x %08x %08x %08x %08x %08x %08x %08x",
        initimg[30], initimg[31], initimg[32], initimg[33], initimg[34], initimg[35], initimg[36], initimg[37]);
      $display("[tb] DUMP non-zero words = %0d of 1024, differing from init S = %0d", nz, ndiff);

      for (dj = 0; dj < 256; dj = dj + 1) begin
        memw[      dj] = core.unit.S.sel.impl.S0[dj];
        memw[256 + dj] = core.unit.S.sel.impl.S1[dj];
        memw[512 + dj] = core.unit.S.sel.impl.S2[dj];
        memw[768 + dj] = core.unit.S.sel.impl.S3[dj];
      end
      dfh = $fopen("mem_S.txt", "w");
      for (dj = 0; dj < 1024; dj = dj + 1) $fdisplay(dfh, "%08x", memw[dj]);
      $fclose(dfh);

      dfh = $fopen("dump_S.txt", "w");
      for (dj = 0; dj < 1024; dj = dj + 1) $fdisplay(dfh, "%08x", dumpw[dj]);
      $fclose(dfh);
      $display("[tb] DUMP wrote dump_S.txt");

      nmm = 0;
      for (dj = 0; dj < 1024; dj = dj + 1) begin
        if (dumpw[dj] !== memw[dj]) nmm = nmm + 1;
      end
      $display("[tb] DUMP vs core S memory: %0d mismatches of 1024", nmm);
      if (nmm == 0) $display("[tb] DUMP *** PASS *** state dump reproduces S exactly");
      else          $display("[tb] DUMP *** FAIL *** %0d words wrong", nmm);

      if (nz == 0)              $display("[tb] DUMP *** FAIL *** S memory readout is all zero");
      else if (ndiff == 0)      $display("[tb] DUMP *** SUSPECT *** identical to the init image, S may not have advanced");
      else                      $display("[tb] DUMP *** ran *** 1024 words framed, %0d non-zero, %0d moved from init", nz, ndiff);

      $display("[tb] done");
      $finish;
    end

    for (i=0; i<256; i=i+1) begin
      @(posedge CLK);
      cap[i] = dout;
    end

    for (i=0; i<16; i=i+1) w[i] = cap[i*16 +: 16];

    ekid_echo = {w[1], w[0]};
    for (i=0; i<6; i=i+1) begin
      D[i]   = {w[5+2*i], w[4+2*i]};
      Dsw[i] = {D[i][7:0], D[i][15:8], D[i][23:16], D[i][31:24]};
    end

    $display("[tb] ID0 (ekid echo) = %08x  (expect %08x)  %s",
             ekid_echo, EKID, (ekid_echo==EKID) ? "OK" : "MISMATCH");
    $display("[tb] ID1 = %08x", {w[3], w[2]});
    $write("[tb] digest words D[]      = "); for (i=0;i<6;i=i+1) $write("%08x ", D[i]);   $write("\n");
    $write("[tb] digest words byteswap = "); for (i=0;i<6;i=i+1) $write("%08x ", Dsw[i]); $write("\n");

    begin : cmp
      integer k; integer ok; reg [31:0] g;
      ok = 1;
      for (i=0;i<6;i=i+1) begin
        g = {gold[i*4+0], gold[i*4+1], gold[i*4+2], gold[i*4+3]};
        if (D[i] !== g) ok = 0;
      end
      $display("[tb] DIGEST %s   ekid echo %s",
               ok ? "*** PASS ***" : "*** FAIL ***",
               (ekid_echo==EKID) ? "PASS" : "FAIL");
      if (ok == 0 || ekid_echo != EKID) $display("[tb] OVERALL FAIL");
      else $display("[tb] OVERALL *** PASS *** core protocol + ekid echo + digest verified");
    end

    repeat (10) @(negedge CLK);
    $display("[tb] done");
    $finish;
  end

  initial begin
    #15000000;
    $display("[tb] TIMEOUT");
    $finish;
  end

endmodule

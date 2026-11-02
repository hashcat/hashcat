/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module tb_core_c2;

  reg CLK = 0;
  always #5 CLK = ~CLK;

  reg rst = 1;

  reg phase = 0;
  always @(posedge CLK) phase <= rst ? 1'b0 : ~phase;

  reg  [31:0] din = 0;
  reg  [3:0]  byte_wr_en = 0;
  reg         start = 0;
  reg  [1:0]  wr_sel = 0;
  reg  [1:0]  rd_en_vc = 0;

  wire [1:0] init_ready_vc, crypt_ready_vc, empty_vc, dout_vc;

  bcrypt_core_c2 #(.DIN_BITS(32)) core (
    .CLK(CLK), .rst(rst), .phase(phase),
    .din(din), .byte_wr_en(byte_wr_en), .start(start), .wr_sel(wr_sel),
    .rd_en_vc(rd_en_vc),
    .init_ready_vc(init_ready_vc), .crypt_ready_vc(crypt_ready_vc),
    .empty_vc(empty_vc), .dout_vc(dout_vc)
  );

  reg [31:0] initimg [0:1053];
  reg [31:0] S [0:1023];

  reg [31:0] batch [0:1][0:30];
  reg [31:0] gold  [0:1][0:5];
  reg [31:0] ekid  [0:1];

  integer i, v, nfail;

  integer exc [0:1];
  initial begin exc[0] = 0; exc[1] = 0; end
  always @(posedge CLK)
    if ((rst == 1'b0) && (core.fsm.IP == 7'd82)) exc[phase] = exc[phase] + 1;

  task beat (input [31:0] w, input [3:0] bwe, input st, input [1:0] sel, input [1:0] rd);
    begin
      @(negedge CLK);
      while (phase != 1'b0) @(negedge CLK);
      din = w; byte_wr_en = bwe; start = st; wr_sel = sel; rd_en_vc = rd;
      @(negedge CLK);
    end
  endtask

  task send_word (input [31:0] w, input is_first, input [1:0] sel);
    begin
      if (is_first)
      begin
        beat (w, 4'b0001, 1'b1, sel, 2'b00);
        beat (w, 4'b0110, 1'b0, sel, 2'b00);
        beat (w, 4'b1000, 1'b0, sel, 2'b00);
      end
      else
      begin
        beat (w, 4'b0111, 1'b0, sel, 2'b00);
        beat (w, 4'b1000, 1'b0, sel, 2'b00);
      end
    end
  endtask

  task idle_beat;
    begin
      beat (32'h0, 4'b0000, 1'b0, 2'b00, 2'b00);
    end
  endtask

  task beat_end;
    begin
      @(posedge CLK);
      while (phase != 1'b1) @(posedge CLK);
    end
  endtask

  reg [255:0] cap;
  reg [15:0]  w [0:15];
  reg [31:0]  D [0:5];
  reg [31:0]  id0;
  integer k, n, ok;

  task read_result (input integer vc);
    begin
      beat_end;
      while (empty_vc[vc] !== 1'b0) beat_end;
      $display("[tb] vc%0d result ready at %0t", vc, $time);

      beat (32'h0, 4'b0000, 1'b0, 2'b00, (vc == 0) ? 2'b01 : 2'b10);
      beat (32'h0, 4'b0000, 1'b0, 2'b00, 2'b00);

      n = 0;
      beat_end;
      while (dout_vc[vc] !== 1'b1) begin
        beat_end;
        n = n + 1;
        if (n > 2000) begin $display("[tb] vc%0d FAIL: no header bit", vc); $finish; end
      end

      for (k = 0; k < 256; k = k + 1) begin
        beat_end;
        cap[k] = dout_vc[vc];
      end

      for (k = 0; k < 16; k = k + 1) w[k] = cap[k*16 +: 16];

      id0 = {w[1], w[0]};
      for (k = 0; k < 6; k = k + 1) D[k] = {w[5+2*k], w[4+2*k]};

      ok = (id0 == ekid[vc]);
      for (k = 0; k < 6; k = k + 1) if (D[k] !== gold[vc][k]) ok = 0;

      $write("[tb] vc%0d ekid %08x digest ", vc, id0);
      for (k = 0; k < 6; k = k + 1) $write("%08x ", D[k]);
      $write("\n");
      $write("[tb] vc%0d expect  %08x digest ", vc, ekid[vc]);
      for (k = 0; k < 6; k = k + 1) $write("%08x ", gold[vc][k]);
      $write("\n");

      if (ok) $display("[tb] vc%0d *** PASS ***", vc);
      else begin $display("[tb] vc%0d *** FAIL ***", vc); nfail = nfail + 1; end
    end
  endtask

  initial begin
    nfail = 0;

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

    `include "tb_core_c2_vectors.vh"

    repeat (8) @(negedge CLK);
    rst = 0;
    repeat (4) @(negedge CLK);

    beat_end;
    while (init_ready_vc !== 2'b11) beat_end;
    $display("[tb] both virtual cores init ready at %0t, one broadcast of 1054 words", $time);
    for (i=0; i<1054; i=i+1) send_word (initimg[i], i==0, 2'b11);
    idle_beat;

    for (v = 0; v < 2; v = v + 1) begin
      beat_end;
      while (crypt_ready_vc[v] !== 1'b1) beat_end;
      $display("[tb] vc%0d crypt ready at %0t, 31 data words", v, $time);
      for (i=0; i<31; i=i+1) send_word (batch[v][i], i==0, (v == 0) ? 2'b01 : 2'b10);
      idle_beat;
    end

    read_result (0);
    read_result (1);

    $display("[tb] S collision exceptions taken: vc0 %0d, vc1 %0d", exc[0], exc[1]);

    if (nfail == 0) $display("[tb] OVERALL *** PASS *** two candidates in one core, both digests exact");
    else            $display("[tb] OVERALL FAIL, %0d of 2", nfail);

    $finish;
  end

  initial begin
    #40000000;
    $display("[tb] TIMEOUT");
    $finish;
  end

endmodule

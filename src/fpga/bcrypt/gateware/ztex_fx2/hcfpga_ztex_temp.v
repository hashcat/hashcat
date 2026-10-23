/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_ztex_temp (
  input  wire        clk,
  input  wire        rst,

  output reg  [31:0] temp = 32'd0
);

  wire [15:0] drp_do;
  wire        drp_rdy;

  reg         drp_en = 1'b0;
  reg         busy   = 1'b0;

  XADC xadc (
    .DCLK(clk),
    .RESET(1'b0),

    .DADDR(7'h00),
    .DEN(drp_en),
    .DWE(1'b0),
    .DI(16'h0000),
    .DO(drp_do),
    .DRDY(drp_rdy),

    .CONVST(1'b0),
    .CONVSTCLK(1'b0),
    .VP(1'b0),
    .VN(1'b0),
    .VAUXP(16'h0000),
    .VAUXN(16'h0000),

    .ALM(),
    .OT(),
    .BUSY(),
    .CHANNEL(),
    .EOC(),
    .EOS(),
    .JTAGBUSY(),
    .JTAGLOCKED(),
    .JTAGMODIFIED(),
    .MUXADDR()
  );

  always @(posedge clk)
  begin
    drp_en <= 1'b0;

    if (rst == 1'b1)
    begin
      busy <= 1'b0;
    end
    else if (busy == 1'b0)
    begin
      drp_en <= 1'b1;
      busy   <= 1'b1;
    end
    else if (drp_rdy == 1'b1)
    begin
      temp <= { 1'b1, 19'd0, drp_do[15:4] };
      busy <= 1'b0;
    end
  end

endmodule

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module IBUFG (input I, output O);

  assign O = I;

endmodule

module BUFG (input I, output O);

  assign O = I;

endmodule

module MMCME2_BASE #(
  parameter BANDWIDTH          = "OPTIMIZED",
  parameter real CLKFBOUT_MULT_F  = 5.0,
  parameter real CLKFBOUT_PHASE   = 0.0,
  parameter real CLKIN1_PERIOD    = 0.0,
  parameter real CLKOUT0_DIVIDE_F = 1.0,
  parameter integer CLKOUT1_DIVIDE = 1,
  parameter integer CLKOUT2_DIVIDE = 1,
  parameter integer CLKOUT3_DIVIDE = 1,
  parameter integer CLKOUT4_DIVIDE = 1,
  parameter integer CLKOUT5_DIVIDE = 1,
  parameter real CLKOUT0_DUTY_CYCLE = 0.5,
  parameter real CLKOUT1_DUTY_CYCLE = 0.5,
  parameter real CLKOUT2_DUTY_CYCLE = 0.5,
  parameter real CLKOUT3_DUTY_CYCLE = 0.5,
  parameter real CLKOUT4_DUTY_CYCLE = 0.5,
  parameter real CLKOUT5_DUTY_CYCLE = 0.5,
  parameter real CLKOUT0_PHASE = 0.0,
  parameter real CLKOUT1_PHASE = 0.0,
  parameter real CLKOUT2_PHASE = 0.0,
  parameter real CLKOUT3_PHASE = 0.0,
  parameter real CLKOUT4_PHASE = 0.0,
  parameter real CLKOUT5_PHASE = 0.0,
  parameter CLKOUT4_CASCADE = "FALSE",
  parameter integer DIVCLK_DIVIDE = 1,
  parameter real REF_JITTER1 = 0.0,
  parameter STARTUP_WAIT = "FALSE"
)(
  output reg  CLKOUT0,
  output reg  CLKOUT1,
  output wire CLKFBOUT,
  output reg  LOCKED,
  input  wire CLKIN1,
  input  wire CLKFBIN,
  input  wire PWRDWN,
  input  wire RST
);

  real t_first;
  real t_period;
  real t_half;
  real t_half1;

  integer seen;

  initial
  begin
    CLKOUT0  = 1'b0;
    CLKOUT1  = 1'b0;
    LOCKED   = 1'b0;
    seen     = 0;
    t_period = 0.0;
  end

  always @(posedge CLKIN1)
  begin
    if (seen == 0)
    begin
      t_first = $realtime;
      seen    = 1;
    end
    else if (seen == 1)
    begin
      t_period = $realtime - t_first;
      seen     = 2;
    end
  end

  assign CLKFBOUT = CLKIN1;

  initial
  begin
    wait (seen == 2);

    t_half = (t_period * DIVCLK_DIVIDE * CLKOUT0_DIVIDE_F) / (CLKFBOUT_MULT_F * 2.0);

    forever #(t_half) CLKOUT0 = ~CLKOUT0;
  end

  initial
  begin
    wait (seen == 2);

    t_half1 = (t_period * DIVCLK_DIVIDE * CLKOUT1_DIVIDE) / (CLKFBOUT_MULT_F * 2.0);

    forever #(t_half1) CLKOUT1 = ~CLKOUT1;
  end

  integer lock_cnt;

  initial lock_cnt = 0;

  always @(posedge CLKOUT0 or posedge RST)
  begin
    if (RST == 1'b1)
    begin
      lock_cnt <= 0;
      LOCKED   <= 1'b0;
    end
    else if (lock_cnt < 8)
    begin
      lock_cnt <= lock_cnt + 1;
    end
    else
    begin
      LOCKED <= 1'b1;
    end
  end

endmodule

module XADC (
  input             DCLK,
  input             RESET,

  input      [6:0]  DADDR,
  input             DEN,
  input             DWE,
  input      [15:0] DI,
  output reg [15:0] DO = 16'h0000,
  output reg        DRDY = 1'b0,

  input             CONVST,
  input             CONVSTCLK,
  input             VP,
  input             VN,
  input      [15:0] VAUXP,
  input      [15:0] VAUXN,

  output     [7:0]  ALM,
  output            OT,
  output            BUSY,
  output     [4:0]  CHANNEL,
  output            EOC,
  output            EOS,
  output            JTAGBUSY,
  output            JTAGLOCKED,
  output            JTAGMODIFIED,
  output     [4:0]  MUXADDR
);

  assign ALM          = 8'h00;
  assign OT           = 1'b0;
  assign BUSY         = 1'b0;
  assign CHANNEL      = 5'd0;
  assign EOC          = 1'b0;
  assign EOS          = 1'b0;
  assign JTAGBUSY     = 1'b0;
  assign JTAGLOCKED   = 1'b0;
  assign JTAGMODIFIED = 1'b0;
  assign MUXADDR      = 5'd0;

  reg       pending  = 1'b0;
  reg [2:0] wait_cnt = 3'd0;

  always @(posedge DCLK)
  begin
    DRDY <= 1'b0;

    if (DEN == 1'b1)
    begin
      pending  <= 1'b1;
      wait_cnt <= 3'd4;
    end
    else if (pending == 1'b1)
    begin
      if (wait_cnt == 3'd0)
      begin
        DO      <= 16'h9a00;
        DRDY    <= 1'b1;
        pending <= 1'b0;
      end
      else
      begin
        wait_cnt <= wait_cnt - 3'd1;
      end
    end
  end

endmodule

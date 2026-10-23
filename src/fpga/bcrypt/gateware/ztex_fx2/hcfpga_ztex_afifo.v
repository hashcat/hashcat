/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_ztex_afifo #(
  parameter WIDTH     = 32,

  parameter ADDR_BITS = 9
)(
  input  wire             wr_clk,
  input  wire             wr_rst,
  input  wire [WIDTH-1:0] wr_data,
  input  wire             wr_valid,
  output wire             wr_ready,

  input  wire             rd_clk,
  input  wire             rd_rst,
  output wire [WIDTH-1:0] rd_data,
  output wire             rd_valid,
  input  wire             rd_ready
);

  localparam DEPTH = 1 << ADDR_BITS;

  reg [ADDR_BITS:0] wr_bin  = 0;
  reg [ADDR_BITS:0] wr_gray = 0;
  reg [ADDR_BITS:0] rd_bin  = 0;
  reg [ADDR_BITS:0] rd_gray = 0;

  (* ASYNC_REG = "TRUE" *) reg [ADDR_BITS:0] rd_gray_meta = 0;
  (* ASYNC_REG = "TRUE" *) reg [ADDR_BITS:0] rd_gray_sync = 0;

  (* ASYNC_REG = "TRUE" *) reg [ADDR_BITS:0] wr_gray_meta = 0;
  (* ASYNC_REG = "TRUE" *) reg [ADDR_BITS:0] wr_gray_sync = 0;

  reg [WIDTH-1:0] mem [0:DEPTH-1];

  wire [ADDR_BITS:0] wr_bin_next  = wr_bin + 1'b1;
  wire [ADDR_BITS:0] wr_gray_next = wr_bin_next ^ (wr_bin_next >> 1);

  wire full = (wr_gray_next == { ~rd_gray_sync[ADDR_BITS:ADDR_BITS-1], rd_gray_sync[ADDR_BITS-2:0] });

  assign wr_ready = (full == 1'b0) && (wr_rst == 1'b0);

  always @(posedge wr_clk)
  begin
    rd_gray_meta <= rd_gray;
    rd_gray_sync <= rd_gray_meta;

    if (wr_rst == 1'b1)
    begin
      wr_bin  <= 0;
      wr_gray <= 0;
    end
    else if ((wr_valid == 1'b1) && (wr_ready == 1'b1))
    begin
      mem[wr_bin[ADDR_BITS-1:0]] <= wr_data;

      wr_bin  <= wr_bin_next;
      wr_gray <= wr_gray_next;
    end
  end

  wire [ADDR_BITS:0] rd_bin_next  = rd_bin + 1'b1;
  wire [ADDR_BITS:0] rd_gray_next = rd_bin_next ^ (rd_bin_next >> 1);

  wire empty = (rd_gray == wr_gray_sync);

  reg [WIDTH-1:0] out_data  = 0;
  reg             out_valid = 0;

  wire pop = (empty == 1'b0) && (rd_rst == 1'b0) && ((out_valid == 1'b0) || (rd_ready == 1'b1));

  always @(posedge rd_clk)
  begin
    wr_gray_meta <= wr_gray;
    wr_gray_sync <= wr_gray_meta;

    if (rd_rst == 1'b1)
    begin
      rd_bin    <= 0;
      rd_gray   <= 0;
      out_valid <= 1'b0;
    end
    else
    begin
      if (pop == 1'b1)
      begin
        rd_bin  <= rd_bin_next;
        rd_gray <= rd_gray_next;
      end

      if (pop == 1'b1)           out_valid <= 1'b1;
      else if (rd_ready == 1'b1) out_valid <= 1'b0;
    end

    if (pop == 1'b1) out_data <= mem[rd_bin[ADDR_BITS-1:0]];
  end

  assign rd_data  = out_data;
  assign rd_valid = out_valid;

endmodule

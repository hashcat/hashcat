/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_top #(
  parameter NUM_CORES = 4,

  parameter NUM_CORES_DIST = 0,
  parameter INIT_BATCH = 0,

  parameter DIN_BITS  = 32,

  parameter FEED_GROUP = 0,

  parameter FEED_SHARD = 0,

  parameter COLLECT_GROUP = 0,

  parameter WITH_DUMP  = 1,

  parameter WITH_CMP   = 1,

  parameter CSLOW      = 1
)(
  input  wire CLK,
  input  wire CLK_CORE,
  input  wire rst,

  input  wire [31:0] s_data,
  input  wire        s_valid,
  output wire        s_ready,
  input  wire        s_last,

  output wire [31:0] frame_status,

  input  wire [31:0] salt0,
  input  wire [31:0] salt1,
  input  wire [31:0] salt2,
  input  wire [31:0] salt3,
  input  wire [31:0] iter_count,
  input  wire        mode_dump,

  input  wire [127:0] cmp_bitmap,
  input  wire         cmp_load,

  input  wire [31:0]  batch_target,
  input  wire         batch_arm,

  input  wire [15:0]  pad_recs,

  output wire [31:0]  retired_cnt,

  output wire [7:0]  m_data,
  output wire        m_valid,
  input  wire        m_ready,
  output wire        m_last
);

  localparam NSH = (FEED_SHARD == 0) ? 1 : ((NUM_CORES + FEED_SHARD - 1) / FEED_SHARD);

  wire [NSH*DIN_BITS-1:0] c_din;
  wire [NSH*4-1:0]        c_bwe;
  wire [NSH-1:0]          c_start;
  wire [NUM_CORES-1:0]    c_wr_en;

  wire [NUM_CORES-1:0] init_ready;
  wire [NUM_CORES-1:0] crypt_ready;
  wire [NUM_CORES-1:0] empty;
  wire [NUM_CORES-1:0] dout;
  wire [NUM_CORES-1:0] rd_en;

  hcfpga_feed_group #(.NUM_CORES(NUM_CORES), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS), .GROUP(FEED_SHARD)) feed (
    .CLK(CLK), .rst(rst),
    .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
    .frame_status(frame_status),
    .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3),
    .iter_count(iter_count),
    .c_din(c_din), .c_bwe(c_bwe), .c_start(c_start), .c_wr_en(c_wr_en),
    .core_init_ready(init_ready), .core_crypt_ready(crypt_ready)
  );

  wire       bm_we;
  wire [6:0] bm_addr;
  wire       bm_din;

  generate
  if (WITH_CMP != 0) begin : bcast
    hcfpga_cmp_bcast b (
      .CLK(CLK), .rst(rst),
      .bitmap(cmp_bitmap), .load(cmp_load),
      .bm_we(bm_we), .bm_addr(bm_addr), .bm_din(bm_din)
    );
  end
  else begin : nobcast
    assign bm_we   = 1'b0;
    assign bm_addr = 7'd0;
    assign bm_din  = 1'b0;
  end
  endgenerate

  hcfpga_cores #(.NUM_CORES(NUM_CORES), .NUM_CORES_DIST(NUM_CORES_DIST), .DIN_BITS(DIN_BITS), .GROUP(FEED_GROUP), .SHARD(FEED_SHARD), .WITH_DUMP(WITH_DUMP), .WITH_CMP(WITH_CMP), .CSLOW(CSLOW)) cores (
    .CLK(CLK), .CLK_CORE(CLK_CORE), .rst(rst), .mode_dump(mode_dump),
    .c_din(c_din), .c_bwe(c_bwe), .c_start(c_start), .c_wr_en(c_wr_en),
    .bm_we(bm_we), .bm_addr(bm_addr), .bm_din(bm_din),
    .init_ready(init_ready), .crypt_ready(crypt_ready),
    .rd_en(rd_en), .empty(empty), .dout(dout)
  );

  hcfpga_collect_group #(.NUM_CORES(NUM_CORES), .GROUP(COLLECT_GROUP), .WITH_CMP(WITH_CMP)) collect (
    .CLK(CLK), .rst(rst),
    .core_empty(empty), .core_dout(dout), .core_rd_en(rd_en),
    .batch_target(batch_target), .batch_arm(batch_arm), .pad_recs(pad_recs), .retired_cnt(retired_cnt),
    .m_data(m_data), .m_valid(m_valid), .m_ready(m_ready), .m_last(m_last)
  );

endmodule

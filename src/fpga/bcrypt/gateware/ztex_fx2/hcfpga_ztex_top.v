/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
`include "hcfpga_iface.vh"

`include "hcfpga_ztex_iface.vh"

module hcfpga_ztex_top #(
  parameter integer NUM_CORES      = 24,
  parameter integer NUM_CORES_DIST = 4,
  parameter integer INIT_BATCH     = 0,
  parameter integer DIN_BITS       = 32,
  parameter integer FEED_GROUP     = 0,

  parameter integer FEED_SHARD     = 0,

  parameter integer COLLECT_GROUP  = 0,
  parameter integer WITH_DUMP      = 0,

  parameter integer WITH_CMP       = 1,

  parameter integer CORE_CLK_MHZ      = 100,
  parameter integer MMCM_DIVCLK       = 1,
  parameter integer MMCM_MULT_MILLI   = 18750,
  parameter integer MMCM_OUTDIV_MILLI = 9000,

  parameter integer CSLOW             = 1,
  parameter integer MMCM_OUT1DIV      = 4,

  parameter [31:0]  BUILD_STAMP       = 32'd0,

  parameter [31:0]  ABI_VERSION       = 32'd1,

  parameter integer H2C_BLOCK_BYTES   = `HCFPGA_ZTEX_MARK_BYTES,

  parameter integer IN_ADDR_BITS      = 9,
  parameter integer OUT_ADDR_BITS     = 8,

  parameter integer PKTEND_IDLE_BITS  = 8
)(
  input  wire        fxclk_in,
  input  wire        ifclk_in,

  input  wire        reset,

  inout  wire [15:0] fd,
  output wire        SLWR,
  output wire        SLRD,
  output wire        SLOE,
  output wire        FIFOADDR0,
  output wire        FIFOADDR1,
  output wire        PKTEND,
  input  wire        FLAGA,
  input  wire        FLAGB,

  input  wire        lsi_clk,
  input  wire        lsi_mosi,
  output wire        lsi_miso,
  input  wire        lsi_stop
);

  wire        ifclk;
  wire        ifclk_rst;

  wire [15:0] usb_do;
  wire        usb_do_valid;
  wire        usb_do_ready;

  wire [15:0] usb_di;
  wire        usb_di_valid;
  wire        usb_di_ready;

  wire [1:0]  fifoaddr;

  assign FIFOADDR0 = fifoaddr[0];
  assign FIFOADDR1 = fifoaddr[1];

  reg pktend_arm = 1'b0;

  wire [3:0] io_status;

  wire io_resend = io_status[1];
  wire io_if_out = io_status[0];

  ezusb_io #(
    .OUTEP(2),
    .INEP(6),
    .TARGET("A7")
  ) io (
    .ifclk(ifclk),
    .reset(reset),
    .reset_out(ifclk_rst),

    .ifclk_in(ifclk_in),
    .fd(fd),
    .SLWR(SLWR),
    .SLRD(SLRD),
    .SLOE(SLOE),
    .PKTEND(PKTEND),
    .FIFOADDR(fifoaddr),
    .EMPTY_FLAG(FLAGA),
    .FULL_FLAG(FLAGB),

    .DI(usb_di),
    .DI_valid(usb_di_valid),
    .DI_ready(usb_di_ready),
    .DI_enable(1'b1),
    .pktend_arm(pktend_arm),

    .pktend_timeout(16'd8),

    .DO(usb_do),
    .DO_valid(usb_do_valid),
    .DO_ready(usb_do_ready),

    .status(io_status)
  );

  localparam real MMCM_MULT_F   = MMCM_MULT_MILLI   / 1000.0;
  localparam real MMCM_OUTDIV_F = MMCM_OUTDIV_MILLI / 1000.0;

  wire fxclk;
  wire core_clk_raw;
  wire core_fb_out;
  wire core_fb_in;
  wire core_locked;
  wire clk_core;

  wire core2x_clk_raw;
  wire clk_core2x;

  IBUFG fxclk_ibuf (.I(fxclk_in), .O(fxclk));

  BUFG core_fb_buf (.I(core_fb_out), .O(core_fb_in));

  BUFG core_clk_buf (.I(core_clk_raw), .O(clk_core));

  generate
  if (CSLOW == 2) begin : core2x
    BUFG core2x_clk_buf (.I(core2x_clk_raw), .O(clk_core2x));
  end
  else begin : core1x
    assign clk_core2x = clk_core;
  end
  endgenerate

  MMCME2_BASE #(
    .BANDWIDTH("OPTIMIZED"),
    .CLKIN1_PERIOD(20.833),
    .DIVCLK_DIVIDE(MMCM_DIVCLK),
    .CLKFBOUT_MULT_F(MMCM_MULT_F),
    .CLKFBOUT_PHASE(0.0),
    .CLKOUT0_DIVIDE_F(MMCM_OUTDIV_F),
    .CLKOUT0_DUTY_CYCLE(0.5),
    .CLKOUT0_PHASE(0.0),
    .CLKOUT1_DIVIDE(MMCM_OUT1DIV),
    .CLKOUT1_DUTY_CYCLE(0.5),
    .CLKOUT1_PHASE(0.0),
    .CLKOUT4_CASCADE("FALSE"),
    .REF_JITTER1(0.0),
    .STARTUP_WAIT("FALSE")
  ) core_mmcm (
    .CLKOUT0(core_clk_raw),
    .CLKOUT1(core2x_clk_raw),
    .CLKFBOUT(core_fb_out),
    .CLKFBIN(core_fb_in),
    .CLKIN1(fxclk),
    .LOCKED(core_locked),
    .PWRDWN(1'b0),
    .RST(reset)
  );

  wire [7:0]  lsi_in_addr;
  wire [31:0] lsi_in_data;
  wire        lsi_in_strobe;
  wire [7:0]  lsi_out_addr;
  wire [31:0] lsi_out_data;
  wire        lsi_out_strobe;

  ezusb_lsi lsi (
    .clk(ifclk),
    .reset_in(ifclk_rst),
    .reset(),
    .data_clk(lsi_clk),
    .mosi(lsi_mosi),
    .miso(lsi_miso),
    .stop(lsi_stop),
    .in_addr(lsi_in_addr),
    .in_data(lsi_in_data),
    .in_strobe(lsi_in_strobe),
    .in_valid(),
    .out_addr(lsi_out_addr),
    .out_data(lsi_out_data),
    .out_strobe(lsi_out_strobe)
  );

  wire [31:0] cfg_salt0;
  wire [31:0] cfg_salt1;
  wire [31:0] cfg_salt2;
  wire [31:0] cfg_salt3;
  wire [31:0] cfg_iter_count;
  wire        cfg_framing_reset;
  wire        cfg_mode_dump;
  wire        cfg_toggle;

  wire [127:0] cfg_cmp_bitmap;
  wire [31:0]  cfg_batch_target;
  wire [15:0]  cfg_pad_recs;
  wire [1:0]   cfg_kind;

  wire [31:0] frame_status_if;

  reg [31:0] dbg_in_words  = 32'd0;
  reg [31:0] dbg_in_halves = 32'd0;
  reg [31:0] dbg_out_words = 32'd0;

  reg [31:0] dbg_flagb_low  = 32'd0;
  reg [31:0] dbg_flagb_fall = 32'd0;
  reg [31:0] dbg_resend     = 32'd0;

  reg [31:0] dbg_if_out_low = 32'd0;
  reg [31:0] dbg_arm        = 32'd0;
  reg [31:0] dbg_pktend     = 32'd0;
  reg [31:0] dbg_arm_wait   = 32'd0;

  wire [31:0] die_temp;

  hcfpga_ztex_temp die_sensor (
    .clk(ifclk),
    .rst(ifclk_rst),

    .temp(die_temp)
  );

  hcfpga_ztex_regs #(
    .NUM_CORES(NUM_CORES),
    .CORE_CLK_MHZ(CORE_CLK_MHZ),
    .BUILD_STAMP(BUILD_STAMP),
    .ABI_VERSION(ABI_VERSION)
  ) regs (
    .clk(ifclk),
    .rst(ifclk_rst),

    .in_addr(lsi_in_addr),
    .in_data(lsi_in_data),
    .in_strobe(lsi_in_strobe),
    .out_addr(lsi_out_addr),
    .out_data(lsi_out_data),
    .out_strobe(lsi_out_strobe),

    .salt0(cfg_salt0),
    .salt1(cfg_salt1),
    .salt2(cfg_salt2),
    .salt3(cfg_salt3),
    .iter_count(cfg_iter_count),
    .framing_reset(cfg_framing_reset),
    .mode_dump(cfg_mode_dump),
    .cfg_toggle(cfg_toggle),

    .cmp_bitmap(cfg_cmp_bitmap),
    .batch_target(cfg_batch_target),
    .pad_recs(cfg_pad_recs),
    .cfg_kind(cfg_kind),

    .frame_status(frame_status_if),
    .die_temp(die_temp),

    .dbg_in_words(dbg_in_words),
    .dbg_in_halves(dbg_in_halves),
    .dbg_out_words(dbg_out_words),

    .dbg_flagb_low(dbg_flagb_low),
    .dbg_flagb_fall(dbg_flagb_fall),
    .dbg_resend(dbg_resend),

    .dbg_if_out_low(dbg_if_out_low),
    .dbg_arm(dbg_arm),
    .dbg_pktend(dbg_pktend),
    .dbg_arm_wait(dbg_arm_wait)
  );

  wire rst_if_hard = ifclk_rst;
  wire rst_if      = ifclk_rst | cfg_framing_reset;

  (* ASYNC_REG = "TRUE" *) reg [1:0] rst_core_hard_q = 2'b11;
  (* ASYNC_REG = "TRUE" *) reg [1:0] rst_core_q      = 2'b11;

  always @(posedge clk_core)
  begin
    rst_core_hard_q <= { rst_core_hard_q[0], rst_if_hard };
    rst_core_q      <= { rst_core_q[0],      rst_if      };
  end

  wire rst_core_hard = rst_core_hard_q[1] | (core_locked == 1'b0);
  wire rst_core      = rst_core_q[1]      | (core_locked == 1'b0);

  (* ASYNC_REG = "TRUE" *) reg [1:0] cfg_tog_q = 2'b00;

  reg        cfg_tog_seen = 1'b0;

  reg [31:0] core_salt0 = 32'd0;
  reg [31:0] core_salt1 = 32'd0;
  reg [31:0] core_salt2 = 32'd0;
  reg [31:0] core_salt3 = 32'd0;
  reg [31:0] core_iter_count = 32'd0;
  reg        core_mode_dump = 1'b0;

  reg [127:0] core_cmp_bitmap  = {128{1'b1}};
  reg [31:0]  core_batch_target = 32'd0;
  reg [15:0]  core_pad_recs     = 16'd1;

  reg         core_cmp_load  = 1'b0;
  reg         core_batch_arm = 1'b0;

  wire cfg_new     = (cfg_tog_q[1] != cfg_tog_seen);
  wire cfg_capture = cfg_new || (rst_core_hard == 1'b1);

  always @(posedge clk_core)
  begin
    cfg_tog_q <= { cfg_tog_q[0], cfg_toggle };

    core_cmp_load  <= 1'b0;
    core_batch_arm <= 1'b0;

    if (cfg_capture == 1'b1)
    begin
      cfg_tog_seen <= cfg_tog_q[1];

      core_salt0      <= cfg_salt0;
      core_salt1      <= cfg_salt1;
      core_salt2      <= cfg_salt2;
      core_salt3      <= cfg_salt3;
      core_iter_count <= cfg_iter_count;
      core_mode_dump  <= cfg_mode_dump;

      core_cmp_bitmap   <= cfg_cmp_bitmap;
      core_batch_target <= cfg_batch_target;
      core_pad_recs     <= cfg_pad_recs;
    end

    if (cfg_new == 1'b1)
    begin
      core_cmp_load  <= (cfg_kind == `HCFPGA_ZTEX_KIND_CMP_LOAD);
      core_batch_arm <= (cfg_kind == `HCFPGA_ZTEX_KIND_BATCH_ARM);
    end
  end

  localparam integer H2C_BLOCK_HALVES = H2C_BLOCK_BYTES / 2;
  localparam integer H2C_CNT_BITS     = $clog2(H2C_BLOCK_HALVES);

  reg [H2C_CNT_BITS-1:0] h2c_half_cnt = 0;
  reg [15:0]             h2c_lo       = 16'd0;

  wire in_wr_ready;

  wire in_beat = (usb_do_valid == 1'b1) && (usb_do_ready == 1'b1);
  wire in_high = h2c_half_cnt[0];
  wire in_last = (h2c_half_cnt == (H2C_BLOCK_HALVES - 1));

  assign usb_do_ready = in_wr_ready;

  always @(posedge ifclk)
  begin
    if (rst_if == 1'b1)
    begin
      h2c_half_cnt <= 0;
    end
    else if (in_beat == 1'b1)
    begin
      h2c_half_cnt <= h2c_half_cnt + 1'b1;

      if (in_high == 1'b0) h2c_lo <= usb_do;
    end
  end

  wire [32:0] in_fifo_rd_data;
  wire        in_fifo_rd_valid;
  wire        in_fifo_rd_ready;

  hcfpga_ztex_afifo #(
    .WIDTH(33),
    .ADDR_BITS(IN_ADDR_BITS)
  ) in_fifo (
    .wr_clk(ifclk),
    .wr_rst(rst_if),
    .wr_data({ in_last, usb_do, h2c_lo }),
    .wr_valid(in_beat & in_high),
    .wr_ready(in_wr_ready),

    .rd_clk(clk_core),
    .rd_rst(rst_core),
    .rd_data(in_fifo_rd_data),
    .rd_valid(in_fifo_rd_valid),
    .rd_ready(in_fifo_rd_ready)
  );

  wire [31:0] frame_status_core;

  wire [7:0]  m_data;
  wire        m_valid;
  wire        m_ready;
  wire        m_last;

  hcfpga_top #(
    .NUM_CORES(NUM_CORES),
    .NUM_CORES_DIST(NUM_CORES_DIST),
    .INIT_BATCH(INIT_BATCH),
    .DIN_BITS(DIN_BITS),
    .FEED_GROUP(FEED_GROUP),
    .FEED_SHARD(FEED_SHARD),
    .COLLECT_GROUP(COLLECT_GROUP),
    .WITH_DUMP(WITH_DUMP),
    .WITH_CMP(WITH_CMP),
    .CSLOW(CSLOW)
  ) core (
    .CLK(clk_core),
    .CLK_CORE(clk_core2x),
    .rst(rst_core),

    .s_data(in_fifo_rd_data[31:0]),
    .s_valid(in_fifo_rd_valid),
    .s_ready(in_fifo_rd_ready),
    .s_last(in_fifo_rd_data[32]),

    .frame_status(frame_status_core),

    .salt0(core_salt0),
    .salt1(core_salt1),
    .salt2(core_salt2),
    .salt3(core_salt3),
    .iter_count(core_iter_count),
    .mode_dump(core_mode_dump),

    .cmp_bitmap(core_cmp_bitmap),
    .cmp_load(core_cmp_load),

    .batch_target(core_batch_target),
    .batch_arm(core_batch_arm),
    .pad_recs(core_pad_recs),

    .retired_cnt(),

    .m_data(m_data),
    .m_valid(m_valid),
    .m_ready(m_ready),
    .m_last(m_last)
  );

  reg       c2h_half = 1'b0;
  reg [7:0] c2h_lo   = 8'd0;

  wire out_wr_ready;

  wire out_beat = (m_valid == 1'b1) && (m_ready == 1'b1);

  assign m_ready = out_wr_ready;

  always @(posedge clk_core)
  begin
    if (rst_core == 1'b1)
    begin
      c2h_half <= 1'b0;
    end
    else if (out_beat == 1'b1)
    begin
      c2h_half <= ~c2h_half;

      if (c2h_half == 1'b0) c2h_lo <= m_data;
    end
  end

  hcfpga_ztex_afifo #(
    .WIDTH(16),
    .ADDR_BITS(OUT_ADDR_BITS)
  ) out_fifo (
    .wr_clk(clk_core),
    .wr_rst(rst_core),
    .wr_data({ m_data, c2h_lo }),
    .wr_valid(out_beat & c2h_half),
    .wr_ready(out_wr_ready),

    .rd_clk(ifclk),
    .rd_rst(rst_if),
    .rd_data(usb_di),
    .rd_valid(usb_di_valid),
    .rd_ready(usb_di_ready)
  );

  reg [PKTEND_IDLE_BITS-1:0] pktend_idle  = 0;
  reg                        pktend_dirty = 1'b0;

  wire di_beat = (usb_di_valid == 1'b1) && (usb_di_ready == 1'b1);

  always @(posedge ifclk)
  begin
    if (rst_if == 1'b1)
    begin
      pktend_idle  <= 0;
      pktend_dirty <= 1'b0;
      pktend_arm   <= 1'b0;
    end
    else if (di_beat == 1'b1)
    begin
      pktend_idle  <= 0;
      pktend_dirty <= 1'b1;
      pktend_arm   <= 1'b0;
    end
    else if (pktend_idle != { PKTEND_IDLE_BITS{1'b1} })
    begin
      pktend_idle <= pktend_idle + 1'b1;
      pktend_arm  <= 1'b0;
    end
    else
    begin
      pktend_arm   <= pktend_dirty;
      pktend_dirty <= 1'b0;
    end
  end

  (* ASYNC_REG = "TRUE" *) reg [31:0] fs_meta = 32'd0;
  (* ASYNC_REG = "TRUE" *) reg [31:0] fs_sync = 32'd0;

  reg flagb_q  = 1'b1;
  reg resend_q = 1'b0;
  reg pktend_q = 1'b1;

  reg arm_pending = 1'b0;

  always @(posedge ifclk)
  begin
    fs_meta <= frame_status_core;
    fs_sync <= fs_meta;

    flagb_q  <= FLAGB;
    resend_q <= io_resend;
    pktend_q <= PKTEND;

    if (rst_if_hard == 1'b1)
    begin
      arm_pending <= 1'b0;
    end
    else if (pktend_arm == 1'b1)
    begin
      arm_pending <= 1'b1;
    end
    else if (PKTEND == 1'b0)
    begin
      arm_pending <= 1'b0;
    end

    if (rst_if_hard == 1'b1)
    begin
      dbg_in_words   <= 32'd0;
      dbg_in_halves  <= 32'd0;
      dbg_out_words  <= 32'd0;
      dbg_flagb_low  <= 32'd0;
      dbg_flagb_fall <= 32'd0;
      dbg_resend     <= 32'd0;
      dbg_if_out_low <= 32'd0;
      dbg_arm        <= 32'd0;
      dbg_pktend     <= 32'd0;
      dbg_arm_wait   <= 32'd0;
    end
    else
    begin
      if ((in_beat == 1'b1) && (in_high == 1'b1)) dbg_in_words  <= dbg_in_words  + 1'b1;

      if (in_beat == 1'b1)                        dbg_in_halves <= dbg_in_halves + 1'b1;
      if (di_beat == 1'b1)                        dbg_out_words <= dbg_out_words + 1'b1;

      if (FLAGB == 1'b0) dbg_flagb_low <= dbg_flagb_low + 1'b1;

      if ((flagb_q  == 1'b1) && (FLAGB     == 1'b0)) dbg_flagb_fall <= dbg_flagb_fall + 1'b1;
      if ((resend_q == 1'b0) && (io_resend == 1'b1)) dbg_resend     <= dbg_resend     + 1'b1;

      if (io_if_out   == 1'b0) dbg_if_out_low <= dbg_if_out_low + 1'b1;
      if (arm_pending == 1'b1) dbg_arm_wait   <= dbg_arm_wait   + 1'b1;

      if (pktend_arm == 1'b1)                       dbg_arm    <= dbg_arm    + 1'b1;
      if ((pktend_q == 1'b1) && (PKTEND == 1'b0))   dbg_pktend <= dbg_pktend + 1'b1;
    end
  end

  assign frame_status_if = fs_sync;

endmodule

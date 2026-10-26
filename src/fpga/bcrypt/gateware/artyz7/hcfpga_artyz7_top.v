/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps

module hcfpga_artyz7_top #(
  parameter NUM_CORES      = 68,
  parameter NUM_CORES_DIST = 0,
  parameter DIN_BITS       = 32,
  parameter INIT_BATCH     = 0,
  parameter FEED_GROUP     = 0,
  parameter FEED_SHARD     = 0,
  parameter COLLECT_GROUP  = 0,
  parameter WITH_DUMP      = 1,
  parameter WITH_CMP       = 1,

  parameter CORE_CLK_MHZ   = 0,
  parameter BUILD_STAMP    = 0,
  parameter ABI_VERSION    = 0,

  parameter TX_DEPTH       = 1024,
  parameter RX_DEPTH       = 256
)(
  input  wire        s_axi_aclk,
  input  wire        s_axi_aresetn,

  input  wire [11:0] s_axi_awaddr,
  input  wire        s_axi_awvalid,
  output wire        s_axi_awready,

  input  wire [31:0] s_axi_wdata,
  input  wire [3:0]  s_axi_wstrb,
  input  wire        s_axi_wvalid,
  output wire        s_axi_wready,

  output wire [1:0]  s_axi_bresp,
  output wire        s_axi_bvalid,
  input  wire        s_axi_bready,

  input  wire [11:0] s_axi_araddr,
  input  wire        s_axi_arvalid,
  output wire        s_axi_arready,

  output reg  [31:0] s_axi_rdata,
  output wire [1:0]  s_axi_rresp,
  output wire        s_axi_rvalid,
  input  wire        s_axi_rready
);

  localparam ADDR_CTRL         = 8'h00;
  localparam ADDR_SALT0        = 8'h04;
  localparam ADDR_SALT1        = 8'h08;
  localparam ADDR_SALT2        = 8'h0C;
  localparam ADDR_SALT3        = 8'h10;
  localparam ADDR_ITER_COUNT   = 8'h14;
  localparam ADDR_STATUS       = 8'h18;
  localparam ADDR_CORE_COUNT   = 8'h1C;
  localparam ADDR_CMP_BM0      = 8'h20;
  localparam ADDR_CMP_BM1      = 8'h24;
  localparam ADDR_CMP_BM2      = 8'h28;
  localparam ADDR_CMP_BM3      = 8'h2C;
  localparam ADDR_BATCH_TARGET = 8'h30;
  localparam ADDR_PAD_RECS     = 8'h34;
  localparam ADDR_RETIRED      = 8'h38;

  localparam ADDR_TX_DATA      = 8'h40;
  localparam ADDR_TX_STAT      = 8'h44;
  localparam ADDR_RX_DATA      = 8'h48;
  localparam ADDR_RX_STAT      = 8'h4C;
  localparam ADDR_BENCH_CYCLES = 8'h50;
  localparam ADDR_BENCH_STAT   = 8'h54;
  localparam ADDR_MAGIC        = 8'h5C;

  localparam ADDR_ABI          = 8'h60;
  localparam ADDR_ALGO_LO      = 8'h64;
  localparam ADDR_ALGO_HI      = 8'h68;
  localparam ADDR_CLK_MHZ      = 8'h6C;
  localparam ADDR_BUILD        = 8'h70;

  localparam MAGIC_VALUE       = 32'h7A7_00068;

  localparam ALGO_LO_VALUE     = 32'h79726362;
  localparam ALGO_HI_VALUE     = 32'h00007470;

  reg [31:0] reg_ctrl;
  reg [31:0] reg_salt0;
  reg [31:0] reg_salt1;
  reg [31:0] reg_salt2;
  reg [31:0] reg_salt3;
  reg [31:0] reg_iter_count;
  reg [31:0] reg_cmp_bm0;
  reg [31:0] reg_cmp_bm1;
  reg [31:0] reg_cmp_bm2;
  reg [31:0] reg_cmp_bm3;
  reg [31:0] reg_batch_target;
  reg [15:0] reg_pad_recs;

  reg        pulse_cmp_load;
  reg        pulse_batch_arm;

  wire [31:0] frame_status;
  wire [31:0] retired_cnt;

  reg        awready;
  reg        wready;
  reg        bvalid;

  wire [7:0] wr_addr = s_axi_awaddr[7:0];
  wire [7:0] rd_addr = s_axi_araddr[7:0];

  assign s_axi_awready = awready;
  assign s_axi_wready  = wready;
  assign s_axi_bvalid  = bvalid;
  assign s_axi_bresp   = 2'b00;

  wire wr_fire = (s_axi_awvalid == 1'b1) && (s_axi_wvalid == 1'b1) && (awready == 1'b0) && (wready == 1'b0) && (bvalid == 1'b0);

  localparam TX_AW = $clog2(TX_DEPTH);

  reg [31:0]      tx_mem [0:TX_DEPTH-1];
  reg [TX_AW:0]   tx_wptr;
  reg [TX_AW:0]   tx_rptr;

  wire [TX_AW:0]  tx_level = tx_wptr - tx_rptr;
  wire            tx_full  = (tx_level == TX_DEPTH);
  wire            tx_empty = (tx_level == 0);

  wire [15:0]     tx_level_w = {{(15-TX_AW){1'b0}}, tx_level};

  localparam RX_AW = $clog2(RX_DEPTH);

  reg [7:0]       rx_mem [0:RX_DEPTH-1];
  reg [RX_AW:0]   rx_wptr;
  reg [RX_AW:0]   rx_rptr;

  wire [RX_AW:0]  rx_level = rx_wptr - rx_rptr;
  wire            rx_full  = (rx_level == RX_DEPTH);
  wire            rx_empty = (rx_level == 0);

  wire [15:0]     rx_level_w = {{(15-RX_AW){1'b0}}, rx_level};

  reg         feed_enable;

  wire [31:0] s_data  = tx_mem[tx_rptr[TX_AW-1:0]];
  wire        s_valid = (tx_empty == 1'b0) && (feed_enable == 1'b1);
  wire        s_ready;

  wire        s_last = 1'b0;

  wire [7:0]  m_data;
  wire        m_valid;
  wire        m_last;
  wire        m_ready = (rx_full == 1'b0);

  reg [31:0] bench_cycles;
  reg        bench_running;
  reg        bench_valid;

  wire       array_rst = (s_axi_aresetn == 1'b0) || (reg_ctrl[0] == 1'b1);

  always @(posedge s_axi_aclk)
  begin
    if (s_axi_aresetn == 1'b0)
    begin
      bench_cycles  <= 32'd0;
      bench_running <= 1'b0;
      bench_valid   <= 1'b0;
    end
    else if (pulse_batch_arm == 1'b1)
    begin
      bench_cycles  <= 32'd0;
      bench_running <= (reg_batch_target != 32'd0);
      bench_valid   <= 1'b0;
    end
    else if (bench_running == 1'b1)
    begin
      if (retired_cnt >= reg_batch_target)
      begin
        bench_running <= 1'b0;
        bench_valid   <= 1'b1;
      end
      else
      begin
        bench_cycles <= bench_cycles + 32'd1;
      end
    end
  end

  always @(posedge s_axi_aclk)
  begin
    if (s_axi_aresetn == 1'b0)
    begin
      awready          <= 1'b0;
      wready           <= 1'b0;
      bvalid           <= 1'b0;

      reg_ctrl         <= 32'd0;
      reg_salt0        <= 32'd0;
      reg_salt1        <= 32'd0;
      reg_salt2        <= 32'd0;
      reg_salt3        <= 32'd0;
      reg_iter_count   <= 32'd0;
      reg_cmp_bm0      <= 32'd0;
      reg_cmp_bm1      <= 32'd0;
      reg_cmp_bm2      <= 32'd0;
      reg_cmp_bm3      <= 32'd0;
      reg_batch_target <= 32'd0;
      reg_pad_recs     <= 16'd0;

      pulse_cmp_load   <= 1'b0;
      pulse_batch_arm  <= 1'b0;

      tx_wptr          <= 0;
    end
    else
    begin
      pulse_cmp_load  <= 1'b0;
      pulse_batch_arm <= 1'b0;

      awready <= 1'b0;
      wready  <= 1'b0;

      if (wr_fire == 1'b1)
      begin
        awready <= 1'b1;
        wready  <= 1'b1;
        bvalid  <= 1'b1;

        case (wr_addr)
          ADDR_CTRL:         reg_ctrl         <= s_axi_wdata;
          ADDR_SALT0:        reg_salt0        <= s_axi_wdata;
          ADDR_SALT1:        reg_salt1        <= s_axi_wdata;
          ADDR_SALT2:        reg_salt2        <= s_axi_wdata;
          ADDR_SALT3:        reg_salt3        <= s_axi_wdata;
          ADDR_ITER_COUNT:   reg_iter_count   <= s_axi_wdata;
          ADDR_CMP_BM0:      reg_cmp_bm0      <= s_axi_wdata;
          ADDR_CMP_BM1:      reg_cmp_bm1      <= s_axi_wdata;
          ADDR_CMP_BM2:      reg_cmp_bm2      <= s_axi_wdata;

          ADDR_CMP_BM3:
          begin
            reg_cmp_bm3    <= s_axi_wdata;
            pulse_cmp_load <= 1'b1;
          end

          ADDR_BATCH_TARGET:
          begin
            reg_batch_target <= s_axi_wdata;
            pulse_batch_arm  <= 1'b1;
          end

          ADDR_PAD_RECS:     reg_pad_recs     <= s_axi_wdata[15:0];

          default: ;
        endcase

        if ((wr_addr == ADDR_TX_DATA) && (tx_full == 1'b0))
        begin
          tx_mem[tx_wptr[TX_AW-1:0]] <= s_axi_wdata;
          tx_wptr                    <= tx_wptr + 1;
        end
      end

      if ((bvalid == 1'b1) && (s_axi_bready == 1'b1)) bvalid <= 1'b0;

      if (reg_ctrl[0] == 1'b1) tx_wptr <= 0;
    end
  end

  always @(posedge s_axi_aclk)
  begin
    if ((s_axi_aresetn == 1'b0) || (array_rst == 1'b1))
    begin
      tx_rptr     <= 0;
      rx_wptr     <= 0;
      feed_enable <= 1'b0;
    end
    else
    begin
      if (pulse_batch_arm == 1'b1) feed_enable <= 1'b1;

      if ((s_valid == 1'b1) && (s_ready == 1'b1)) tx_rptr <= tx_rptr + 1;

      if ((m_valid == 1'b1) && (m_ready == 1'b1))
      begin
        rx_mem[rx_wptr[RX_AW-1:0]] <= m_data;
        rx_wptr                    <= rx_wptr + 1;
      end
    end
  end

  reg arready;
  reg rvalid;

  assign s_axi_arready = arready;
  assign s_axi_rvalid  = rvalid;
  assign s_axi_rresp   = 2'b00;

  wire rd_fire = (s_axi_arvalid == 1'b1) && (arready == 1'b0) && (rvalid == 1'b0);

  always @(posedge s_axi_aclk)
  begin
    if (s_axi_aresetn == 1'b0)
    begin
      arready <= 1'b0;
      rvalid  <= 1'b0;
      rx_rptr <= 0;
    end
    else
    begin
      arready <= 1'b0;

      if (rd_fire == 1'b1)
      begin
        arready <= 1'b1;
        rvalid  <= 1'b1;

        case (rd_addr)
          ADDR_CTRL:         s_axi_rdata <= reg_ctrl;
          ADDR_SALT0:        s_axi_rdata <= reg_salt0;
          ADDR_SALT1:        s_axi_rdata <= reg_salt1;
          ADDR_SALT2:        s_axi_rdata <= reg_salt2;
          ADDR_SALT3:        s_axi_rdata <= reg_salt3;
          ADDR_ITER_COUNT:   s_axi_rdata <= reg_iter_count;
          ADDR_STATUS:       s_axi_rdata <= frame_status;
          ADDR_CORE_COUNT:   s_axi_rdata <= NUM_CORES;
          ADDR_CMP_BM0:      s_axi_rdata <= reg_cmp_bm0;
          ADDR_CMP_BM1:      s_axi_rdata <= reg_cmp_bm1;
          ADDR_CMP_BM2:      s_axi_rdata <= reg_cmp_bm2;
          ADDR_CMP_BM3:      s_axi_rdata <= reg_cmp_bm3;
          ADDR_BATCH_TARGET: s_axi_rdata <= reg_batch_target;
          ADDR_PAD_RECS:     s_axi_rdata <= {16'd0, reg_pad_recs};
          ADDR_RETIRED:      s_axi_rdata <= retired_cnt;

          ADDR_TX_STAT:      s_axi_rdata <= {tx_level_w, 14'd0, tx_empty, tx_full};
          ADDR_RX_STAT:      s_axi_rdata <= {rx_level_w, 14'd0, rx_full,  rx_empty};

          ADDR_BENCH_CYCLES: s_axi_rdata <= bench_cycles;
          ADDR_BENCH_STAT:   s_axi_rdata <= {30'd0, bench_valid, bench_running};
          ADDR_MAGIC:        s_axi_rdata <= MAGIC_VALUE;

          ADDR_ABI:          s_axi_rdata <= ABI_VERSION;
          ADDR_ALGO_LO:      s_axi_rdata <= ALGO_LO_VALUE;
          ADDR_ALGO_HI:      s_axi_rdata <= ALGO_HI_VALUE;
          ADDR_CLK_MHZ:      s_axi_rdata <= CORE_CLK_MHZ;
          ADDR_BUILD:        s_axi_rdata <= BUILD_STAMP;

          ADDR_RX_DATA:
          begin
            s_axi_rdata <= {24'd0, rx_mem[rx_rptr[RX_AW-1:0]]};

            if (rx_empty == 1'b0) rx_rptr <= rx_rptr + 1;
          end

          default: s_axi_rdata <= 32'd0;
        endcase
      end

      if ((rvalid == 1'b1) && (s_axi_rready == 1'b1)) rvalid <= 1'b0;

      if (array_rst == 1'b1) rx_rptr <= 0;
    end
  end

  hcfpga_top #(
    .NUM_CORES      (NUM_CORES),
    .NUM_CORES_DIST (NUM_CORES_DIST),
    .DIN_BITS       (DIN_BITS),
    .INIT_BATCH     (INIT_BATCH),
    .FEED_GROUP     (FEED_GROUP),
    .FEED_SHARD     (FEED_SHARD),
    .COLLECT_GROUP  (COLLECT_GROUP),
    .WITH_DUMP      (WITH_DUMP),
    .WITH_CMP       (WITH_CMP)
  ) array (
    .CLK          (s_axi_aclk),
    .CLK_CORE     (s_axi_aclk),
    .rst          (array_rst),

    .s_data       (s_data),
    .s_valid      (s_valid),
    .s_ready      (s_ready),
    .s_last       (s_last),

    .frame_status (frame_status),

    .salt0        (reg_salt0),
    .salt1        (reg_salt1),
    .salt2        (reg_salt2),
    .salt3        (reg_salt3),
    .iter_count   (reg_iter_count),
    .mode_dump    (reg_ctrl[1]),

    .cmp_bitmap   ({reg_cmp_bm3, reg_cmp_bm2, reg_cmp_bm1, reg_cmp_bm0}),
    .cmp_load     (pulse_cmp_load),

    .batch_target (reg_batch_target),
    .batch_arm    (pulse_batch_arm),
    .pad_recs     (reg_pad_recs),
    .retired_cnt  (retired_cnt),

    .m_data       (m_data),
    .m_valid      (m_valid),
    .m_ready      (m_ready),
    .m_last       (m_last)
  );

endmodule

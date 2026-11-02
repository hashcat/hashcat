/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_feed_group #(
  parameter NUM_CORES = 4,
  parameter INIT_BATCH = 0,
  parameter DIN_BITS = 32,

  parameter GROUP = 0,

  parameter NENG = (GROUP == 0) ? 1 : ((NUM_CORES + GROUP - 1) / GROUP)
)(
  input  wire CLK,
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

  output wire [NENG*DIN_BITS-1:0] c_din,
  output wire [NENG*4-1:0]        c_bwe,
  output wire [NENG-1:0]          c_start,
  output wire [NUM_CORES-1:0]     c_wr_en,

  input  wire [NUM_CORES-1:0] core_init_ready,
  input  wire [NUM_CORES-1:0] core_crypt_ready
);

  localparam CPE  = (GROUP == 0) ? NUM_CORES : GROUP;
  localparam EW   = (NENG <= 1) ? 1 : $clog2 (NENG);

  generate
  if (GROUP == 0)
  begin : single

    hcfpga_feed #(.NUM_CORES(NUM_CORES), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS)) f (
      .CLK(CLK), .rst(rst),
      .s_data(s_data), .s_valid(s_valid), .s_ready(s_ready), .s_last(s_last),
      .frame_status(frame_status),
      .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3), .iter_count(iter_count),
      .c_din(c_din), .c_bwe(c_bwe), .c_start(c_start), .c_wr_en(c_wr_en),
      .core_init_ready(core_init_ready), .core_crypt_ready(core_crypt_ready)
    );

  end
  else
  begin : sharded

    wire [NENG*CPE-1:0] pad_init_ready;
    wire [NENG*CPE-1:0] pad_crypt_ready;
    wire [NENG*CPE-1:0] pad_wr_en;

    genvar b;

    for (b = 0; b < NENG*CPE; b = b + 1)
    begin : padbits
      if (b < NUM_CORES)
      begin : present
        assign pad_init_ready[b]  = core_init_ready[b];
        assign pad_crypt_ready[b] = core_crypt_ready[b];
        assign c_wr_en[b]         = pad_wr_en[b];
      end
      else
      begin : absent
        assign pad_init_ready[b]  = 1'b0;
        assign pad_crypt_ready[b] = 1'b0;
      end
    end

    localparam [7:0] SP_TAG    = 8'hbc;
    localparam [7:0] SP_PW_MAX = 8'd72;

    reg [EW-1:0] tgt = 0;
    reg [4:0]    sp_wcnt = 0;
    reg [4:0]    sp_words = 5'd2;

    wire [NENG-1:0] e_ready;

    wire at_boundary = (sp_wcnt == 5'd0);
    wire tgt_ready   = e_ready[tgt];

    assign s_ready = tgt_ready;

    wire       sp_bad   = (s_data[31:24] != SP_TAG) || (s_data[7:0] > SP_PW_MAX);
    wire [7:0] sp_len   = sp_bad ? 8'd0 : s_data[7:0];
    wire [4:0] sp_hdr_w = 5'd2 + sp_len[6:2] + ((sp_len[1:0] != 2'd0) ? 5'd1 : 5'd0);

    always @(posedge CLK)
    begin
      if (rst == 1'b1)
      begin
        tgt      <= 0;
        sp_wcnt  <= 0;
        sp_words <= 5'd2;
      end
      else
      begin
        if (s_valid & s_ready)
        begin
          if ((at_boundary == 1'b1) && (sp_bad == 1'b0)) sp_words <= sp_hdr_w;

          if ((at_boundary == 1'b1) && (sp_bad == 1'b1))
          begin
            sp_wcnt <= 0;
          end
          else if (sp_wcnt == (sp_words - 1'b1))
          begin
            sp_wcnt <= 0;
            tgt     <= (tgt == NENG-1) ? {EW{1'b0}} : tgt + 1'b1;
          end
          else
            sp_wcnt <= sp_wcnt + 1'b1;
        end
        else if ((at_boundary == 1'b1) && (tgt_ready == 1'b0))
        begin
          tgt <= (tgt == NENG-1) ? {EW{1'b0}} : tgt + 1'b1;
        end
      end
    end

    wire [NENG-1:0]      e_slip;
    wire [NENG-1:0]      e_last_seen;
    wire [32*NENG-1:0]   e_status;

    genvar g;

    for (g = 0; g < NENG; g = g + 1)
    begin : eng
      wire sel = (tgt == g);

      hcfpga_feed #(.NUM_CORES(CPE), .INIT_BATCH(INIT_BATCH), .DIN_BITS(DIN_BITS), .ADMIT_GATE(1)) f (
        .CLK(CLK), .rst(rst),
        .s_data(s_data),
        .s_valid(s_valid & sel),
        .s_ready(e_ready[g]),
        .s_last(s_last & sel),
        .frame_status(e_status[32*g +: 32]),
        .salt0(salt0), .salt1(salt1), .salt2(salt2), .salt3(salt3), .iter_count(iter_count),
        .c_din(c_din[DIN_BITS*g +: DIN_BITS]),
        .c_bwe(c_bwe[4*g +: 4]),
        .c_start(c_start[g]),
        .c_wr_en(pad_wr_en[CPE*g +: CPE]),
        .core_init_ready(pad_init_ready[CPE*g +: CPE]),
        .core_crypt_ready(pad_crypt_ready[CPE*g +: CPE])
      );

      assign e_slip[g]      = e_status[32*g + 0];
      assign e_last_seen[g] = e_status[32*g + 1];
    end

    integer    si;
    reg [15:0] slip_sum;

    always @(*)
    begin
      slip_sum = 16'd0;

      for (si = 0; si < NENG; si = si + 1)
      begin
        slip_sum = slip_sum + { 8'd0, e_status[32*si + 8 +: 8] };
      end
    end

    reg [7:0] slip_tot = 8'd0;

    always @(posedge CLK)
    begin
      if (rst == 1'b1) slip_tot <= 8'd0;
      else             slip_tot <= (slip_sum > 16'd255) ? 8'hff : slip_sum[7:0];
    end

    assign frame_status = {16'd0, slip_tot, 6'd0, |e_last_seen, |e_slip};

  end
  endgenerate

endmodule

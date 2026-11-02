/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_collect_group #(
  parameter NUM_CORES = 4,

  parameter GROUP = 0,

  parameter WITH_CMP = 1
)(
  input  wire CLK,
  input  wire rst,

  input  wire [NUM_CORES-1:0] core_empty,
  input  wire [NUM_CORES-1:0] core_dout,
  output wire [NUM_CORES-1:0] core_rd_en,

  input  wire [31:0] batch_target,
  input  wire        batch_arm,

  input  wire [15:0] pad_recs,

  output wire [31:0] retired_cnt,

  output wire [7:0] m_data,
  output wire       m_valid,
  input  wire       m_ready,
  output wire       m_last
);

  localparam [15:0] FLAG_EOB = 16'h8000;

  localparam EGROUP = (GROUP == 0) ? NUM_CORES : GROUP;
  localparam NENG   = (NUM_CORES + EGROUP - 1) / EGROUP;

  localparam NSRC = NENG + 1;
  localparam SW   = (NSRC <= 1) ? 1 : $clog2(NSRC);

  localparam [SW-1:0] EOB_SEL = NENG;

  wire [NENG*EGROUP-1:0] pad_empty;
  wire [NENG*EGROUP-1:0] pad_dout;
  wire [NENG*EGROUP-1:0] pad_rd_en;

  genvar b;

  generate
  for (b = 0; b < NENG*EGROUP; b = b + 1)
  begin : padbits
    if (b < NUM_CORES)
    begin : present
      assign pad_empty[b]  = core_empty[b];
      assign pad_dout[b]   = core_dout[b];
      assign core_rd_en[b] = pad_rd_en[b];
    end
    else
    begin : absent
      assign pad_empty[b] = 1'b1;
      assign pad_dout[b]  = 1'b0;
    end
  end
  endgenerate

  wire [8*NSRC-1:0] e_data;
  wire [NSRC-1:0]   e_valid;
  wire [NSRC-1:0]   e_last;
  wire [NSRC-1:0]   e_ready;

  wire [NENG-1:0]   e_retire;

  genvar g;

  generate
  for (g = 0; g < NENG; g = g + 1)
  begin : eng
    hcfpga_collect #(.NUM_CORES(EGROUP), .CORE_BASE(g * EGROUP), .WITH_CMP(WITH_CMP)) c (
      .CLK(CLK), .rst(rst),
      .core_empty(pad_empty [g*EGROUP +: EGROUP]),
      .core_dout (pad_dout  [g*EGROUP +: EGROUP]),
      .core_rd_en(pad_rd_en [g*EGROUP +: EGROUP]),
      .retire (e_retire[g]),
      .m_data (e_data[8*g +: 8]),
      .m_valid(e_valid[g]),
      .m_ready(e_ready[g]),
      .m_last (e_last[g])
    );
  end
  endgenerate

  localparam RW = (NENG <= 1) ? 1 : $clog2(NENG + 1);

  reg [RW-1:0] retire_add = 0;

  integer k;

  always @(*)
  begin
    retire_add = 0;

    for (k = 0; k < NENG; k = k + 1) retire_add = retire_add + e_retire[k];
  end

  reg [RW-1:0] retire_add_r = 0;
  reg [31:0]   retired      = 0;

  always @(posedge CLK)
  begin
    if ((rst == 1'b1) || (batch_arm == 1'b1))
    begin
      retire_add_r <= 0;
      retired      <= 0;
    end
    else
    begin
      retire_add_r <= retire_add;
      retired      <= retired + retire_add_r;
    end
  end

  assign retired_cnt = retired;

  reg        armed  = 0;
  reg [31:0] target = 0;

  reg [15:0] pad_pos = 0;

  wire [15:0] pad_mod = (pad_recs >= 16'd2) ? pad_recs : 16'd1;

  wire rec_out = m_valid & m_ready & m_last;

  reg [255:0] eob_frame = 0;
  reg [5:0]   eob_byte  = 0;
  reg         eob_busy  = 0;
  reg         eob_emit  = 0;

  wire [31:0] eob_cnt = retired;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      armed    <= 0;
      target   <= 0;
      pad_pos  <= 0;
      eob_busy <= 0;
      eob_emit <= 0;
      eob_byte <= 0;
    end
    else
    begin
      if (batch_arm == 1'b1)
      begin
        armed    <= (batch_target != 32'd0);
        target   <= batch_target;
        pad_pos  <= 0;
        eob_busy <= 0;
        eob_emit <= 0;
      end

      if (rec_out == 1'b1) pad_pos <= ((pad_pos + 16'd1) == pad_mod) ? 16'd0 : (pad_pos + 16'd1);

      if (eob_emit == 1'b0)
      begin
        if ((armed == 1'b1) && (eob_busy == 1'b1) && (retired >= target))
        begin
          eob_frame <= {
            FLAG_EOB[15:8], FLAG_EOB[7:0],
            8'h00, 8'h00,
            192'd0,
            eob_cnt[31:24], eob_cnt[23:16], eob_cnt[15:8], eob_cnt[7:0]
          };

          eob_byte <= 0;
          eob_emit <= 1;
        end
        else if ((armed == 1'b1) && (retired >= target))
        begin
          eob_busy <= 1;
        end
      end
      else
      begin
        if (e_ready[NENG] == 1'b1)
        begin
          if (eob_byte == 6'd31)
          begin
            eob_emit <= 0;

            if ((pad_pos + 16'd1) == pad_mod)
            begin
              eob_busy <= 0;
              armed    <= 0;
            end
          end
          else
          begin
            eob_frame <= eob_frame >> 8;
            eob_byte  <= eob_byte + 1'b1;
          end
        end
      end
    end
  end

  assign e_data[8*NENG +: 8] = eob_frame[7:0];
  assign e_valid[NENG]       = eob_emit;
  assign e_last[NENG]        = eob_emit & (eob_byte == 6'd31);

  reg [SW-1:0] sel  = 0;
  reg          busy = 0;

  wire [SW-1:0] arb_sel = (eob_busy == 1'b1) ? EOB_SEL : sel;

  wire sel_valid = e_valid[arb_sel];
  wire sel_last  = e_last[arb_sel];

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      sel  <= 0;
      busy <= 0;
    end
    else if (busy == 1'b0)
    begin
      if (sel_valid == 1'b1) busy <= 1'b1;
      else                   sel  <= (sel == NSRC-1) ? {SW{1'b0}} : sel + 1'b1;
    end
    else if ((m_ready == 1'b1) && (sel_valid == 1'b1) && (sel_last == 1'b1))
    begin
      busy <= 1'b0;

      sel <= (sel == NSRC-1) ? {SW{1'b0}} : sel + 1'b1;
    end
  end

  assign m_data  = e_data[8*arb_sel +: 8];
  assign m_valid = busy & sel_valid;
  assign m_last  = busy & sel_valid & sel_last;

  generate
  for (g = 0; g < NSRC; g = g + 1)
  begin : rdy
    assign e_ready[g] = busy & (arb_sel == g) & m_ready;
  end
  endgenerate

endmodule

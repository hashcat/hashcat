/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

`timescale 1ns / 1ps
module hcfpga_feed #(
  parameter NUM_CORES = 4,
  parameter INIT_BATCH = 0,

  parameter DIN_BITS = 32,

  parameter ADMIT_GATE = 0
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

  (* max_fanout = 32 *) output reg  [DIN_BITS-1:0]  c_din = 0,
  (* max_fanout = 32 *) output reg  [3:0]           c_bwe = 0,
  (* max_fanout = 32 *) output reg                  c_start = 0,
  output reg  [NUM_CORES-1:0] c_wr_en = 0,

  input  wire [NUM_CORES-1:0] core_init_ready,
  input  wire [NUM_CORES-1:0] core_crypt_ready
);

  localparam INIT_WORDS = 11'd1054;
  localparam DATA_WORDS = 11'd31;

  localparam [7:0] H2C_TAG = 8'hbc;
  localparam [7:0] PW_MAX  = 8'd72;

  (* ROM_STYLE = "block" *)
  reg [31:0] initimg [0:1053];
  integer k;
  initial begin
    initimg[ 0]=32'h243f6a88; initimg[ 1]=32'h85a308d3; initimg[ 2]=32'h13198a2e; initimg[ 3]=32'h03707344;
    initimg[ 4]=32'ha4093822; initimg[ 5]=32'h299f31d0; initimg[ 6]=32'h082efa98; initimg[ 7]=32'hec4e6c89;
    initimg[ 8]=32'h452821e6; initimg[ 9]=32'h38d01377; initimg[10]=32'hbe5466cf; initimg[11]=32'h34e90c6c;
    initimg[12]=32'hc0ac29b7; initimg[13]=32'hc97c50dd; initimg[14]=32'h3f84d5b5; initimg[15]=32'hb5470917;
    initimg[16]=32'h9216d5d9; initimg[17]=32'h8979fb1b;
    for (k=18; k<24; k=k+1) initimg[k] = 32'h0;
    initimg[24]=32'h65616E42; initimg[25]=32'h4F727068; initimg[26]=32'h64657253;
    initimg[27]=32'h65686F6C; initimg[28]=32'h6F756274; initimg[29]=32'h63727944;
    `include "hcfpga_sbox_init.vh"
  end

  reg [31:0] pw_buf   [0:35];
  reg [31:0] ek_buf   [0:35];
  reg [7:0]  pwlen_buf[0:1];
  reg [31:0] ekid_buf [0:1];

  reg [4:0]  in_wcnt   = 0;
  reg [4:0]  rec_words = 5'd2;
  reg        in_slot   = 0;
  reg        out_slot  = 0;
  reg        exp_slot  = 0;

  reg [1:0]  slot_filled = 0;
  reg [1:0]  slot_ready  = 0;

  reg cand_consume = 0;

  reg exp_ack      = 0;
  reg exp_ack_slot = 0;

  wire [5:0] in_base  = in_slot  ? 6'd18 : 6'd0;
  wire [5:0] out_base = out_slot ? 6'd18 : 6'd0;
  wire [5:0] exp_base = exp_slot ? 6'd18 : 6'd0;

  wire cand_valid = slot_ready[out_slot];

  wire s_ready_slot = (rst == 1'b0) & (slot_filled[in_slot] == 1'b0) & (slot_ready[in_slot] == 1'b0);

  reg       frame_slip = 0;
  reg       last_seen  = 0;
  reg [7:0] slip_count = 0;

  assign frame_status = {16'd0, slip_count, 6'd0, last_seen, frame_slip};

  wire       hdr_word = (in_wcnt == 5'd0);
  wire       hdr_bad  = (s_data[31:24] != H2C_TAG) | (s_data[7:0] > PW_MAX);
  wire [7:0] hdr_len  = hdr_bad ? 8'd0 : s_data[7:0];

  wire [4:0] hdr_words = 5'd2 + hdr_len[6:2] + ((hdr_len[1:0] != 2'd0) ? 5'd1 : 5'd0);

  wire rec_end = (s_valid & s_ready) & (in_wcnt == (rec_words - 1'b1));

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      in_wcnt     <= 0;
      rec_words   <= 5'd2;
      in_slot     <= 0;
      out_slot    <= 0;
      slot_filled <= 0;
      frame_slip  <= 0;
      last_seen   <= 0;
      slip_count  <= 0;
    end
    else
    begin
      if (exp_ack == 1'b1)   slot_filled[exp_ack_slot] <= 1'b0;
      if (rec_end == 1'b1)   slot_filled[in_slot]      <= 1'b1;

      if (cand_consume == 1'b1)
        out_slot <= out_slot + 1'b1;

      if (s_valid & s_ready)
      begin
        if ((hdr_word == 1'b1) && (hdr_bad == 1'b1))
        begin
          frame_slip <= 1'b1;

          if (slip_count != 8'hff) slip_count <= slip_count + 1'b1;
        end
        else if (hdr_word == 1'b1)
        begin
          rec_words             <= hdr_words;
          pwlen_buf[in_slot]    <= hdr_len;
        end
        else if (in_wcnt == 5'd1)
          ekid_buf[in_slot] <= s_data;
        else
          pw_buf[in_base + (in_wcnt - 5'd2)] <= s_data;

        if (s_last == 1'b1) last_seen <= 1'b1;

        if ((hdr_word == 1'b1) && (hdr_bad == 1'b1))
        begin
          in_wcnt <= 0;
        end
        else if (in_wcnt == (rec_words - 1'b1))
        begin
          in_wcnt <= 0;
          in_slot <= in_slot + 1'b1;
        end
        else
          in_wcnt <= in_wcnt + 1'b1;
      end
    end
  end

  localparam E_IDLE = 1'b0, E_RUN = 1'b1;

  reg        e_state = E_IDLE;
  reg [6:0]  exp_k   = 0;
  reg [6:0]  exp_idx = 0;
  reg [31:0] exp_acc = 0;

  wire [7:0] exp_len  = pwlen_buf[exp_slot];
  wire [4:0] exp_widx = exp_idx[6:2];

  wire [31:0] exp_word = pw_buf[exp_base + exp_widx];

  reg [7:0] exp_byte;
  always @(*)
  begin
    case (exp_idx[1:0])
      2'd0:    exp_byte = exp_word[31:24];
      2'd1:    exp_byte = exp_word[23:16];
      2'd2:    exp_byte = exp_word[15: 8];
      default: exp_byte = exp_word[ 7: 0];
    endcase
  end

  wire [7:0] exp_src = (exp_idx < exp_len[6:0]) ? exp_byte : 8'h00;

  wire [31:0] exp_out = {exp_acc[23:0], exp_src};

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      e_state    <= E_IDLE;
      exp_k      <= 0;
      exp_idx    <= 0;
      exp_acc    <= 0;
      exp_slot     <= 0;
      exp_ack      <= 0;
      exp_ack_slot <= 0;
      slot_ready   <= 0;
    end
    else
    begin
      exp_ack <= 1'b0;

      if (cand_consume == 1'b1) slot_ready[out_slot] <= 1'b0;

      case (e_state)
      E_IDLE:
      begin
        if ((slot_filled[exp_slot] == 1'b1) && (slot_ready[exp_slot] == 1'b0))
        begin
          exp_k   <= 0;
          exp_idx <= 0;
          exp_acc <= 0;
          e_state <= E_RUN;
        end
      end

      E_RUN:
      begin
        exp_acc <= exp_out;

        if (exp_k[1:0] == 2'd3) ek_buf[exp_base + exp_k[6:2]] <= exp_out;

        if (exp_k == 7'd71)
        begin
          exp_idx <= 7'd0;

          slot_ready[exp_slot] <= 1'b1;

          exp_ack      <= 1'b1;
          exp_ack_slot <= exp_slot;
          exp_slot     <= exp_slot + 1'b1;

          e_state <= E_IDLE;
        end
        else
        begin
          exp_idx <= (exp_idx == exp_len[6:0]) ? 7'd0 : exp_idx + 1'b1;

          exp_k <= exp_k + 1'b1;
        end
      end
      endcase
    end
  end

  wire [NUM_CORES-1:0] crypt_onehot = core_crypt_ready & (~core_crypt_ready + 1'b1);

  wire can_data = cand_valid & (|core_crypt_ready);

  localparam D_CHECK = 0, D_STREAM = 1, D_END = 2, D_GAP = 3;

  reg [1:0]  state = D_CHECK;

  reg [1:0]  settle = 0;

  reg [15:0] ready_cnt = 0;

  reg [15:0] avail_cnt = 0;

  integer    ci;
  reg [15:0] ready_sum;
  reg [15:0] avail_sum;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      ready_cnt <= 0;
      avail_cnt <= 0;
    end
    else
    begin
      ready_sum = 16'd0;
      avail_sum = 16'd0;

      for (ci = 0; ci < NUM_CORES; ci = ci + 1)
      begin
        if (core_init_ready[ci] == 1'b1) ready_sum = ready_sum + 16'd1;

        if ((core_init_ready[ci] | core_crypt_ready[ci]) == 1'b1) avail_sum = avail_sum + 16'd1;
      end

      ready_cnt <= ready_sum;
      avail_cnt <= avail_sum;
    end
  end

  reg        src_init = 0;
  reg [10:0] word_idx = 0;
  reg [1:0]  byte_idx = 0;
  reg [10:0] stream_count = 0;
  reg [3:0]  gap = 0;

  wire streaming = (state == D_STREAM);

  wire [31:0] init_word = initimg[word_idx];

  reg [31:0] data_word;
  always @(*)
  begin
    if (word_idx <= 11'd17)
      data_word = ek_buf[out_base + word_idx[4:0]];
    else
    begin
      case (word_idx)
        11'd18:  data_word = 32'd64;
        11'd19:  data_word = iter_count;
        11'd20:  data_word = salt0;
        11'd21:  data_word = salt1;
        11'd22:  data_word = salt2;
        11'd23:  data_word = salt3;
        11'd24:  data_word = ekid_buf[out_slot];
        default: data_word = 32'd0;
      endcase
    end
  end

  wire [31:0] cur_word = src_init ? init_word : data_word;

  reg  [NUM_CORES-1:0] c_wr_en_q = 0;
  wire [DIN_BITS-1:0] c_din_q = streaming ? ((DIN_BITS == 32) ? cur_word[DIN_BITS-1:0]
                                                              : cur_word[byte_idx*8 +: 8])
                                          : {DIN_BITS{1'b0}};
  wire [3:0] wide_bwe = (word_idx == 11'd0)
                      ? ((byte_idx == 2'd0) ? 4'b0001 : (byte_idx == 2'd1) ? 4'b0110 : 4'b1000)
                      : ((byte_idx[0])      ? 4'b1000 : 4'b0111);

  wire [3:0] c_bwe_q   = streaming ? ((DIN_BITS == 32) ? wide_bwe
                                                       : (4'b0001 << byte_idx)) : 4'b0000;
  wire       c_start_q = streaming & (word_idx == 11'd0) & (byte_idx == 2'd0);

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      c_din   <= 0;
      c_bwe   <= 0;
      c_start <= 0;
      c_wr_en <= 0;
    end
    else
    begin
      c_din   <= c_din_q;
      c_bwe   <= c_bwe_q;
      c_start <= c_start_q;
      c_wr_en <= c_wr_en_q;
    end
  end

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
    begin
      state        <= D_CHECK;
      c_wr_en_q    <= 0;
      word_idx     <= 0;
      byte_idx     <= 0;
      src_init     <= 0;
      stream_count <= 0;
      gap          <= 0;
      cand_consume <= 0;
      settle       <= 0;
    end
    else
    begin
      cand_consume <= 0;

      if (settle != 2'd0) settle <= settle - 1'b1;

      case (state)
      D_CHECK:
      begin
        byte_idx <= 0;
        word_idx <= 0;

        if ((|core_init_ready) && ((ready_cnt >= INIT_BATCH) || (can_data == 1'b0)))
        begin
          c_wr_en_q    <= core_init_ready;
          src_init     <= 1;
          stream_count <= INIT_WORDS;
          state        <= D_STREAM;
        end
        else if (can_data == 1'b1)
        begin
          c_wr_en_q    <= crypt_onehot;
          src_init     <= 0;
          stream_count <= DATA_WORDS;
          state        <= D_STREAM;
        end
      end

      D_STREAM:
      begin
        byte_idx <= byte_idx + 1'b1;
        if (byte_idx == ((DIN_BITS == 32) ? ((word_idx == 11'd0) ? 2'd2 : 2'd1) : 2'd3))
        begin
          byte_idx <= 0;
          if (word_idx == stream_count - 1'b1)
            state <= D_END;
          else
            word_idx <= word_idx + 1'b1;
        end
      end

      D_END:
      begin
        c_wr_en_q <= 0;
        if (src_init == 1'b0)
          cand_consume <= 1;
        gap   <= 0;
        state <= D_GAP;
      end

      D_GAP:
      begin
        if (gap == 4'd8)
        begin
          state <= D_CHECK;

          if (src_init == 1'b0) settle <= 2'd3;
        end
        else
          gap <= gap + 1'b1;
      end
      endcase
    end
  end

  wire data_settling = (((state == D_END) || (state == D_GAP)) && (src_init == 1'b0)) || (settle != 2'd0);

  wire [1:0]  held      = {1'b0, (slot_filled[0] | slot_ready[0])} + {1'b0, (slot_filled[1] | slot_ready[1])};
  wire [15:0] avail_eff = ((data_settling == 1'b1) && (avail_cnt != 16'd0)) ? (avail_cnt - 16'd1) : avail_cnt;
  wire [2:0]  held_next = {1'b0, held} + {2'd0, rec_end};

  reg admit = 1'b0;

  always @(posedge CLK)
  begin
    if (rst == 1'b1)
      admit <= 1'b0;
    else
      admit <= (avail_eff > {13'd0, held_next});
  end

  assign s_ready = s_ready_slot & ((ADMIT_GATE == 0) | (hdr_word == 1'b0) | (admit == 1'b1));

endmodule

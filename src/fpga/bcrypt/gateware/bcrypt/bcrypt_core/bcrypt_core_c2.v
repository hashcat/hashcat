`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Derived for hashcat from John the Ripper's bcrypt core files named below. The C-slowing and the
// changes described here are hashcat's. src/fpga/bcrypt/PROVENANCE.md lists every change.

//
// bcrypt_core_c2: two independent bcrypt hashes in one core, interleaved cycle by cycle.
//
// bcrypt_core, fsm, unit, P_2x32, S_body and addr_regs, C-slowed by two. Every register becomes a
// two stage chain and every memory takes the virtual core number as its top address bit, so one core
// is two virtual cores taking turns, each running the core's microcode at half the clock rate.
//
// What that buys is a second register inside the round loop. The loop is the S read, the F function
// and the XOR into the next S address, all in one cycle in the original. Here each virtual core has
// two cycles for it, so a register can split it: the array latch ends the first half, and a register
// after the first adder, U = S0 + S1 beside copies of S2 and S3, ends the second. The 4 S-box RAMB18
// were half empty, so the second hash costs no block RAM.
//
// phase names the virtual core whose state is in the second stage this cycle. It toggles every
// cycle and must agree with whatever drives the bus.
//
// Bus contract. Every beat on din, byte_wr_en and start is held for two cycles, a phase 0 cycle then
// a phase 1 cycle, so each virtual core sees each beat once, and wr_sel picks which of them takes it.
// rd_en_vc is held the same way. Virtual core 0's flags and dout are captured at the end of its phase 0
// cycle and held. Virtual core 1's are its live second stage, valid during its phase 1 cycle. A fabric
// that samples at the end of each phase 1 cycle sees both with the latency the original core has.
// hcfpga_cores registers them once more on the fabric clock, see the note there for why.
//
// One microcode change against fsm.v. The original core keeps the S read result across a step that
// does not read, and one path uses the kept value: the collision exception re-reads in MC[81] and the
// result is used in MC[48], after MC[82]. Here the read latch is shared by both virtual cores and
// cannot keep one core's value across the other's cycle, so the re-read moves to MC[82], directly
// before its use. MC[82] then has to load the PN address as P plus one in a single step, which needs
// the PNAR_LD_ADDR_P_PLUS1 opcode below. Everything else in the microcode, the MC[0] reset change
// included, is fsm.v's.
// Every other use of S follows a read in the step before it, or a reset, and a reset is kept per
// virtual core as a zero flag that clears the second stage.
//
// The S state dump is not carried. It uses kept values, and no two hash shape builds it.
//

`include "bcrypt.vh"

`define	PNAR_LD_ADDR_P_PLUS1	4'b1011


module bcrypt_core_c2 #(
	parameter MSB = 31,
	parameter DIN_BITS = 32
	)(
	input CLK,
	input rst,
	input phase,

	input [DIN_BITS-1:0] din,
	input [3:0] byte_wr_en,
	input start,
	input [1:0] wr_sel,

	input [1:0] rd_en_vc,

	output [1:0] init_ready_vc,
	output [1:0] crypt_ready_vc,
	output [1:0] empty_vc,
	output [1:0] dout_vc
	);

	wire sel = wr_sel[phase];

	wire [3:0] bwe = byte_wr_en & {4{sel}};

	wire start_in = start & sel;

	wire rd_en = rd_en_vc[phase];

	wire [31:0] din_x = (DIN_BITS == 32) ? din : {4{din[7:0]}};

	//
	// Input to the core. Each original register is a pair: the _1 stage takes the next value and
	// the unsuffixed stage is what the logic reads.
	//
	reg [MSB:0] din_r1 = 0, din_r = 0;
	reg start_r1 = 0, start_r = 0;
	reg wr_b2_1 = 0, wr_b2 = 0;
	reg wr_b3_1 = 0, wr_b3 = 0;
	reg rd_en_r1 = 0, rd_en_r = 0;

	always @(posedge CLK) begin
		start_r1 <= bwe[0] ? start_in : start_r;
		wr_b3_1  <= bwe[3];
		wr_b2_1  <= bwe[2];
		rd_en_r1 <= rd_en;

		din_r1[7:0]   <= bwe[0] ? din_x[7:0]   : din_r[7:0];
		din_r1[15:8]  <= bwe[1] ? din_x[15:8]  : din_r[15:8];
		din_r1[23:16] <= bwe[2] ? din_x[23:16] : din_r[23:16];
		din_r1[31:24] <= bwe[3] ? din_x[31:24] : din_r[31:24];

		start_r <= start_r1;
		wr_b3   <= wr_b3_1;
		wr_b2   <= wr_b2_1;
		rd_en_r <= rd_en_r1;
		din_r   <= din_r1;
	end


	//
	// Extra Controls.
	//
	wire [`MC_NBITS_E-1:0] Extra_Controls;

	reg init_ready1 = 1, init_ready = 1;
	reg crypt_ready1 = 0, crypt_ready = 0;
	reg empty1 = 1, empty = 1;

	always @(posedge CLK) begin
		if (rst) begin
			init_ready1  <= 1;
			crypt_ready1 <= 0;
			empty1       <= 1;

			init_ready  <= 1;
			crypt_ready <= 0;
			empty       <= 1;
		end
		else begin
			init_ready1 <=
				(Extra_Controls == `E_SET_INIT_READY) ? 1'b1 :
				(Extra_Controls == `E_RST_INIT_READY) ? 1'b0 : init_ready;

			crypt_ready1 <=
				(Extra_Controls == `E_SET_CRYPT_READY) ? 1'b1 :
				(Extra_Controls == `E_RST_CRYPT_READY) ? 1'b0 : crypt_ready;

			empty1 <=
				(Extra_Controls == `E_SET_EMPTY) ? 1'b1 :
				(Extra_Controls == `E_RST_EMPTY) ? 1'b0 : empty;

			init_ready  <= init_ready1;
			crypt_ready <= crypt_ready1;
			empty       <= empty1;
		end
	end

	reg [1:0] MW_count1 = 0, MW_count = 0;
	always @(posedge CLK) begin
		MW_count1 <=
			(Extra_Controls == `E_MW_COUNT_RST) ? 2'd0 :
			(Extra_Controls == `E_MW_COUNT_INC) ? (MW_count + 1'b1) : MW_count;

		MW_count <= MW_count1;
	end

	reg [4:0] output_cnt1 = 0, output_cnt = 0;
	always @(posedge CLK) begin
		output_cnt1 <=
			(Extra_Controls == `E_RST) ? 5'd0 :
			(Extra_Controls == `E_OUTPUT_DATA) ? (output_cnt + 1'b1) : output_cnt;

		output_cnt <= output_cnt1;
	end

	wire ZF_wr_en = Extra_Controls == `E_WR_ZF;

	wire output_data;

	reg dout1 = 0, dout = 0;
	always @(posedge CLK) begin
		dout1 <=
			(Extra_Controls == `E_OUTPUT_HEADER) ? 1'b1 :
			(Extra_Controls == `E_OUTPUT_DATA) ? output_data : 1'b0;

		dout <= dout1;
	end


	//
	// Main Address & Control.
	//
	wire [3:0] PNWAR_op, PNAR_op;
	wire [4:0] PDAR_op;
	wire [4:0] PN_wr_addr, PN_addr, PD_addr;

	PN_wr_addr_reg_c2 PN_wr_addr_reg(
		.CLK(CLK), .op(PNWAR_op), .PN_wr_addr(PN_wr_addr), .MW_count(MW_count),
		.wr_b3(wr_b3),
		.eq29(PNWAR_eq29), .eq15(PNWAR_eq15), .ne8(PNWAR41_ne8) );

	PN_addr_reg_c2 PN_addr_reg(
		.CLK(CLK), .op(PNAR_op), .PN_addr(PN_addr), .MW_count(MW_count),
		.eq14(PNAR_eq14), .eq29(PNAR_eq29) );

	PD_addr_reg_c2 PD_addr_reg(
		.CLK(CLK), .op(PDAR_op), .PD_addr(PD_addr),
		.wr_b3(wr_b3),
		.P_addr1(PN_wr_addr[1]), .S_addr1(S_wr_addr[1]),
		.eq30(PDAR_eq30) );

	wire [2:0] SWAR_op;
	wire [9:0] S_wr_addr;

	S_wr_addr_reg_c2 S_wr_addr_reg(
		.CLK(CLK), .op(SWAR_op), .S_wr_addr(S_wr_addr),
		.wr_b3(wr_b3),
		.eq1022(SWAR_eq1022), .eq1023(SWAR_eq1023) );


	//
	// Main computing unit.
	//
	unit_c2 #(.MSB(MSB)) unit(
		.CLK(CLK), .phase(phase),
		.din(din_r),
		.PS_input_select(PS_input_select), .decr(decr),
		.PN_wr_addr(PN_wr_addr), .PN_wr_en(PN_wr_en),
		.PN_addr(PN_addr),
		.PD_addr(PD_addr), .PD_wr_en(PD_wr_en),
		.ZF_wr_en(ZF_wr_en), .ZF(ZF), .Exception_S_rd(Exception_S_rd),

		.L_input_select(L_input_select), .Ltmp_wr_en(Ltmp_wr_en),
		.L_wr_en(L_wr_en), .R_wr_en(R_wr_en), .LR_zero(LR_zero),

		.S_wr_addr(S_wr_addr),
		.S_wr_en(S_wr_en), .S_rd_en(S_rd_en), .S_rst(S_rst),

		.output_cnt(output_cnt), .out(output_data)
	);


	//
	// Condition Signals
	//
	wire [2**`MC_NBITS_CONDITION-1:0] Condition_Signals = {
		// 16
		1'b0, // #15 JMP_mode_dump, no state dump in this core
		rd_en_r,
		output_cnt == 26,
		~PNAR_eq29,
		~MW_count[1],
		~ZF,
		~SWAR_eq1022,
		PNWAR41_ne8,
		// 8
		PNAR_eq14,
		PNWAR_eq15,
		PDAR_eq30 & wr_b2,
		SWAR_eq1023 & wr_b2,
		PNWAR_eq29 & wr_b2,
		start_r,
		1'b1, 1'b0	// always true/false
	};


	fsm_c2 fsm(
		.CLK(CLK),
		.rst(rst),
		.Condition_Signals(Condition_Signals),
		.Exception_S_rd(Exception_S_rd),

		.Extra_Controls(Extra_Controls),
		.PS_input_select(PS_input_select), .decr(decr),
		.PN_wr_en(PN_wr_en), .PD_wr_en(PD_wr_en),
		.PNWAR_op(PNWAR_op), .PNAR_op(PNAR_op), .PDAR_op(PDAR_op),

		.L_input_select(L_input_select), .Ltmp_wr_en(Ltmp_wr_en), .L_wr_en(L_wr_en),
		.R_wr_en(R_wr_en), .LR_zero(LR_zero),
		.S_wr_en(S_wr_en), .S_rd_en(S_rd_en), .S_rst(S_rst),
		.SWAR_op(SWAR_op)
	);


	//
	// Per virtual core outputs. Virtual core 0 is captured at the end of its own cycle and held across
	// virtual core 1's. Virtual core 1 is the live second stage during its own cycle.
	//
	reg init_ready_0 = 1, crypt_ready_0 = 0, empty_0 = 1, dout_0 = 0;

	always @(posedge CLK)
		if (phase == 1'b0) begin
			init_ready_0  <= init_ready;
			crypt_ready_0 <= crypt_ready;
			empty_0       <= empty;
			dout_0        <= dout;
		end

	assign init_ready_vc  = { init_ready,  init_ready_0 };
	assign crypt_ready_vc = { crypt_ready, crypt_ready_0 };
	assign empty_vc       = { empty,       empty_0 };
	assign dout_vc        = { dout,        dout_0 };

endmodule


module fsm_c2(
	input CLK,
	input rst,
	input [2**`MC_NBITS_CONDITION-1:0] Condition_Signals,
	input Exception_S_rd,

	output reg [`MC_NBITS_E-1:0] Extra_Controls = `E_X_,
	output reg PS_input_select = 0, decr = 0,

	output reg PN_wr_en = 0, PD_wr_en = 0,
	output reg [3:0] PNWAR_op = `PNWAR_X_,
	output reg [3:0] PNAR_op = `PNAR_X_,
	output reg [4:0] PDAR_op = `PDAR_X_,

	output reg L_input_select = 0, Ltmp_wr_en = 0, L_wr_en = 0,
		R_wr_en = 0, LR_zero = 0,

	output reg S_wr_en = 0, S_rd_en = 0, S_rst = 0,
	output reg [2:0] SWAR_op = 0
	);

	reg [`MC_ADDR_MSB:0] IP1 = 0, IP = 0, IP_saved1 = 0, IP_saved = 0;

	wire [`MC_NBITS_TOTAL-1:0] MC_output;
	MC_c2 MC(
		.addr(IP), .out(MC_output)
	);

	wire [`MC_NBITS_E-1:0] MC_E;
	wire [1:0] MC_PN_input_select;
	wire [`MC_NBITS_P-1:0] MC_P;
	wire [`MC_NBITS_LR-1:0] MC_LR;
	wire [`MC_NBITS_S-1:0] MC_S;
	wire [`MC_ADDR_MSB:0] MC_jump_addr;
	wire [`MC_NBITS_CONDITION-1:0] MC_condition;
	wire [`MC_NBITS_FLOW-1:0] MC_flow;

	assign {
		MC_E, MC_PN_input_select,
		MC_P,
		MC_LR, MC_S,
		MC_jump_addr, MC_condition, MC_flow
	} = MC_output;

	// The first stage of every control register, in microcode word order.
	localparam CW = `MC_NBITS_E + 2 + `MC_NBITS_P + `MC_NBITS_LR + `MC_NBITS_S;

	reg [CW-1:0] ctl1 = 0;

	wire [`MC_ADDR_MSB:0] IP_next =
		(MC_flow == `FLOW_CALL) ? MC_jump_addr :
		(Exception_S_rd) ? 7'd80 :
		(MC_flow == `FLOW_RETURN) ? (IP_saved + 1'b1) :
		(Condition_Signals [MC_condition] == 1'b1) ? MC_jump_addr :
		(MC_flow == `FLOW_NEXT) ? (IP + 1'b1) :
		IP;

	always @(posedge CLK) begin
		if (rst) begin
			ctl1 <= 0;

			{ Extra_Controls, decr, PS_input_select,
			  PN_wr_en, PD_wr_en, PNWAR_op, PNAR_op, PDAR_op,
			  L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en,
			  S_wr_en, S_rd_en, S_rst, SWAR_op } <= 0;

			IP1 <= 0; IP <= 0;
			IP_saved1 <= 0; IP_saved <= 0;
		end
		else begin
			ctl1 <= { MC_E, MC_PN_input_select, MC_P, MC_LR, MC_S };

			{ Extra_Controls, decr, PS_input_select,
			  PN_wr_en, PD_wr_en, PNWAR_op, PNAR_op, PDAR_op,
			  L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en,
			  S_wr_en, S_rd_en, S_rst, SWAR_op } <= ctl1;

			IP_saved1 <= (MC_flow == `FLOW_CALL) ? IP : IP_saved;
			IP1       <= IP_next;

			IP_saved <= IP_saved1;
			IP       <= IP1;
		end
	end

endmodule


// The microcode with MC[81] and MC[82] replaced, see the top of this file.
module MC_c2(
	input [`MC_ADDR_MSB:0] addr,
	output [`MC_NBITS_TOTAL-1:0] out
	);

	wire [`MC_NBITS_TOTAL-1:0] base;

	MC MC(
		.addr(addr), .out(base)
	);

	// the step the read used to take, now idle: PN and PD still point at their zero words
	localparam [`MC_NBITS_TOTAL-1:0] MC81 = { `E_X_, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		`LR_X_, `S_X_, `SWAR_X_,
		`MC_X_, `JMP_X_, `FLOW_NEXT };

	// re-read S at L, and point PN at P[1] for round 1 in MC[48]
	localparam [`MC_NBITS_TOTAL-1:0] MC82 = { `E_X_, `INPUT_X_,
		`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P_PLUS1, `PDAR_X_,
		`LR_select_L, `S_RD, `SWAR_X_,
		7'd48, `JMP_UNCONDITIONAL, `FLOW_X_ };

	assign out =
		(addr == 7'd81) ? MC81 :
		(addr == 7'd82) ? MC82 :
		base;

endmodule


module unit_c2 #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8
	)(
	input CLK,
	input phase,
	input [MSB:0] din,

	input [9:0] S_wr_addr,
	input S_wr_en,
	input S_rd_en,
	input S_rst,

	input [4:0] PD_addr,
	input PD_wr_en,

	input [4:0] PN_wr_addr,
	input [4:0] PN_addr,
	input PS_input_select, decr,
	input PN_wr_en,
	input ZF_wr_en,
	output ZF,
	output reg Exception_S_rd = 0,

	input L_input_select,
	input Ltmp_wr_en,
	input L_wr_en,
	input R_wr_en,
	input LR_zero,

	input [4:0] output_cnt,
	output out
	);

	reg [MSB:0] L1 = 0, L = 0, R1 = 0, R = 0, Ltmp1 = 0, Ltmp = 0;
	wire [MSB:0] L_in;

	reg Exception_S_rd1 = 0, Exception_S_rd_r1 = 0, Exception_S_rd_r = 0;

	wire LR_wr_ok = ~Exception_S_rd & ~Exception_S_rd_r;

	always @(posedge CLK) begin
		Ltmp1 <= Ltmp_wr_en ? L_in : Ltmp;

		L1 <= LR_zero ? {(MSB+1){1'b0}} : (L_wr_en & LR_wr_ok) ? L_in : L;
		R1 <= LR_zero ? {(MSB+1){1'b0}} : (R_wr_en & LR_wr_ok) ? L : R;

		Ltmp <= Ltmp1;
		L    <= L1;
		R    <= R1;
	end


	wire [MSB:0] PD, PN, S_input;

	P_c2 #( .MSB(MSB)
	) P(
		.CLK(CLK), .phase(phase),
		.PD_addr(PD_addr), .PD_wr_en(PD_wr_en), .PD_out(PD),
		.din(din), .Ltmp_in(Ltmp),
		.PS_input_select(PS_input_select), .decr(decr),
		.S_input(S_input),
		.PN_wr_addr(PN_wr_addr), .PN_wr_en(PN_wr_en),
		.PN_addr(PN_addr), .PN_out(PN),
		.ZF_wr_en(ZF_wr_en), .ZF(ZF)
	);


	wire [MSB:0] S_dout;

	S_c2 #( .MSB(MSB), .ADDR_NBITS(ADDR_NBITS)
	) S(
		.CLK(CLK), .phase(phase),
		.din(S_input),
		.addr_wr(S_wr_addr), .wr_en(S_wr_en),
		.addr_rd(L_in), .out(S_dout), .rd_en(S_rd_en), .rst_rd(S_rst)
	);


	S_rd_collision_detector S_rd_collision_detector(
		.din(L ^ PN), .S_wr_addr(S_wr_addr),
		.en(S_rd_en & S_wr_en), .dout(S_rd_collision)
	);

	always @(posedge CLK) begin
		Exception_S_rd1   <= S_rd_collision;
		Exception_S_rd_r1 <= Exception_S_rd;

		Exception_S_rd   <= Exception_S_rd1;
		Exception_S_rd_r <= Exception_S_rd_r1;
	end


	assign L_in = (L_input_select ? L : R ^ S_dout) ^ PD ^ PN;

	assign out = Ltmp [output_cnt];

endmodule


module P_c2 #(
	parameter MSB = 31
	)(
	input CLK,
	input phase,

	input [4:0] PD_addr,
	input PD_wr_en,
	output [MSB:0] PD_out,

	input [MSB:0] din,
	input [MSB:0] Ltmp_in,
	input PS_input_select, decr,
	output [MSB:0] S_input,

	input [4:0] PN_wr_addr,
	input [4:0] PN_addr,
	input PN_wr_en,
	output [MSB:0] PN_out,

	input ZF_wr_en,
	output reg ZF = 0
	);

	// Each virtual core's 32 words, the virtual core in the top address bit. Word 31 of each half is
	// the zero word PD_ADDR_ZERO and PN_ADDR_ZERO point at, and nothing writes it.
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [MSB:0] PD [63:0];
	initial begin
		PD[31] = 0;
		PD[63] = 0;
	end

	always @(posedge CLK)
		if (PD_wr_en)
			PD [{phase, PD_addr}] <= din;

	(* KEEP="true" *)
	wire [5:0] PD_addr_rd = {phase, PD_addr};

	assign PD_out = PD [PD_addr_rd];


	(* RAM_STYLE="DISTRIBUTED" *)
	reg [MSB:0] PN [63:0];
	initial begin
		PN[30] = 0;
		PN[31] = 0;
		PN[62] = 0;
		PN[63] = 0;
	end

	wire [MSB:0] PN_input;
	always @(posedge CLK)
		if (PN_wr_en)
			PN [{phase, PN_wr_addr}] <= PN_input;

	assign PN_out = PN [{phase, PN_addr}];

	assign PN_input[31:`SETTING_MAX+1] =
		PS_input_select == `INPUT_DIN ? din[31:`SETTING_MAX+1] :
		Ltmp_in[31:`SETTING_MAX+1];

	assign PN_input[`SETTING_MAX:0] = (
		decr ? PN_out[`SETTING_MAX:0] :
		PS_input_select == `INPUT_DIN ? din[`SETTING_MAX:0] :
		Ltmp_in[`SETTING_MAX:0]
	) - (decr ? 1'b1 : 1'b0);

	assign S_input = PN_input;

	reg ZF1 = 0;
	always @(posedge CLK) begin
		ZF1 <= ZF_wr_en ? (PN_input[`SETTING_MAX:0] == 0) : ZF;
		ZF  <= ZF1;
	end

endmodule


// The four S-boxes of both virtual cores, block RAM only. Each bank is 512 x 32, the virtual core in
// the top address bit, which fills the RAMB18 the original left half empty.
//
// The read is the array latch S*_l, then the second stage, U_q = S0 + S1 beside S2_q and S3_q, in
// fabric after the first adder. The XOR with S2 belongs on the far side of that register: there it is
// one more input to the LUT the second adder needs anyway, and on the near side it was the last level
// of the half of the loop that sets the clock. Putting the second stage in the RAMB18's own DO_REG
// instead leaves the loop unbalanced: one cycle carries the block RAM access alone and the other
// everything else. The original resets and holds its single read register. Here a reset is the zero flag z, kept
// per virtual core like any other register, and it clears the second stage on the cycle that virtual
// core's result passes through it. A hold of a non-zero result cannot be kept, see the top of the file
// for why none is needed.
module S_c2 #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8
	)(
	input CLK,
	input phase,
	input [MSB:0] din,
	input wr_en,
	input [9:0] addr_wr,

	input rd_en,
	input rst_rd,
	input [MSB:0] addr_rd,

	output [MSB:0] out
	);

	(* RAM_STYLE = "block" *) reg [MSB:0] S0 [511:0];
	(* RAM_STYLE = "block" *) reg [MSB:0] S1 [511:0];
	(* RAM_STYLE = "block" *) reg [MSB:0] S2 [511:0];
	(* RAM_STYLE = "block" *) reg [MSB:0] S3 [511:0];

	reg [MSB:0] S0_l = 0, S1_l = 0, S2_l = 0, S3_l = 0;
	reg [MSB:0] U_q = 0, S2_q = 0, S3_q = 0;

	reg z1 = 1, z = 1;

	always @(posedge CLK) begin
		if (wr_en && addr_wr[9:8] == 2'b00)
			S0 [{phase, addr_wr[7:0]}] <= din;
		if (wr_en && addr_wr[9:8] == 2'b01)
			S1 [{phase, addr_wr[7:0]}] <= din;
		if (wr_en && addr_wr[9:8] == 2'b10)
			S2 [{phase, addr_wr[7:0]}] <= din;
		if (wr_en && addr_wr[9:8] == 2'b11)
			S3 [{phase, addr_wr[7:0]}] <= din;

		if (rd_en) begin
			S0_l <= S0 [{phase, addr_rd[4*ADDR_NBITS-1 : 3*ADDR_NBITS]}];
			S1_l <= S1 [{phase, addr_rd[3*ADDR_NBITS-1 : 2*ADDR_NBITS]}];
			S2_l <= S2 [{phase, addr_rd[2*ADDR_NBITS-1 : ADDR_NBITS]}];
			S3_l <= S3 [{phase, addr_rd[ADDR_NBITS-1 : 0]}];
		end

		z1 <= rst_rd ? 1'b1 : (rd_en ? 1'b0 : z);
		z  <= z1;

		if (z1) begin
			U_q  <= 0;
			S2_q <= 0;
			S3_q <= 0;
		end
		else begin
			U_q  <= S1_l + S0_l;
			S2_q <= S2_l;
			S3_q <= S3_l;
		end
	end

	assign out = S3_q + (S2_q ^ U_q);

endmodule


module S_wr_addr_reg_c2(
	input CLK,
	input [2:0] op,
	input wr_b3,

	output reg [9:0] S_wr_addr = 10'b01,
	output eq1022, eq1023
	);

	reg [9:0] S_wr_addr1 = 10'b01;

	wire [1:0] c =
		op[2:1] == `SWAR_INC_B3/2 ? S_wr_addr[0] + wr_b3 :
		op[2:1] == `SWAR_ADD2B1SET/2 ? 2'b11 :
		2'b00;

	always @(posedge CLK) begin
		S_wr_addr1 <= (op[0] == 1'b0) ? S_wr_addr :
			op == `SWAR_1 ? 10'b01 :
			{ S_wr_addr[9:1] + c[1], c[0] };

		S_wr_addr <= S_wr_addr1;
	end

	assign eq1022 = S_wr_addr[9:1] == 1022/2;

	assign eq1023 = eq1022 & S_wr_addr[0];

endmodule


module PN_wr_addr_reg_c2(
	input CLK,
	input [3:0] op,
	input [1:0] MW_count,
	input wr_b3,

	output reg [4:0] PN_wr_addr = `PN_ADDR_P,
	output eq29,
	output eq15,
	output ne8
	);

	wire [1:0] PN_addr_mw10 = `PN_ADDR_MW / 8;

	reg [4:0] PN_wr_addr1 = `PN_ADDR_P;

	always @(posedge CLK) begin
		PN_wr_addr1 <= (op[0] == 1'b0) ? PN_wr_addr :
			op == `PNWAR_LD_ADDR_P ? `PN_ADDR_P :
			op == `PNWAR_LD_ADDR_P_PLUS1 ? `PN_ADDR_P + 1'b1 :
			op == `PNWAR_INC ? PN_wr_addr + 1'b1 :
			op == `PNWAR_INC_B3 ? PN_wr_addr + wr_b3 :
			op == `PNWAR_B0RST ? { PN_wr_addr[4:1], 1'b0 } :
			op == `PNWAR_LD_ADDR_ITER_CURR ? `PN_ADDR_ITER_CURR :
			op == `PNWAR_LD_ADDR_MW1 ? { PN_addr_mw10, MW_count, 1'b1 } :
			{ PN_wr_addr[4:1] + 1'b1, 1'b1 }; // PNWAR_ADD2B1SET

		PN_wr_addr <= PN_wr_addr1;
	end

	assign eq29 = PN_wr_addr == `PN_ADDR_P + 29;

	assign eq15 = PN_wr_addr == `PN_ADDR_P + 15;

	assign ne8 = PN_wr_addr[4:1] != (`PN_ADDR_P + 16)/2;

endmodule


module PN_addr_reg_c2(
	input CLK,
	input [3:0] op,
	input [1:0] MW_count,

	output reg [4:0] PN_addr = `PN_ADDR_P,
	output eq14,
	output eq29
	);

	wire [1:0] PN_addr_mw10 = `PN_ADDR_MW / 8;

	reg [4:0] PN_addr1 = `PN_ADDR_P;

	always @(posedge CLK) begin
		PN_addr1 <= (op[0] == 1'b0) ? PN_addr :
			op == `PNAR_LD_ADDR_P ? `PN_ADDR_P :
			op == `PNAR_LD_ADDR_P_PLUS1 ? `PN_ADDR_P + 1'b1 :
			op == `PNAR_LD_ADDR_ZERO ? `PN_ADDR_ZERO :
			op == `PNAR_LD_ADDR_ITER_CURR ? `PN_ADDR_ITER_CURR :
			op == `PNAR_INC ? PN_addr + 1'b1 :
			{ PN_addr_mw10, MW_count, 1'b0 }; // `PNAR_LD_ADDR_MW

		PN_addr <= PN_addr1;
	end

	assign eq14 = PN_addr == 14;

	assign eq29 = PN_addr == `PNAR_LD_ADDR_MW + 5;

endmodule


module PD_addr_reg_c2(
	input CLK,
	input [4:0] op,
	input wr_b3,

	input P_addr1, S_addr1,

	output reg [4:0] PD_addr = `PD_ADDR_EK,
	output eq30
	);

	wire [2:0] PD_addr_salt20 = `PD_ADDR_SALT / 4;

	reg [4:0] PD_addr1 = `PD_ADDR_EK;

	always @(posedge CLK) begin
		PD_addr1 <= (op[0] == 1'b0) ? PD_addr :
			op == `PDAR_LD_ADDR_EK ? `PD_ADDR_EK :

			op == `PDAR_LD_ADDR_ITER ? `PD_ADDR_ITER :
			op == `PDAR_LD_ADDR_ZERO ? `PD_ADDR_ZERO :
			op == `PDAR_LD_ADDR_LR_XOR_SALT0_P ? { PD_addr_salt20, P_addr1, 1'b1 } :
			op == `PDAR_LD_ADDR_LR_XOR_SALT1_P ? { PD_addr_salt20, P_addr1, 1'b0 } :
			op == `PDAR_LD_ADDR_LR_XOR_SALT0_S ? { PD_addr_salt20, ~S_addr1, 1'b1 } :
			op == `PDAR_LD_ADDR_LR_XOR_SALT1_S ? { PD_addr_salt20, ~S_addr1, 1'b0 } :

			op == `PDAR_LD_ADDR_SALT ? `PD_ADDR_SALT :
			op == `PDAR_LD_ADDR_64 ? `PD_ADDR_64 :
			op == `PDAR_INC ? PD_addr + 1'b1 :
			op == `PDAR_INC_ADDR_SALT ? { PD_addr_salt20, (PD_addr[1:0] + 1'b1) } :
			op == `PDAR_INC_B3 ? PD_addr + wr_b3 :
			`PD_ADDR_IDS; // `PDAR_LD_ADDR_ID0

		PD_addr <= PD_addr1;
	end

	assign eq30 = PD_addr == 30;

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Modified for hashcat from John the Ripper's original.
// src/fpga/bcrypt/PROVENANCE.md lists every change.

`include "bcrypt.vh"

	//
	// Description of operation.
	//
	// 1. On startup, it has init_ready flag set. That indicates it's waiting
	//    for initialization with P, MW, S data. Detailed description of the data
	//    can be found in bcdata.v. Once 'start' is asserted, the data 
	//    is expected to arrive without an interrupt.
	// 2. After initialization, 'crypt_ready' flag is set. It waits for
	//    data for 1 encryption. That includes EK (Expanded Key), salt, IDs, iter_count etc.
	// 3. When encryption is done, it deasserts 'empty' and waits for 'rd_en'.
	// 4. When 'rd_en' arrives, it starts output N-bit result packet over 1-bit bus.
	//    The header is 1 bit (1'b1).
	//    Once output transfer starts, it goes without an interrupt, 'rd_en' no longer
	//    controls the data flow.
	//    Transferred are: header, 2 x 32-bit IDs, 6 x 32-bit encryption result.
	// 5. Go to pt.1.
	//
	// Performance.
	// In most cases, 16 Blowfish rounds are performed in 18 CLK cycles.
	// Hash with setting="$05" is computed in 618K cycles.
	//
`ifdef SIMULATION

module bcrypt_core #(
	// Setting MSB to 3, ADDR_NBITS to 1
	// allows to launch Technology Viewer
	parameter MSB = 31,
	parameter ADDR_NBITS = 8,
	parameter S_STYLE = "block",
	// 8 feeds a word over four cycles, one byte at a time, which is what the ZTEX-era core did.
	// 32 takes a whole word per cycle. See the input stage below for what that costs.
	parameter DIN_BITS = 8
	)(
	input CLK,
	input rst,
	//input wr_en,
	input mode_cmp,
	input mode_dump, // walk P and S out instead of a digest, for a chunk boundary
	input [DIN_BITS-1:0] din,
	input [3:0] byte_wr_en,
	input start,
	output reg init_ready = 1, // Ready for initialization with P, MW, S data
	output reg crypt_ready = 0, // Ready to get EK, salt etc.
	
	input rd_en,
	output reg empty = 1,
	output reg dout = 0
	);

	//
	// Input to the core.
	//
	reg [MSB:0] din_r;
	reg start_r = 0;
	reg wr_b2 = 0;
	reg wr_b3 = 0; // all 4 bytes of input word - ready

	// DIN_BITS only changes how many of the four byte lanes can be written in one cycle. Everything
	// downstream keeps its original timing, and that is deliberate:
	//
	//   wr_b3 increments the write address registers, so it means "a word landed".
	//   wr_b2 leads it by one cycle. The end-of-region comparators (PNWAR_eq29, SWAR_eq1023,
	//   PDAR_eq30) are combinational on the CURRENT address and are ANDed with wr_b2 to build
	//   Extra_Controls, which is what the microcode jumps on.
	//
	// Both properties survive as long as lane 3 arrives strictly after lane 2, so the feeder sends a
	// word as lanes 0..2 then lane 3. That is two cycles instead of four.
	//
	// One word per cycle was tried and does not work. Collapsing lane 2 and lane 3 into one cycle
	// leaves the fsm a single cycle to act on an end-of-region jump before the next word is written,
	// and it needs two, so words are lost at every region boundary. The symptom is no digests at all.

	// Replicating the byte across all four lanes keeps the part selects below in range at either
	// width, so the same four assignments serve both. At 8 bits the feeder puts the right byte on the
	// bus and only one enable is set, so every lane sees the same value and the enable picks it.
	wire [31:0] din_x = (DIN_BITS == 32) ? din : {4{din[7:0]}};

	always @(posedge CLK) begin
		if (byte_wr_en[0])
			start_r <= start;
		wr_b3 <= byte_wr_en[3];
		wr_b2 <= byte_wr_en[2];

		if (byte_wr_en[0])
			din_r[7:0] <= din_x[7:0];
		if (byte_wr_en[1])
			din_r[15:8] <= din_x[15:8];
		if (byte_wr_en[2])
			din_r[23:16] <= din_x[23:16];
		if (byte_wr_en[3])
			din_r[31:24] <= din_x[31:24];
	end

	reg rd_en_r = 0;
	always @(posedge CLK)
		rd_en_r <= rd_en;
	
	
	//
	// Extra Controls.
	//
	wire [`MC_NBITS_E-1:0] Extra_Controls;
	
	// Synchronous reset: initialise the handshake flags to their power-on defaults. The fsm is reset in
	// the same way; the compute datapath initialises itself once the control path is in a known state.
	always @(posedge CLK) begin
		if (rst) begin
			init_ready  <= 1;
			crypt_ready <= 0;
			empty       <= 1;
		end
		else begin
		if (Extra_Controls == `E_SET_INIT_READY)
			init_ready <= 1;
		else if (Extra_Controls == `E_RST_INIT_READY)
			init_ready <= 0;

		if (Extra_Controls == `E_SET_CRYPT_READY)
			crypt_ready <= 1;
		else if (Extra_Controls == `E_RST_CRYPT_READY)
			crypt_ready <= 0;

		if (Extra_Controls == `E_SET_EMPTY)
			empty <= 1;
		else if (Extra_Controls == `E_RST_EMPTY)
			empty <= 0;
		end
	end
	
	// counter for Magic Words
	reg [1:0] MW_count = 0;
	always @(posedge CLK)
		if (Extra_Controls == `E_MW_COUNT_RST)
			MW_count <= 0;
		else if (Extra_Controls == `E_MW_COUNT_INC)
			MW_count <= MW_count + 1'b1;
	
	reg [4:0] output_cnt = 0;
	always @(posedge CLK)
		if (Extra_Controls == `E_RST)
			output_cnt <= 0;
		else if (Extra_Controls == `E_OUTPUT_DATA)
			output_cnt <= output_cnt + 1'b1;

	// State dump walk position. Low 8 bits address the entry, high 2 select the bank, so the whole of
	// S is 1024 steps, and each step reads the entry it names.
	// Advanced in hardware rather than by a microcode opcode, because every cycle of an output phase
	// has to carry E_OUTPUT_DATA: any other opcode drives dout to 0 and injects a bit into the stream.
	// output_cnt 29 is the third from last cycle of a word, which puts the new address in place for the
	// read that prefetches the next one. See the dump sequence in fsm.v.
	reg [10:0] dump_cnt = 0;
	always @(posedge CLK)
		if ((Extra_Controls == `E_RST) || (Extra_Controls == `E_DUMP_CNT_RST))
			dump_cnt <= 0;
		else if (mode_dump_r && (Extra_Controls == `E_OUTPUT_DATA) && (output_cnt == 5'd29))
			dump_cnt <= dump_cnt + 1'b1;

	reg mode_dump_r = 0;
	always @(posedge CLK)
		mode_dump_r <= mode_dump;

	// 1024 and not 1023: the exit is tested three cycles before a word finishes shifting, so stopping
	// on 1023 would cut that word short. Starting one extra word takes 34 cycles and lets word 1023
	// come out whole.
	wire dump_cnt_eq1023 = (dump_cnt == 11'd1024);

	wire ZF_wr_en = Extra_Controls == `E_WR_ZF;

	always @(posedge CLK)
		dout <=
			Extra_Controls == `E_OUTPUT_HEADER ? 1'b1 :
			Extra_Controls == `E_OUTPUT_DATA ? output_data :
			1'b0;

	//
	// Main Address & Control.
	//
	wire [3:0] PNWAR_op, PNAR_op;
	wire [4:0] PDAR_op;
	wire [4:0] PN_wr_addr, PN_addr, PD_addr;
	
	PN_wr_addr_reg PN_wr_addr_reg(
		.CLK(CLK), .op(PNWAR_op), .PN_wr_addr(PN_wr_addr), .MW_count(MW_count),
		.wr_b3(wr_b3),
		.eq29(PNWAR_eq29), .eq15(PNWAR_eq15), .ne8(PNWAR41_ne8) );
	
	PN_addr_reg PN_addr_reg(
		.CLK(CLK), .op(PNAR_op), .PN_addr(PN_addr), .MW_count(MW_count),
		.eq14(PNAR_eq14), .eq29(PNAR_eq29) );

	PD_addr_reg PD_addr_reg(
		.CLK(CLK), .op(PDAR_op), .PD_addr(PD_addr),
		.wr_b3(wr_b3),
		.P_addr1(PN_wr_addr[1]), .S_addr1(S_wr_addr[1]),
		.eq30(PDAR_eq30) );
	
	wire [2:0] SWAR_op;
	wire [9:0] S_wr_addr;

	S_wr_addr_reg S_wr_addr_reg(
		.CLK(CLK), .op(SWAR_op), .S_wr_addr(S_wr_addr),
		.wr_b3(wr_b3),
		.eq1022(SWAR_eq1022), .eq1023(SWAR_eq1023) );
	

	
	//
	// Main computing unit.
	//
	unit #(.MSB(MSB), .S_STYLE(S_STYLE)
	) unit(
		.CLK(CLK),
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
		
		.output_cnt(output_cnt), .out(output_data),

		.dump_en(mode_dump_r), .dump_entry(dump_cnt[7:0]), .dump_bank(dump_cnt[9:8])
	);
	
	
	//
	// Condition Signals
	//
	wire [2**`MC_NBITS_CONDITION-1:0] Condition_Signals = {
		// 16
		mode_dump_r, // #15 for JMP_mode_dump
		rd_en_r,
		output_cnt == 26,
		~PNAR_eq29,
		~MW_count[1],//MW_count != 2,
		~ZF,
		~SWAR_eq1022, // for JMP_not_end_wr_S
		PNWAR41_ne8, // #8 for JMP_not_end_wr_P
		// 8
		PNAR_eq14,
		PNWAR_eq15,
		PDAR_eq30 & wr_b2,
		(SWAR_eq1023 & wr_b2) | (dump_cnt_eq1023 & mode_dump_r), // #4 end of either S walk
		PNWAR_eq29 & wr_b2,
		start_r,
		1'b1, 1'b0	// always true/false
	};


	fsm fsm(
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
	

endmodule

`else

module bcrypt_core (
	input CLK,
	input mode_cmp,
	input [3:0] byte_wr_en,
	input [7:0] din,
	input start,
	output reg init_ready = 1, // Ready for initialization with P, MW, S data
	output reg crypt_ready = 0, // Ready to get EK, salt etc.

	input rd_en,
	output reg empty = 1,
	output reg dout = 0
	);

endmodule

`endif

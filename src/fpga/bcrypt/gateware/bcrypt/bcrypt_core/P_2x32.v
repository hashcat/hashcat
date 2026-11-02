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
// "EK" means expanded key
//
module P_2x32 #(
	parameter MSB = 31
	)(
	input CLK,

	// Memory PD (1 write/read port)
	input [4:0] PD_addr,
	input PD_wr_en,
	output [MSB:0] PD_out,

	// Input MUX
	input [MSB:0] din,
	input [MSB:0] Ltmp_in,
	input PS_input_select, decr,
	output [MSB:0] S_input,

	// Memory PN (1 write, 1 read port)
	input [4:0] PN_wr_addr,
	input [4:0] PN_addr,
	input PN_wr_en,
	output [MSB:0] PN_out,

	input ZF_wr_en,
	output reg ZF = 0
	);


	integer i;

	// PD: 32-deep RAM for constant data, 1 write/read port
	// - input only from din
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [MSB:0] PD [31:0];
	initial begin
		// - EK(18)
		// - constant 'd64(1) - off+18
		// - iter_count(1) - off+19
		// - salt(4) - off+20
		// - IDs(2) - off+24
		// - reserved(5) - off+26
		// Total words in data for encryption: 31
		PD[31] = 0;
	end

	always @(posedge CLK)
		if (PD_wr_en)
			PD [PD_addr] <= din;

	// Force creation of RAM32M instead of RAM32X1S
	// (by defining separate read port) - save 8 LUTs
	(* KEEP="true" *)
	wire [4:0] PD_addr_rd = PD_addr;

	assign PD_out = PD [PD_addr_rd];


	//
	// PN: 32-deep RAM, 1 write, 1 read port
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [MSB:0] PN [31:0];
	initial begin
		// P(0-17)
		// 18 - current value for iter_count
		// resevrved(19-23)
		// magic_w(24-29), replaced by result
		// Total: 30
		PN[30] = 0;
		PN[31] = 0;
	end

	wire [MSB:0] PN_input;
	always @(posedge CLK)
		if (PN_wr_en)
			PN [PN_wr_addr] <= PN_input;

	assign PN_out = PN [PN_addr];


	//
	// Input selection.
	// It's able to perform decrement w/o touching L,R.
	//
	//assign PN_input =
	//	PS_input_select == `INPUT_DIN & ~decr ? din :
	//	PS_input_select == `INPUT_X_ & ~decr ? Ltmp_in :
	//	{ {31-`SETTING_MAX{1'b0}}, PN_out[`SETTING_MAX:0] - 1'b1 }; // INPUT_DECR
	//
	// Saving 32+6 LUT in contrast with the above
	// (+6 for allowance to contain trash in upper bits after decrement)
	//
	assign PN_input[31:`SETTING_MAX+1] =
		//decr ? {31-`SETTING_MAX{1'b0}} : // 6 LUT
		PS_input_select == `INPUT_DIN ? din[31:`SETTING_MAX+1] :
		Ltmp_in[31:`SETTING_MAX+1];

	assign PN_input[`SETTING_MAX:0] = (
		decr ? PN_out[`SETTING_MAX:0] :
		PS_input_select == `INPUT_DIN ? din[`SETTING_MAX:0] :
		Ltmp_in[`SETTING_MAX:0]
	) - (decr ? 1'b1 : 1'b0);

	assign S_input = PN_input;


	//
	// Zero flag (ZF)
	//
	always @(posedge CLK)
		if (ZF_wr_en)
			ZF <= PN_input[`SETTING_MAX:0] == 0;


endmodule

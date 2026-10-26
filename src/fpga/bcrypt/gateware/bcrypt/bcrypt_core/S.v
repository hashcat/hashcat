`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Modified for hashcat from John the Ripper's original.
// src/fpga/bcrypt/PROVENANCE.md lists every change.

//
// 4x 1K S-blocks for bcrypt core
//
// WHERE THE FOUR BANKS ARE STORED IS A BUILD CHOICE, AND THIS FILE IS HOW IT IS MADE.
//
// hcfpga_cores builds an array in which some cores keep S in block RAM and the rest keep it in
// distributed RAM, because the two draw on different silicon and an array of one kind alone runs out
// of one pool with the other still half empty. That choice arrives here as the S_STYLE parameter.
//
// A synthesis attribute has to carry a LITERAL. `(* RAM_STYLE = S_STYLE *)` with S_STYLE a parameter
// is a Vivado extension: a Verilog attribute is legal syntax everywhere and is silently parsed and
// discarded by any tool that does not recognise it, so on a second tool that form does not fail, it
// just quietly stops choosing anything. So the choice is made by generate instead, which every tool
// elaborates on every build.
//
// S_body.vh holds the one and only copy of the logic. It is included twice, once per style, and the
// two modules that result differ in nothing but the attribute string. On Vivado they elaborate to
// the same netlist the parameter form did.
//

`define HC_S_MODULE    S_block
`define HC_S_RAM_STYLE "block"
`include "S_body.vh"
`undef HC_S_MODULE
`undef HC_S_RAM_STYLE

`define HC_S_MODULE    S_dist
`define HC_S_RAM_STYLE "distributed"
`include "S_body.vh"
`undef HC_S_MODULE
`undef HC_S_RAM_STYLE

module S #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8,
	// "block" or "distributed". See hcfpga_cores.v: an array mixes both so that the two
	// stores draw on different silicon and neither pool binds alone.
	parameter S_STYLE = "block"
	)(
	input CLK,
	input [MSB:0] din,
	input wr_en,
	input [9:0] addr_wr,

	input rd_en,
	input rst_rd,
	input [MSB:0] addr_rd,

	input dump_en,
	input [ADDR_NBITS-1:0] dump_entry,
	input [1:0] dump_bank,

	output [MSB:0] out
	);

	// Both branches are called sel and both instances are called impl, on purpose. A conditional
	// generate elaborates at most one of them, so the names do not collide, and the four banks are
	// then at S.sel.impl.S0 whichever style was picked. tb_core reads them by that path, and a name
	// that moved with the style would mean a bench that only builds for one of the two.
	generate
	if (S_STYLE == "distributed")
	begin : sel

		S_dist #(.MSB(MSB), .ADDR_NBITS(ADDR_NBITS)) impl (
			.CLK(CLK), .din(din), .wr_en(wr_en), .addr_wr(addr_wr),
			.rd_en(rd_en), .rst_rd(rst_rd), .addr_rd(addr_rd),
			.dump_en(dump_en), .dump_entry(dump_entry), .dump_bank(dump_bank),
			.out(out)
		);

	end
	else
	begin : sel

		S_block #(.MSB(MSB), .ADDR_NBITS(ADDR_NBITS)) impl (
			.CLK(CLK), .din(din), .wr_en(wr_en), .addr_wr(addr_wr),
			.rd_en(rd_en), .rst_rd(rst_rd), .addr_rd(addr_rd),
			.dump_en(dump_en), .dump_entry(dump_entry), .dump_bank(dump_bank),
			.out(out)
		);

	end
	endgenerate

endmodule

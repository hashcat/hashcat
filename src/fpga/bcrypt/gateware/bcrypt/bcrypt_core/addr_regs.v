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

`include "bcrypt.vh"


module S_wr_addr_reg(
	input CLK,
	input [2:0] op,
	input wr_b3,

	output reg [9:0] S_wr_addr = 10'b01,
	output eq1022, eq1023
	);

	wire [1:0] c =
		op[2:1] == `SWAR_INC_B3/2 ? S_wr_addr[0] + wr_b3 :
		op[2:1] == `SWAR_ADD2B1SET/2 ? 2'b11 :
		2'b00;

	always @(posedge CLK)
		if (op[0])
			S_wr_addr <=
				op == `SWAR_1 ? 10'b01 :
				{ S_wr_addr[9:1] + c[1], c[0] };

	assign eq1022 = S_wr_addr[9:1] == 1022/2;

	assign eq1023 = eq1022 & S_wr_addr[0];

endmodule


module PN_wr_addr_reg(
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

	always @(posedge CLK)
		if (op[0])
			PN_wr_addr <=
				op == `PNWAR_LD_ADDR_P ? `PN_ADDR_P :
				op == `PNWAR_LD_ADDR_P_PLUS1 ? `PN_ADDR_P + 1'b1 :
				op == `PNWAR_INC ? PN_wr_addr + 1'b1 :
				op == `PNWAR_INC_B3 ? PN_wr_addr + wr_b3 :
				op == `PNWAR_B0RST ? { PN_wr_addr[4:1], 1'b0 } :
				op == `PNWAR_LD_ADDR_ITER_CURR ? `PN_ADDR_ITER_CURR :
				op == `PNWAR_LD_ADDR_MW1 ? { PN_addr_mw10, MW_count, 1'b1 } :
				{ PN_wr_addr[4:1] + 1'b1, 1'b1 }; // PNWAR_ADD2B1SET

	assign eq29 = PN_wr_addr == `PN_ADDR_P + 29;

	assign eq15 = PN_wr_addr == `PN_ADDR_P + 15;

	assign ne8 = PN_wr_addr[4:1] != (`PN_ADDR_P + 16)/2;

endmodule


module PN_addr_reg(
	input CLK,
	input [3:0] op,
	input [1:0] MW_count,

	output reg [4:0] PN_addr = `PN_ADDR_P,
	output eq14,
	output eq29
	);

	wire [1:0] PN_addr_mw10 = `PN_ADDR_MW / 8;

	always @(posedge CLK)
		if (op[0])
			PN_addr <=
				op == `PNAR_LD_ADDR_P ? `PN_ADDR_P :
				op == `PNAR_LD_ADDR_ZERO ? `PN_ADDR_ZERO :
				op == `PNAR_LD_ADDR_ITER_CURR ? `PN_ADDR_ITER_CURR :
				op == `PNAR_INC ? PN_addr + 1'b1 :
				{ PN_addr_mw10, MW_count, 1'b0 }; // `PNAR_LD_ADDR_MW

	assign eq14 = PN_addr == 14;

	assign eq29 = PN_addr == `PNAR_LD_ADDR_MW + 5;

endmodule


module PD_addr_reg(
	input CLK,
	input [4:0] op,
	input wr_b3,

	// for proper loading of address for LR ^ salt
	input P_addr1, S_addr1,

	output reg [4:0] PD_addr = `PD_ADDR_EK,
	output eq30
	);

	wire [2:0] PD_addr_salt20 = `PD_ADDR_SALT / 4;

	always @(posedge CLK)
		if (op[0])
			PD_addr <=
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

		assign eq30 = PD_addr == 30;

endmodule



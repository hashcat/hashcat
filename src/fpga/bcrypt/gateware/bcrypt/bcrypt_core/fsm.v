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


module fsm(
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
	output reg [2:0] SWAR_op
	);

	//
	// "IP": Instruction Pointer, 1-deep call stack
	//
	reg [`MC_ADDR_MSB:0] IP = 0, IP_saved = 0;

	//
	// "MC": Microcode (ROM)
	//
	wire [`MC_NBITS_TOTAL-1:0] MC_output;
	MC MC(
		.addr(IP), .out(MC_output)
	);

	//
	// Microcode Output
	//
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

	reg x = 0;

	always @(posedge CLK) begin
	// Synchronous reset: initialise the control FSM to its power-on state. The reset values are the
	// registers' own defaults (the *_X_ control codes and the instruction pointer are all zero), which
	// keeps behaviour deterministic in simulation as well as on hardware.
	if (rst) begin
		Extra_Controls <= 0;
		decr <= 0; PS_input_select <= 0;
		PN_wr_en <= 0; PD_wr_en <= 0; PNWAR_op <= 0; PNAR_op <= 0; PDAR_op <= 0;
		L_input_select <= 0; Ltmp_wr_en <= 0; LR_zero <= 0; L_wr_en <= 0; R_wr_en <= 0;
		S_wr_en <= 0; S_rd_en <= 0; S_rst <= 0; SWAR_op <= 0;
		IP <= 0; IP_saved <= 0;
	end
	else begin
		Extra_Controls <= MC_E;
		{ decr, PS_input_select } <= MC_PN_input_select;
		{ PN_wr_en, PD_wr_en, PNWAR_op, PNAR_op, PDAR_op } <= MC_P;
		{ L_input_select, Ltmp_wr_en, LR_zero, L_wr_en, R_wr_en } <= MC_LR;
		{ S_wr_en, S_rd_en, S_rst, SWAR_op } <= MC_S;

		// for simulation breakpoints; optimized away by synthesis
		if (IP==1)
			x<=1;
		else if (IP==2)
			x<=1;
		else if (IP==3)
			x<=1;
		else if (IP==6) // end of input
			x<=1;
		else if (IP==60) // P_XOR_EK_START
			x<=1;
		else if (IP==62) // P_XOR_EK_END
			x<=1;
		else if (IP==13) // After end_wr_P.
			x<=1;
		else if (IP==19) // After end_wr_S. Start loading ITER.
			x<=1;
		else if (IP==22) // Before P_XOR_SALT
			x<=1;
		else if (IP==23) // After P_XOR_SALT
			x<=1;
		else if (IP==24) // ITER_CURR_DECR
			x<=1;
		else if (IP==49) // end_wr_P. (main)
			x<=1;
		else if (IP==52) // end_wr_S. (main)
			x<=1;

		else if (IP==26) // Started G_STATE_2
			x<=1;
		else if (IP==29) // Completed loading 'd64 into ITER; MW into L,R
			x<=1;
		else if (IP==34) // Completed encryption with MW
			x<=1;
		else if (IP==38) // Saved encryption result
			x<=1;
		else if (IP==80) // S rd/wr exception
			x<=1;


		//
		// Microcode Execution Control
		//
		if (MC_flow == `FLOW_CALL) begin
			IP_saved <= IP;
			IP <= MC_jump_addr;
		end
		else if (Exception_S_rd)
			IP <= 7'd80;
		else if (MC_flow == `FLOW_RETURN)
			IP <= IP_saved + 1'b1;
		else if (Condition_Signals [MC_condition] == 1'b1)
			IP <= MC_jump_addr;
		else if (MC_flow == `FLOW_NEXT)
			IP <= IP + 1'b1;
	end // else (not rst)
	end

endmodule


module MC(
	input [`MC_ADDR_MSB:0] addr,
	output [`MC_NBITS_TOTAL-1:0] out
	);

	//
	// "MC": Microcode (ROM)
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`MC_NBITS_TOTAL-1:0] MC [95:0];
	assign out = MC [addr];

	initial begin
		// PDAR_LD_ADDR_EK, and not PDAR_X_, because this is where a RESET lands.
		//
		// PD_addr has no reset. It is declared with a power on initialiser in addr_regs.v and nothing
		// puts it back, so a core reset restarts this microcode while leaving the PD write pointer
		// wherever the interrupted job had it. In the cost loop that is PD_ADDR_ZERO, which is 31, and
		// the 31 words of the next data batch then run 31, 0, 1 ... 29 and never make PDAR_eq30 true
		// while writing. MC[5] therefore never exits, crypt_ready stays low, and hcfpga_feed only ever
		// streams to a core that asserts crypt_ready, so the core is lost until the fabric is
		// reconfigured. Caught earlier in the job instead, the core leaves MC[5] early and returns a
		// confident wrong digest from a shifted PD image.
		//
		// Loading it here costs nothing on the normal path: MC[77] ends every job with the same load
		// and jumps straight back to MC[0], so the pointer is already PD_ADDR_EK whenever this runs
		// without a reset in between. It is a no-op in normal operation and the whole fix after one.
		//
		// The host asserts the framing reset after any failed batch, with cores mid job, so this is
		// reached by the ordinary retry path rather than only by a cold start.
		MC[0] = { `E_RST, `INPUT_DIN,
			`P_X_, `PNWAR_LD_ADDR_P, `PNAR_X_, `PDAR_LD_ADDR_EK,
			`LR_X_, `S_X_, `SWAR_1,//X_,
			7'd1, `JMP_START_R, `FLOW_X_ };

		// Start input of initialization data (30 + 1024 words) into PN, S
		// STATE_INPUT_PN
		MC[1] = { `E_RST_INIT_READY, `INPUT_DIN,
			`PN_WR, `PNWAR_INC_B3, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_B0RST,//ZERO,
			7'd2, `JMP_PNWAR_eq29_b2, `FLOW_X_ };

		// STATE_INPUT_S
		MC[2] = { `E_X_, `INPUT_DIN,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_WR, `SWAR_INC_B3,
			7'd3, `JMP_SWAR_eq1023_b2, `FLOW_X_ };

		// E_SET_CRYPT_READY, Wait for the data for encryption
		MC[3] = { `E_SET_CRYPT_READY, `INPUT_DIN,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd5, `JMP_START_R, `FLOW_X_ };
			//`MC_X_, `JMP_X_, `FLOW_NEXT };
	// Input of initialization data ends

		// Wait for the data for encryption
		//MC[4] = { `E_X_, `INPUT_DIN,
		//	`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_LD_ADDR_EK,
		//	`LR_X_, `S_X_, `SWAR_X_,
		//	7'd5, `JMP_START_R, `FLOW_X_ };

		// Start input of data for encryption (31 words into PD)
		MC[5] = { `E_RST_CRYPT_READY, `INPUT_DIN,
			`PD_WR, `PNWAR_X_, `PNAR_X_, `PDAR_INC_B3,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd6, `JMP_PDAR_eq30_b2, `FLOW_X_ };
			//7'd65, `JMP_PDAR_eq29, `FLOW_X_ };
	// Input of data for encryption ends, proceeding to BF_BODY


		// ***********************************************************************
		// New iteration of BF_BODY (in terms of JtR) (with L, R ^= salt) starts here
		// Includes:
		// Call LR_ZERO_P_XOR_EK (also sets SWAR to 1, set P*AR's)
		// BF_ROUND's:
		// - L, R ^ salt before each BF_ENCRYPT
		// - save results into P or S

		// ***********************************************************************

		// Call LR_ZERO_P_XOR_EK
		MC[6]= { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_P, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_EK,
			`LR_ZERO, `S_RST, `SWAR_X_,
			`MC_LR_ZERO_P_XOR_EK, `JMP_X_, `FLOW_CALL };

		// ***********************************************************************
		// L, R ^= salt before BF_ENCRYPT with save to P
		// Prepare. It constructs address for salt.
		MC[7] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_LR_XOR_SALT0_P,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// xor #0
		MC[8] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_LD_ADDR_LR_XOR_SALT1_P,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// xor #1; init before Round0
		MC[9] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_ZERO,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// ***********************************************************************
		// Here goes BF_ENCRYPT with save into P
		// Round 0, call to rounds 1-16
		MC[10] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_Round0, `S_RD, `SWAR_X_,
			`MC_BF_ENCRYPT_ROUNDS_1_16, `JMP_X_, `FLOW_CALL };

		// Round 17. Write Ltmp and P
		MC[11] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_B0RST, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_WR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// STATE_ROUND_SAVE. End of BF_ROUND. Write P
		// In most cases go to (L,R ^ salt) before Round 0.
		MC[12] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_ADD2B1SET, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd7, `JMP_not_end_wr_P, `FLOW_NEXT };

		// end_wr_P.

		// ***********************************************************************
		// L, R ^= salt before BF_ENCRYPT with save to S
		// Prepare. It constructs address for salt.
		MC[13] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_LR_XOR_SALT0_S,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// xor 0
		MC[14] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_LD_ADDR_LR_XOR_SALT1_S,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// xor 1; init before Round0
		MC[15] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_ZERO,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// ***********************************************************************
		// Here goes BF_ENCRYPT with save into S
		// Round 0, call for rounds 1-16
		MC[16] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_Round0, `S_RD, `SWAR_X_,
			`MC_BF_ENCRYPT_ROUNDS_1_16, `JMP_X_, `FLOW_CALL };

		// Round 17. Write Ltmp and S
		MC[17] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_WR_Ltmp, `S_WR, `SWAR_B0RST,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// STATE_ROUND_SAVE. End of BF_ROUND. Write S
		// In most cases go to Round 0.
		MC[18] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_WR, `SWAR_ADD2B1SET,
			7'd13, `JMP_not_end_wr_S, `FLOW_NEXT };

		// end_wr_S.

		// ***********************************************************************
		// Load iteration count for the "main" loop.
		// Iteration count from salt resides at location pointed to by `PDAR_LD_ADDR_ITER
		// Current iteration count: at location pointed to by `PNWAR_LD_ADDR_ITER_CURR

		// Load iter_count, call to save it into ITER_CURR (must LR_ZERO, S_RST)
		MC[19] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_ITER,
			`LR_ZERO, `S_RST, `SWAR_X_,
			`MC_SAVE_ITER_CURR, `JMP_X_, `FLOW_CALL };


		// ***********************************************************************
		// Repeated BF_BODY without (L, R ^= salt)
		//
		// Call LR_ZERO_P_XOR_EK
		MC[20]= { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_P, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_EK,
			`LR_ZERO, `S_RST, `SWAR_X_,
			`MC_LR_ZERO_P_XOR_EK, `JMP_X_, `FLOW_CALL };

		// Call MC_BF_MAIN
		MC[21] = `CMD_CALL(`MC_BF_MAIN);

		// Call LR_ZERO_P_XOR_SALT
		MC[22] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_P, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_SALT,
			`LR_ZERO, `S_RST, `SWAR_X_,
			`MC_LR_ZERO_P_XOR_SALT, `JMP_X_, `FLOW_CALL };

		// Call MC_BF_MAIN
		MC[23] = `CMD_CALL(`MC_BF_MAIN);

		// Call CMD_ITER_CURR_DECR
		MC[24] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_ITER_CURR, `PNAR_LD_ADDR_ITER_CURR, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_ITER_CURR_DECR, `JMP_X_, `FLOW_CALL };

		// Perform jump based on ZF; Reset MW_count
		MC[25] = { `E_MW_COUNT_RST, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd20, `JMP_not_ZF, `FLOW_NEXT };
	// "Main" loop completed


		// ***********************************************************************
		// Stage 2: Encryption with 3 magic words x 64bit

		// Load 'd64 into ITER_CURR
		MC[26] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_64,
			`LR_ZERO, `S_RST, `SWAR_X_,
			`MC_SAVE_ITER_CURR, `JMP_X_, `FLOW_CALL };

		// Set address of the current MW.
		MC[27] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_MW, `PDAR_LD_ADDR_ZERO,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// Load MW (1st part 32 bits)
		MC[28] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// Load MW (2nd part 32 bits).
		MC[29] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// ***********************************************************************
		// BF_ENCRYPT w/o save into P or S
		// Round 0, call for rounds 1-16
		MC[30] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_Round0, `S_RD, `SWAR_X_,
			`MC_BF_ENCRYPT_ROUNDS_1_16, `JMP_X_, `FLOW_CALL };

		// Round 17. Don't write Ltmp or P/S
		MC[31] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_WR, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// CMD_ITER_CURR_DECR //-1!
		MC[32] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_ITER_CURR, `PNAR_LD_ADDR_ITER_CURR, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_ITER_CURR_DECR, `JMP_X_, `FLOW_CALL };

		// Perform jump base on ZF. (next iteration of 64)
		MC[33] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd30, `JMP_not_ZF, `FLOW_NEXT };

		// Save R into BF_out[MW_count][1], L into BF_out[MW_count][0]
		// 1. setup
		MC[34] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// 2. L->R, R->L,Ltmp
		MC[35] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_MW1, `PNAR_X_, `PDAR_X_,
			`LR_WR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// 3. L->R, R->L,Ltmp, Ltmp->PN, PNWAR--
		MC[36] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_B0RST, `PNAR_X_, `PDAR_X_,
			`LR_WR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// 4. Ltmp->PN. L->R.
		// MW_count++. Jump to the next MW
		MC[37] = { `E_MW_COUNT_INC, `INPUT_X_,
			`PN_WR, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_WR, `S_X_, `SWAR_X_,
			7'd26, `JMP_MW_count_ne2, `FLOW_NEXT };

		MC[38] = `CMD_JMP(7'd65); // Output


		// **************************************************
		// OUTPUT

		// set empty to 0; continue if rd_en
		MC[65] = { `E_RST_EMPTY, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_ZERO,
			`LR_ZERO, `S_RST, `SWAR_X_,
			7'd66, `JMP_rd_en, `FLOW_X_ };

		// set empty to 1
		MC[66] = { `E_SET_EMPTY, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// A dump and a digest are both "the host asked for this core's output", so they share the
		// rd_en handshake above and split here.
		MC[67] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd83, `JMP_mode_dump, `FLOW_NEXT };

		// output_data; IDs[0]
		// Reset magic word count
		MC[68] = { `E_MW_COUNT_RST, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_ID0,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[69] = { `E_OUTPUT_HEADER, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[70] = { `E_OUTPUT_DATA, `INPUT_X_, //-1!
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd71, `JMP_output_cnt, `FLOW_X_ };

		MC[71] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// It requires 1 cycle after MC_OUTPUT
		MC[72] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// output_data; IDs[1]
		MC[73] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_INC,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_OUTPUT, `JMP_X_, `FLOW_CALL };

		MC[74] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_MW, `PDAR_LD_ADDR_ZERO,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// output magic words (now contain encryption results)
		MC[75] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_OUTPUT, `JMP_X_, `FLOW_CALL };

		MC[76] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd75, `JMP_PNAR_ne29, `FLOW_NEXT };

		// END. jmp -> 0
		MC[77] = { `E_SET_INIT_READY, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_P, `PNAR_X_, `PDAR_LD_ADDR_EK,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd0, `JMP_UNCONDITIONAL, `FLOW_X_ };


		// *********************************************************************
		// State dump: walk S out through the same 1-bit path the digest uses.
		//
		// L and R are zeroed and PN and PD point at their zero words, so
		// L_in = (R ^ S_dout) ^ PD ^ PN collapses to S_dout and LR_Ltmp latches the raw bank word.
		//
		// Two counts have to hold at once, and both were found the hard way:
		//
		//  1. EXACTLY 32 E_OUTPUT_DATA cycles per word. The shifter emits Ltmp[output_cnt] and
		//     output_cnt is a free running 5 bit counter, so at 32 the phase looks after itself.
		//     MC_OUTPUT supplies 28 of them, so exactly 4 live out here: 86, 87, 88 and 89.
		//  2. The bank read leads the latch by one entry, and the latch sits in the entry immediately
		//     before the shift restarts. Control signals take effect a cycle after their entry is
		//     fetched, so a latch any earlier swaps the next word in while the current one is still
		//     going out. That is 84 then 85 for the first word, and 88 then 89 for every word after.
		//
		// The loop is MC[83] to MC[89], between the exception handlers at 80 to 82 and the MC_OUTPUT
		// subroutine at 93 to 95. It leaves through MC[64], which puts the core back at the top.

		MC[83] = { `E_DUMP_CNT_RST, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_ZERO,
			`LR_ZERO, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[84] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_RD, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// header bit, and latch the first word while it goes out
		MC[85] = { `E_OUTPUT_HEADER, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// shift the latched word out (output 1 of 4)
		// Every cycle here carries E_OUTPUT_DATA, without exception: any other opcode drives dout to 0
		// and injects a bit into the serial stream. The E, LR and S fields are independent, so the read
		// and the latch ride along with the output instead of costing cycles of their own, and the walk
		// is advanced in hardware. MC_OUTPUT supplies 28 output cycles, these 4 make 32.

		MC[86] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_OUTPUT, `JMP_X_, `FLOW_CALL };

		// condition #4 is the end of either S walk, so here it is dump_cnt hitting 1023
		MC[87] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd64, `JMP_SWAR_eq1023_b2, `FLOW_NEXT };

		// prefetch the next entry, the walk has already advanced by now
		MC[88] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_RD, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// latch it, one step before the next word starts shifting, as MC[85] does for the first word
		MC[89] = { `E_OUTPUT_DATA, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			7'd86, `JMP_UNCONDITIONAL, `FLOW_X_ };

		// S is out. Back to the top ready for the next batch, as the digest path does.
		MC[64] = { `E_SET_INIT_READY, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_P, `PNAR_X_, `PDAR_LD_ADDR_EK,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd0, `JMP_UNCONDITIONAL, `FLOW_X_ };

		// *********************************************************************
		// Subroutine:
		// MC_OUTPUT

		MC[93] = { `E_OUTPUT_DATA, `INPUT_X_, // +4 after JMP_output_cnt
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[94] = { `E_OUTPUT_DATA, `INPUT_X_, //-1!
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd95, `JMP_output_cnt, `FLOW_X_ };

		MC[95] = { `E_OUTPUT_DATA, `INPUT_X_, //-1 if conditional return
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_RETURN };

		// ***********************************************************************
		// Subroutine:
		// MC_ITER_CURR_DECR

		// register ZF, decrement, write PN
		MC[40] = { `E_WR_ZF, `INPUT_DECR,
			`PN_WR, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[41] = `CMD_RETURN;

		// ***********************************************************************
		// Subroutine:
		// MC_BF_MAIN
		// Performs BF_BODY without (L, R ^= salt). L, R already set to 0.

		// Here goes BF_ENCRYPT with save into P
		// Round 0
		MC[42] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_Round0, `S_RD, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// Rounds 1-15 of the innermost loop.
		MC[43] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR, `S_RD, `SWAR_X_,
			7'd44, `JMP_PNAR_eq14, `FLOW_X_ };

		// Round 16. Write Ltmp
		MC[44] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR_Ltmp, `S_RST, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// Round 17. Write Ltmp and P
		MC[45] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_B0RST, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_WR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// STATE_ROUND_SAVE. End of BF_ROUND. Write P
		MC[46] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_ADD2B1SET, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd42, `JMP_not_end_wr_P, `FLOW_NEXT };

		// end_wr_P. (main)

		// Here goes BF_ENCRYPT with save into S
		// Round 0
		MC[47] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_Round0, `S_RD, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// Rounds 1-15 of the innermost loop.
		MC[48] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR, `S_RD, `SWAR_X_,
			7'd49, `JMP_PNAR_eq14, `FLOW_X_ };

		// Round 16. Write Ltmp
		MC[49] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR_Ltmp, `S_RST, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// Round 17. Write Ltmp and S
		MC[50] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_WR_Ltmp, `S_WR, `SWAR_B0RST,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// STATE_ROUND_SAVE. End of BF_ROUND. Write S
		// In most cases go to Round 0.
		//MC[51] = { `E_X_, `INPUT_X_,
		//	`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
		//	`LR_X_, `S_WR, `SWAR_ADD2B1SET,
		//	7'd47, `JMP_not_end_wr_S, `FLOW_NEXT };

		// STATE_ROUND_SAVE. End of BF_ROUND. Write S
		// At the same time perform Round 0.
		// On S_RW, S read/write collision is possible, exception raises.
		MC[51] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_Round0, `S_RW, `SWAR_ADD2B1SET,
			7'd48, `JMP_not_end_wr_S, `FLOW_NEXT };

		// end_wr_S (main).

		MC[52] = `CMD_RETURN;


		// S read/write collision. Exception raised.
		//
		// * exception at the end of the loop issue.
		// Exception doesn't affect execution flow on CALL.
		// If it happens at the end of the loop, it is perfirming
		// CALL CMD_ITER_CURR_DECR(addr 24) / LR_ZERO_P_XOR_SALT(addr 22),
		//
		MC[80] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_ZERO, `PDAR_LD_ADDR_ZERO,
			`LR_X_, `S_RST, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[81] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_LD_ADDR_P, `PDAR_X_,
			`LR_select_L, `S_RD, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		MC[82] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			7'd48, `JMP_UNCONDITIONAL, `FLOW_X_ };


		// ***********************************************************************
		// Subroutine:
		// LR_ZERO_P_XOR_SALT
		// also prepares to BF_BODY - sets PNWAR, SWAR

		// STATE_P_XOR_SALT_START // write Ltmp
		MC[53] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_INC,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// STATE_P_XOR_SALT // write Ltmp, PN
		MC[54] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_INC, `PNAR_INC, `PDAR_INC_ADDR_SALT,
			`LR_Ltmp, `S_X_, `SWAR_X_,//`SWAR_ZERO,
			7'd55, `JMP_PNWAR_eq15, `FLOW_X_ };

		// STATE_P_XOR_SALT_END // write PN
		// init PNW, PN, PD, SW before round 0
		MC[55] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_LD_ADDR_P_PLUS1, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_ZERO,
			`LR_X_, `S_X_, `SWAR_1,
			`MC_X_, `JMP_X_, `FLOW_RETURN };

		// ***********************************************************************
		// Subroutine:
		// SAVE_ITER_CURR
		// Saves iter_count into PN_ADDR_ITER_CURR

		// 1: write Ltmp
		MC[56] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_LD_ADDR_ITER_CURR, `PNAR_X_, `PDAR_X_,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// 2: write ITER_CURR
		MC[57] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_RETURN };

		// ***********************************************************************
		// Subroutine:
		// BF_ENCRYPT_ROUNDS_1_16
		// Rounds 1-16 of BF_ENCRYPT

		// Rounds 1-15 of the innermost loop.
		MC[58] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR, `S_RD, `SWAR_X_,
			7'd59, `JMP_PNAR_eq14, `FLOW_X_ };

		// Round 16. Write Ltmp
		MC[59] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_X_,
			`LR_WR_Ltmp, `S_RST, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_RETURN };

		// ***********************************************************************
		// Subroutine:
		// LR_ZERO_P_XOR_EK
		// also prepares to BF_BODY - sets PNWAR, SWAR

		// STATE_P_XOR_EK_START // write Ltmp
		MC[60] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_INC, `PDAR_INC,
			`LR_Ltmp, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_NEXT };

		// STATE_P_XOR_EK // write Ltmp, PN
		MC[61] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_INC, `PNAR_INC, `PDAR_INC,
			`LR_Ltmp, `S_X_, `SWAR_X_,//ZERO,
			7'd62, `JMP_PNWAR_eq15, `FLOW_X_ };

		// STATE_P_XOR_EK_END // write PN
		// init PNW, PN, PD before round 0
		// SW already initialized
		MC[62] = { `E_X_, `INPUT_X_,
			`PN_WR, `PNWAR_LD_ADDR_P_PLUS1, `PNAR_LD_ADDR_P, `PDAR_LD_ADDR_ZERO,
			`LR_X_, `S_X_, `SWAR_1,
			`MC_X_, `JMP_X_, `FLOW_RETURN };

		// ***********************************************************************
		MC[63] = { `E_X_, `INPUT_X_,
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_,
			`LR_X_, `S_X_, `SWAR_X_,
			`MC_X_, `JMP_X_, `FLOW_X_ };

	end


endmodule

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
`ifndef _BCRYPT_VH_
`define _BCRYPT_VH_

// hashcat build: enable the real (behavioural-model) bcrypt_core rather than the empty stub. The
// macro name is JtR's and it misleads: it selects the actual synthesisable core, not a testbench. No `MSB inline (the kept core doesn't use it).
`define	SIMULATION


// An attempt to set more will result in cmp_config error
`define	SETTING_MAX	19

// ****************************************
//
// low-level stuff
//
// ****************************************
`define	CTRL_NONE	2'b00
`define	CTRL_INIT_START	2'b01
`define	CTRL_DATA_START	2'b10
`define	CTRL_END		2'b11
// ****************************************

`define	PN_ADDR_P		5'd0
`define	PN_ADDR_ITER_CURR	5'd18
`define	PN_ADDR_MW		5'd24
`define	PN_ADDR_ZERO	5'd31
//`define PN_ADDR_

`define	PD_ADDR_EK		5'd0
`define	PD_ADDR_64		5'd18
`define	PD_ADDR_ITER	5'd19
`define	PD_ADDR_SALT	5'd20
`define	PD_ADDR_IDS		5'd24
`define	PD_ADDR_ZERO	5'd31

//
// Microcode
//
`define	MC_ADDR_MSB	6

//
// Unit op. codes
//

// ****************************************
// Extra controls
`define	MC_NBITS_E	4

`define	E_X_		`MC_NBITS_E'd0
`define	E_RST		`MC_NBITS_E'd1
`define	E_SET_INIT_READY	`MC_NBITS_E'd2
`define	E_RST_INIT_READY	`MC_NBITS_E'd3
`define	E_SET_CRYPT_READY	`MC_NBITS_E'd4
`define	E_RST_CRYPT_READY	`MC_NBITS_E'd5
`define	E_SET_EMPTY		`MC_NBITS_E'd6
`define	E_RST_EMPTY		`MC_NBITS_E'd7

`define	E_MW_COUNT_RST		`MC_NBITS_E'd8
`define	E_MW_COUNT_INC		`MC_NBITS_E'd9

`define	E_OUTPUT_DATA		`MC_NBITS_E'd10
`define	E_OUTPUT_HEADER	`MC_NBITS_E'd11

`define	E_WR_ZF		`MC_NBITS_E'd12

// State dump. The counter is 11 bits wide so it can reach 1024 and end the walk. Low 8 pick the
// entry and the next 2 pick the bank, so the entry changes on every word and the bank every 256
// words. The walk costs 1024 reads for 1024 words, one per word.
`define	E_DUMP_CNT_RST	`MC_NBITS_E'd13
`define	E_DUMP_CNT_INC	`MC_NBITS_E'd14


// PN,S Input
`define	INPUT_X_		2'b01
`define	INPUT_DIN	2'b00
`define	INPUT_DECR	2'b11

// ****************************************
// P Controls
`define	MC_NBITS_P	(2 +4 +4 +5)

`define	P_X_	2'b00
`define	PN_WR	2'b10
`define	PD_WR	2'b01

// "PN" Write Address Register (PNWAR) ops
`define	PNWAR_X_		4'b0000
`define	PNWAR_LD_ADDR_P	4'b0001
`define	PNWAR_INC_B3	4'b0011
`define	PNWAR_LD_ADDR_P_PLUS1	4'b0101
`define	PNWAR_INC		4'b0111
`define	PNWAR_B0RST		4'b1001
`define	PNWAR_ADD2B1SET	4'b1011
`define	PNWAR_LD_ADDR_ITER_CURR	4'b1101
`define	PNWAR_LD_ADDR_MW1	4'b1111

// "PN" Address Register (PNAR) ops
`define	PNAR_X_		4'b0000
`define	PNAR_LD_ADDR_P		4'b0001
`define	PNAR_LD_ADDR_ZERO	4'b0011
`define	PNAR_INC		4'b0101
`define	PNAR_LD_ADDR_ITER_CURR	4'b0111
`define	PNAR_LD_ADDR_MW	4'b1001

// "PD" Address Register (PDAR) ops
`define	PDAR_X_		5'b00000
`define	PDAR_LD_ADDR_EK	5'b00001
`define	PDAR_LD_ADDR_ZERO	5'b00011
`define	PDAR_LD_ADDR_SALT	5'b00101
`define	PDAR_INC	5'b00111
//`define	PDAR_LD_ADDR_4_LR_XOR_SALT0	4'b1011
//`define	PDAR_LD_ADDR_4_LR_XOR_SALT1	4'b1101
`define	PDAR_LD_ADDR_LR_XOR_SALT0_P	5'b01001
`define	PDAR_LD_ADDR_LR_XOR_SALT1_P	5'b01011
`define	PDAR_LD_ADDR_LR_XOR_SALT0_S	5'b01101
`define	PDAR_LD_ADDR_LR_XOR_SALT1_S	5'b01111

`define	PDAR_LD_ADDR_ITER		5'b10001
`define	PDAR_INC_ADDR_SALT	5'b10011
`define	PDAR_LD_ADDR_64		5'b10101
`define	PDAR_LD_ADDR_CMP_DATA	5'b10111
`define	PDAR_LD_ADDR_ID0		5'b11001

`define	PDAR_INC_B3		5'b11011

// ****************************************
// L & R Controls
`define	MC_NBITS_LR	5

`define	LR_X_	5'b00000
`define	LR_ZERO	5'b00100
`define	LR_Ltmp	5'b01000
`define	LR_Round0	5'b10010
`define	LR_WR		5'b00011
`define	LR_WR_Ltmp	5'b01011
`define	LR_select_L	5'b10000

// ****************************************
// S Controls
`define	MC_NBITS_S	6

`define	S_X_	3'b000
`define	S_WR	3'b100
`define	S_RD	3'b010
`define	S_RST	3'b011
`define	S_RW	3'b110

// "S" Write Address Register (SWAR) ops
`define	SWAR_X_	3'b000
`define	SWAR_1	3'b001
`define	SWAR_B0RST	3'b011
`define	SWAR_INC_B3		3'b101
`define	SWAR_ADD2B1SET	3'b111

// ****************************************
// Jumps
//
`define	MC_NBITS_CONDITION	4

// JMP_X_ <- no jump
`define	JMP_X_	`MC_NBITS_CONDITION'd0

`define	JMP_UNCONDITIONAL	`MC_NBITS_CONDITION'd1
`define	JMP_START_R			`MC_NBITS_CONDITION'd2
`define	JMP_PNWAR_eq29_b2	`MC_NBITS_CONDITION'd3
`define	JMP_SWAR_eq1023_b2	`MC_NBITS_CONDITION'd4
`define	JMP_PDAR_eq30_b2	`MC_NBITS_CONDITION'd5
`define	JMP_PNWAR_eq15		`MC_NBITS_CONDITION'd6
`define	JMP_PNAR_eq14		`MC_NBITS_CONDITION'd7
`define	JMP_not_end_wr_P	`MC_NBITS_CONDITION'd8
`define	JMP_not_end_wr_S	`MC_NBITS_CONDITION'd9
`define	JMP_not_ZF			`MC_NBITS_CONDITION'd10
`define	JMP_MW_count_ne2	`MC_NBITS_CONDITION'd11
`define	JMP_PNAR_ne29		`MC_NBITS_CONDITION'd12
`define	JMP_output_cnt		`MC_NBITS_CONDITION'd13
`define	JMP_rd_en			`MC_NBITS_CONDITION'd14

// Set when the host has asked for a state dump rather than a digest. Last free condition slot.
`define	JMP_mode_dump		`MC_NBITS_CONDITION'd15


// ****************************************
// Evaluation Order:
// - FLOW_CALL
// - Exception
// - FLOW_RETURN
// - Condition_Signals
// - FLOW_NEXT or FLOW_X_
`define	MC_NBITS_FLOW	2
// FLOW_X_ <-- remain at same step
`define	FLOW_X_		2'b00
`define	FLOW_NEXT	2'b01
`define	FLOW_CALL	2'b10
`define	FLOW_RETURN	2'b11

// ****************************************
// Microcode addresses

`define	MC_X_	7'd0
// Subroutines
`define	MC_LR_ZERO_P_XOR_EK	7'd60
`define	MC_BF_ENCRYPT_ROUNDS_1_16	7'd58
`define	MC_SAVE_ITER_CURR		7'd56
`define	MC_BF_MAIN		7'd42
`define	MC_LR_ZERO_P_XOR_SALT	7'd53
`define	MC_ITER_CURR_DECR		7'd40
`define	MC_OUTPUT		7'd93

// ****************************************
`define	MC_NBITS_TOTAL ( \
		`MC_NBITS_E + 2 + \
		`MC_NBITS_P + \
		`MC_NBITS_LR + `MC_NBITS_S + \
		`MC_ADDR_MSB+1 + \
		`MC_NBITS_CONDITION + `MC_NBITS_FLOW \
)

// ****************************************

`define	CMD_NOP	{ `E_X_, `INPUT_X_, \
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_, \
			`LR_X_, `S_X_, `SWAR_X_, \
			`MC_X_, `JMP_X_, `FLOW_NEXT } \

`define	CMD_RETURN	{ `E_X_, `INPUT_X_, \
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_, \
			`LR_X_, `S_X_, `SWAR_X_, \
			`MC_X_, `JMP_X_, `FLOW_RETURN } \

`define CMD_CALL(arg) \
			{ `E_X_, `INPUT_X_, \
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_, \
			`LR_X_, `S_X_, `SWAR_X_, \
			arg, `JMP_X_, `FLOW_CALL } \

`define CMD_JMP(arg) \
			{ `E_X_, `INPUT_X_, \
			`P_X_, `PNWAR_X_, `PNAR_X_, `PDAR_X_, \
			`LR_X_, `S_X_, `SWAR_X_, \
			arg, `JMP_UNCONDITIONAL, `FLOW_X_ } \

`endif

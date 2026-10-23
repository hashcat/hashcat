/*%
   Common communication interface of default firmwares
   Copyright (C) 2009-2023 ZTEX GmbH.
   http://www.ztex.de

   Copyright and related rights are licensed under the Solderpad Hardware
   License, Version 0.51 (the "License"); you may not use this file except
   in compliance with the License. You may obtain a copy of the License at
   
       http://solderpad.org/licenses/SHL-0.51.
       
   Unless required by applicable law or agreed to in writing, software, hardware
   and materials distributed under this License is distributed on an "AS IS"
   BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied. See the License for the specific language governing permissions
   and limitations under the License.
%*/
/*
   Implements the EZ-USB Slave FIFO interface for both 
   directions. It also includes an scheduler (required if both
   directions are used at the same time) and short packets (PKTEND).
*/  
module ezusb_io #(
	parameter OUTEP = 2,            // EP for FPGA -> EZ-USB transfers
	parameter INEP = 6,             // EP for EZ-USB -> FPGA transfers 
	parameter TARGET = ""		// Target FPGA: "A7": Artix 7, "" all others
    ) (
        output ifclk,
        input reset,                    // asynchronous reset input
        output reset_out,		// synchronous reset output
        // pins
        input ifclk_in,
        inout [15:0] fd,
	output reg SLWR, PKTEND,
	output SLRD, SLOE, 
	output [1:0] FIFOADDR,
	input EMPTY_FLAG, FULL_FLAG,
	// signals for FPGA -> EZ-USB transfer
        input [15:0] DI,                // data written to EZ-USB
        input DI_valid,			// 1 indicates data valid; DI and DI_valid must be hold if DI_ready is 0
        output DI_ready, 		// 1 if new data are accepted
        input DI_enable,		// setting to 0 disables FPGA -> EZ-USB transfers
    	input pktend_arm,		// 0->1 transition enables the manual PKTEND mechanism:
    	                                // PKTEND is asserted as soon output becomes idle
    	                                // recommended procedure for accurate packet transfers:
    	                                //   * DI_valid goes low after last data of package
    	                                //   * monitor PKTEND and hold DI_valid until PKTEND is asserted (PKTEND = 0)
        input [15:0] pktend_timeout,    // automatic PKTEN assertion after pktend_timeout*65536 clocks of no output data
    					// setting to 0 disables this feature
	// signals for EZ-USB -> FPGA transfer
        output reg [15:0] DO,           // data read from EZ-USB
        output reg DO_valid,		// 1 indicated valid data
        input DO_ready,			// setting to 1 enables writing new data to DO in next clock; DO and DO_valid are hold if DO_ready is 0
    					// set to 0 to disable data reads 
        // debug output
        output [3:0] status
    );


    wire locked;

    generate
	if ( TARGET == "A7") begin: gen_artix7_clocks
	
	    wire ifclk_inbuf, ifclk_fbin, ifclk_fbout, ifclk_out;
	
	    IBUFG ifclkin_buf (
		.I(ifclk_in),
		.O(ifclk_inbuf) 
	    );

	    BUFG ifclk_fb_buf (
    		.I(ifclk_fbout),
    		.O(ifclk_fbin)
    	    ); 

	    BUFG ifclk_out_buf (
    		.I(ifclk_out),
    		.O(ifclk)
    	    ); 

	    MMCME2_BASE #(
    		.BANDWIDTH("OPTIMIZED"),
    		.CLKFBOUT_MULT_F(20.0),
    		.CLKFBOUT_PHASE(0.0),
    		.CLKIN1_PERIOD(0.0),
    		.CLKOUT0_DIVIDE_F(20.0), 
    		.CLKOUT1_DIVIDE(1),
    	    	.CLKOUT2_DIVIDE(1),
    	    	.CLKOUT3_DIVIDE(1),
    	    	.CLKOUT4_DIVIDE(1),
    	    	.CLKOUT5_DIVIDE(1),
    	    	.CLKOUT0_DUTY_CYCLE(0.5),
    	    	.CLKOUT1_DUTY_CYCLE(0.5),
    	    	.CLKOUT2_DUTY_CYCLE(0.5),
    	    	.CLKOUT3_DUTY_CYCLE(0.5),
    	    	.CLKOUT4_DUTY_CYCLE(0.5),
    	    	.CLKOUT5_DUTY_CYCLE(0.5),
    	    	.CLKOUT0_PHASE(0.0),
    	    	.CLKOUT1_PHASE(0.0),
    	    	.CLKOUT2_PHASE(0.0),
    	    	.CLKOUT3_PHASE(0.0),
    	    	.CLKOUT4_PHASE(0.0),
    	    	.CLKOUT5_PHASE(0.0),
    	    	.CLKOUT4_CASCADE("FALSE"), 
    	    	.DIVCLK_DIVIDE(1),
    	    	.REF_JITTER1(0.0),
    	    	.STARTUP_WAIT("FALSE")
	    )  ifclk_mmcm_inst (
    	    	.CLKOUT0(ifclk_out),
    	    	.CLKFBOUT(ifclk_fbout),
    	    	.CLKIN1(ifclk_inbuf),
    	    	.PWRDWN(1'b0),
    	    	.RST(reset),
    	    	.CLKFBIN(ifclk_fbin),
    	    	.LOCKED(locked)
	    );

	end else begin: gen_other_clocks
    
	    IBUFG ifclkin_buf (
		.I(ifclk_in),
		.O(ifclk) 
	    );
	    
	    assign locked = 1'b1;
	
	end
    endgenerate
	
    reg reset_ifclk = 1;
    reg if_out, if_in;
    reg [4:0] if_out_buf;
    reg [15:0] fd_buf;
    reg resend;
    reg SLRD_buf;
    reg pktend_auto, pktend_arm_buf, pktend_arm_prev;
    reg [31:0] pktend_cnt;

    // FPGA <-> EZ-USB signals
    assign SLOE = if_out;
//    assign FIFOADDR[0] = 1'b0;
//    assign FIFOADDR[1] = !if_out;
    assign FIFOADDR = ( if_out ? (OUTEP/2-1) : (INEP/2-1) ) & 2'b11;
    assign fd = if_out ? fd_buf : {16{1'bz}};
    assign SLRD = SLRD_buf || !DO_ready;

    assign status = { !SLRD_buf, !SLWR, resend, if_out };

    assign DI_ready = !reset_ifclk && FULL_FLAG && if_out & if_out_buf[4] && !resend;
    assign reset_out = reset || reset_ifclk;
    
    always @ (posedge ifclk)
    begin
	reset_ifclk <= reset || !locked;
	// FPGA -> EZ-USB
        if ( reset_ifclk )
        begin
	    SLWR <= 1'b1;
	    if_out <= DI_enable;  // direction of EZ-USB interface: 1 means FPGA -> EZ_USB 
	    resend <= 1'b0;
	    SLRD_buf <= 1'b1;
	end else if ( FULL_FLAG && if_out && if_out_buf[4] && ( resend || DI_valid) )  	// FPGA -> EZ-USB
	begin
	    SLWR <= 1'b0;
	    SLRD_buf <= 1'b1;
	    resend <= 1'b0;
	    if ( !resend ) fd_buf <= DI;
	end else if ( EMPTY_FLAG && !if_out && !if_out_buf[4] && DO_ready )  		// EZ-USB -> FPGA
	begin
	    SLWR <= 1'b1;
	    DO <= fd;
	    SLRD_buf <= 1'b0;
	end else if (if_out == if_out_buf[4])
	begin
	    if ( !SLWR && !FULL_FLAG ) resend <= 1'b1;  // FLAGS are received two clocks after data. If FULL_FLAG was asserted last data was ignored and has to be re-sent.
	    SLRD_buf <= 1'b1;
	    SLWR <= 1'b1;
	    if_out <= DI_enable && (!DO_ready || !EMPTY_FLAG);
	end 
	if_out_buf <= reset_ifclk ? {5{!DI_enable}} : { if_out_buf[3:0], if_out };
	if ( DO_ready ) DO_valid <= !if_out && !if_out_buf[4] && EMPTY_FLAG && !SLRD_buf;  // assertion of SLRD_buf takes two clocks to take effect
	
	// PKTEND processing
	pktend_arm_prev <= pktend_arm;
        if ( reset_ifclk || !SLWR || resend || DI_valid || !FULL_FLAG )
        begin
    	    // auto mode is always enabled if data appears. It may send ZLP's.
    	    pktend_auto <= !reset_ifclk && (pktend_auto || !SLWR);
	    pktend_cnt <= 32'd0;
    	    PKTEND <= 1'b1;
    	    pktend_arm_buf <= (!reset_ifclk) && ( pktend_arm_buf || ( pktend_arm && !pktend_arm_prev ) );
    	// PKTEND must not be asserted unless a buffer is available (FULL=1)
    	end else if ( if_out && if_out_buf[4] && ( pktend_arm_buf || ( pktend_auto && (pktend_timeout != 16'd0) && (pktend_timeout <= pktend_cnt[31:16]) ) ) )
    	begin
    	    PKTEND <= 1'b0;
    	    pktend_auto <= 1'b0;
    	    pktend_arm_buf <= 1'b0;
    	end else 
    	begin
    	    PKTEND <= 1'b1;
    	    pktend_cnt <= pktend_cnt + 32'd1;
    	    pktend_arm_buf <= pktend_arm_buf || ( pktend_arm && !pktend_arm_prev );
    	end
    end

endmodule


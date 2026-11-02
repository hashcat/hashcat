/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
//
// Entry for the bare metal thermal load application.
//
// The BootROM has already parked the cores in JTAG boot mode and OCM is live at address 0, so the
// image needs no relocation and no DDR setup. The debugger loads this image, points the PC at
// _start and releases the core.
//
// A real vector table is laid down even though normal execution takes no exceptions. The cost is
// eight words, and the alternative is that any fault at all runs off into whatever OCM happens to
// hold.
//
// Every fault writes a record before it stops. A bare spin loop is safe but provides no diagnostic,
// and an application that dies on a fault then looks, from every counter the host can read, exactly
// like an Ethernet controller that has stopped handing back buffers.
//
// So the handlers cost 20 more instructions and record which vector was taken, where, and what the
// fault registers held. The host reads it and is told what actually happened.

  .equ FAULT_BASE,   0x0000F100
  .equ FAULT_MAGIC,  0xFA017ED0

  .section .vectors, "ax"
  .global _start

_start:
  b     reset
  b     fault_undef
  b     fault_svc
  b     fault_pabt
  b     fault_dabt
  b     hang          // reserved
  b     fault_irq
  b     fault_fiq

fault_undef:
  mov   r0, #1
  b     fault_record

fault_svc:
  mov   r0, #2
  b     fault_record

fault_pabt:
  mov   r0, #3
  b     fault_record

fault_dabt:
  mov   r0, #4
  b     fault_record

fault_irq:
  mov   r0, #6
  b     fault_record

fault_fiq:
  mov   r0, #7
  b     fault_record

// Record the fault and stop. Recovery and return are unsupported: the application has no
// meaningful way to carry on past a fault, and stopping with an explanation is worth far more than
// continuing without one.
//
// The magic is written LAST, so a record that is half stored is never reported as a whole one.
fault_record:
  ldr   r1, =FAULT_BASE

  str   r0, [r1, #4]              // which vector was taken
  str   lr, [r1, #8]              // return address, so the faulting instruction is close by

  mrc   p15, 0, r2, c5, c0, 0     // data fault status
  str   r2, [r1, #12]

  mrc   p15, 0, r2, c6, c0, 0     // data fault address
  str   r2, [r1, #16]

  mrc   p15, 0, r2, c5, c0, 1     // instruction fault status
  str   r2, [r1, #20]

  mrc   p15, 0, r2, c6, c0, 2     // instruction fault address
  str   r2, [r1, #24]

  mrs   r2, spsr                  // the mode the fault came from
  str   r2, [r1, #28]

  ldr   r2, =FAULT_MAGIC
  str   r2, [r1, #0]

  b     hang

reset:
  // No interrupt handlers are installed, so masking both is the honest thing to do rather than
  // leaving them enabled and assuming neither interrupt will fire.
  cpsid if

  // The stack lives at the top of the low OCM block. Code sits at 0, the sample log at 0x10000, so
  // growing down from 0x2FFF0 leaves the whole gap between them free.
  ldr   sp, =0x0002FFF0

  // ZERO .bss BEFORE ANYTHING ELSE RUNS.
  //
  // A flat binary contains only what has initialised content, so .bss occupies addresses that are in
  // the link map and NOT in the image. This code must clear them. Every zero-initialised
  // static therefore comes up holding whatever the last thing to use that memory left behind, which
  // is not zero on a board that has been running.
  ldr   r0, =__bss_start
  ldr   r1, =__bss_end
  mov   r2, #0

bss_zero:
  cmp   r0, r1
  strlo r2, [r0], #4
  blo   bss_zero

  // Invalidate any fault record left by a previous run. It sits at a fixed address so the host can
  // find it without a symbol table, which also means .bss clearing does not reach it, and a stale
  // record would be reported as if this run had faulted.
  ldr   r0, =FAULT_BASE
  mov   r1, #0
  str   r1, [r0, #0]

  bl    main

hang:
  b     hang

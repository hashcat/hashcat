/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
/*
 * Link map for the bare metal thermal load.
 *
 * OCM only. At reset the Zynq maps three 64K blocks low, so 0x00000000 to 0x0002FFFF is live with no
 * DDR controller involved and no state to initialise. That is the whole reason this design skips
 * DDR: DDR bring-up is the most board-specific and most fragile part of ps7_init, and none of it is
 * needed to run an application this size.
 *
 *   0x00000000  code, starting with the vector table
 *   0x00010000  sample log, written here and read out over JTAG afterwards
 *   0x0002FFF0  stack top, growing down toward the log
 */

ENTRY(_start)

MEMORY
{
  ocm (rwx) : ORIGIN = 0x00000000, LENGTH = 0x00010000
}

SECTIONS
{
  /*
   * THE VECTOR TABLE MUST BE THE FIRST BYTE OF THE IMAGE, because the debugger starts this by
   * setting the PC to 0 rather than by reading the ELF entry point.
   *
   * Without the discard below, the linker places .note.gnu.build-id at address 0 as an orphan
   * section and pushes _start to 0x24. That failure is silent and vicious: the load succeeds, the
   * core resumes, and it executes 36 bytes of ELF metadata as ARM instructions before running off
   * into memory that does not exist.
   */
  /DISCARD/ : {
    *(.note*)
    *(.comment)
    *(.ARM.attributes)
  }

  .text : {
    KEEP(*(.vectors))
    *(.text*)
  } > ocm

  .rodata : {
    *(.rodata*)
  } > ocm

  .data : {
    *(.data*)
  } > ocm

  /*
   * The end of what the host loads. A flat binary stops at the last section with content, so this is
   * its length, and the Makefile refuses an image where the two disagree. The application checksums
   * the bytes up to here at startup and reports the result in its ping reply.
   */
  __image_end = .;

  .bss : {
    __bss_start = .;
    *(.bss*)
    *(COMMON)
    __bss_end = .;
  } > ocm

  . = ALIGN(8);
  _end = .;
}

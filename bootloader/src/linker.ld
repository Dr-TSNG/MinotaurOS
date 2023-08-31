OUTPUT_ARCH(riscv)
ENTRY(_start)
KERNEL_PADDR_BASE = 0x80200000;

SECTIONS
{
    . = KERNEL_PADDR_BASE;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    .bss : {
        *(.bss.stack)
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    ebss = .;

    /DISCARD/ : {
        *(.eh_frame)
    }
}

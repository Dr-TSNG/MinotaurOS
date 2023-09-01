OUTPUT_ARCH(riscv)
ENTRY(_start)
BOOTLOADER_PADDR_BASE = 0x80200000;
KERNEL_PADDR_BASE = 0x80400000;

SECTIONS
{
    . = BOOTLOADER_PADDR_BASE;
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

    . = KERNEL_PADDR_BASE;

    /DISCARD/ : {
        *(.eh_frame)
    }
}

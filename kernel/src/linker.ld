OUTPUT_ARCH(riscv)
ENTRY(_start)
KERNEL_VADDR_BASE = 0xFFFFFFFF80200000;

SECTIONS
{
    . = KERNEL_VADDR_BASE;
    skernel = .;

    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4K);
    etext = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    . = ALIGN(4K);
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    .bss : {
        *(.bss.stack)
        sbss = .;
        . = ALIGN(4K);
        *(.bss.heap)
        . = ALIGN(4K);
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    ebss = .;

    . = ALIGN(2M);
    ekernel = .;
}

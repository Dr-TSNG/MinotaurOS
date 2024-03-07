.section .data
.align 3
.global builtin_apps
builtin_apps:
    .quad 1
    .quad builtin_app_0_start
    .quad builtin_app_0_end

.global builtin_app_names
builtin_app_names:
    .string "init"

.section .data
.align 3
.global builtin_app_0_start
builtin_app_0_start:
    .incbin "target/riscv64gc-unknown-none-elf/debug/init"
.global builtin_app_0_end
builtin_app_0_end:

.section .data
.align 3
.global builtin_apps
builtin_apps:
    .quad 4
    .quad builtin_app_0_start
    .quad builtin_app_1_start
    .quad builtin_app_2_start
    .quad builtin_app_3_start
    .quad builtin_app_3_end

.global builtin_app_names
builtin_app_names:
    .string "shell"
    .string "testsuits"
    .string "proc_test"
    .string "sig_test"

.section .data
.align 3
.global builtin_app_0_start
builtin_app_0_start:
    .incbin "target/riscv64gc-unknown-none-elf/release/shell"
.global builtin_app_1_start
builtin_app_1_start:
    .incbin "target/riscv64gc-unknown-none-elf/release/testsuits"
.global builtin_app_2_start
builtin_app_2_start:
    .incbin "target/riscv64gc-unknown-none-elf/release/proc_test"
.global builtin_app_3_start
builtin_app_3_start:
    .incbin "target/riscv64gc-unknown-none-elf/release/sig_test"
builtin_app_3_end:

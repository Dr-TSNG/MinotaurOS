use core::arch::asm;
use riscv::register::sstatus;
use crate::config::MAX_HARTS;
use crate::println;

pub struct Hart {
    pub id: usize,
}

impl Hart {
    const fn new() -> Self {
        Self {
            id: 0,
        }
    }
}

const HART_EACH: Hart = Hart::new();
static mut HARTS: [Hart; MAX_HARTS] = [HART_EACH; MAX_HARTS];

pub fn current_hart() -> &'static mut Hart {
    unsafe {
        let tp: usize;
        asm!("mv {}, tp", out(reg) tp);
        &mut HARTS[tp]
    }
}

pub fn init(hart_id: usize) {
    unsafe {
        // 将当前 hart 的 id 保存到 tp 寄存器
        asm!("mv tp, {}", in(reg) hart_id);
        HARTS[hart_id].id = hart_id;
        // 允许内核访问用户态地址空间
        sstatus::set_sum();
    };
    println!("[kernel] Hart {} initialized", current_hart().id);
}

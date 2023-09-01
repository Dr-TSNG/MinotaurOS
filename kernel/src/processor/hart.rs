use core::arch::asm;
use common::println;
use crate::board::HART_CNT;

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
static mut HARTS: [Hart; HART_CNT] = [HART_EACH; HART_CNT];

pub fn current_hart() -> &'static mut Hart {
    unsafe {
        let tp: usize;
        asm!("mv {}, tp", out(reg) tp);
        &mut HARTS[tp]
    }
}

pub fn init() {
    unsafe {
        let tp: usize;
        asm!("mv {}, tp", out(reg) tp);
        let hart = &mut HARTS[tp];
        hart.id = tp;
    };
    println!("[kernel] Hart {} initialized", current_hart().id);
}

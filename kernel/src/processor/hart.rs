use alloc::sync::Arc;
use core::arch::asm;
use aligned::{A16, Aligned};
use riscv::register::mstatus::FS;
use riscv::register::sstatus;
use crate::config::{KERNEL_STACK_SIZE, MAX_HARTS};
use crate::mm::KERNEL_SPACE;
use crate::process::thread::Thread;
use crate::processor::context::HartContext;

pub struct Hart {
    pub id: usize,
    pub ctx: HartContext,
}

impl Hart {
    const fn new() -> Self {
        Self {
            id: 0,
            ctx: HartContext::new(None),
        }
    }

    pub fn current_thread(&self) -> Option<&Arc<Thread>> {
        self.ctx.user_task.as_ref().map(|t| &t.thread)
    }

    pub fn switch_ctx(&mut self, another: &mut HartContext) {
        let (thread_now, thread_next) = (
            self.current_thread(),
            another.user_task.as_ref().map(|t| &t.thread),
        );
        if let Some(now) = thread_now {
            now.inner().rusage.sched_out();
        }
        if let Some(next) = thread_next {
            next.inner().rusage.sched_in();
            let switch_pt = match thread_now {
                Some(now) => now.tid != next.tid,
                None => true,
            };
            if switch_pt {
                unsafe { next.process.inner.lock().addr_space.activate(); }
            }
        } else {
            if thread_now.is_some() {
                unsafe { KERNEL_SPACE.lock().activate(); }
            }
        }
        core::mem::swap(&mut self.ctx, another);
    }
}

const HART_EACH: Hart = Hart::new();
static mut HARTS: [Hart; MAX_HARTS] = [HART_EACH; MAX_HARTS];

#[link_section = ".bss.uninit"]
pub static mut KERNEL_STACK: Aligned<A16, [u8; KERNEL_STACK_SIZE * MAX_HARTS]> = Aligned([0; KERNEL_STACK_SIZE * MAX_HARTS]);

pub fn local_hart() -> &'static mut Hart {
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
        sstatus::set_fs(FS::Clean);
    };
}

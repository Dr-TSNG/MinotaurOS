use alloc::sync::Arc;
use core::arch::asm;
use riscv::register::sstatus;
use crate::config::MAX_HARTS;
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
        if let Some(task) = &another.user_task {
            let switch_pt = match self.current_thread() {
                Some(t) => t.tid != task.thread.tid,
                None => true,
            };
            if switch_pt {
                unsafe { task.thread.process.inner.lock().addr_space.activate(); }
            }
        } else {
            if self.current_thread().is_some() {
                unsafe { KERNEL_SPACE.lock().activate(); }
            }
        }
        core::mem::swap(&mut self.ctx, another);
    }
}

const HART_EACH: Hart = Hart::new();
static mut HARTS: [Hart; MAX_HARTS] = [HART_EACH; MAX_HARTS];

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
    };
}

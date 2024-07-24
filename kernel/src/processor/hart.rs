use alloc::sync::Arc;
use core::arch::asm;
use aligned::{A16, Aligned};
use riscv::register::sstatus;
use riscv::register::sstatus::FS;
use crate::arch;
use crate::config::{KERNEL_STACK_SIZE, MAX_HARTS};
use crate::mm::addr_space::AddressSpace;
use crate::mm::asid::ASIDManager;
use crate::mm::KERNEL_SPACE;
use crate::process::thread::Thread;
use crate::processor::context::HartContext;
use crate::result::SyscallResult;

pub struct Hart {
    pub id: usize,
    pub ctx: HartContext,
    pub asid_manager: Option<ASIDManager>,
    pub on_kintr: bool,
    pub on_page_test: bool,
    pub last_page_fault: SyscallResult,
    kintr_rec: usize,
}

pub struct KIntrGuard;

impl KIntrGuard {
    pub fn new() -> Self {
        local_hart().disable_kintr();
        Self
    }
}

impl Drop for KIntrGuard {
    fn drop(&mut self) {
        local_hart().enable_kintr();
    }
}

impl Hart {
    const fn new() -> Self {
        Self {
            id: 0,
            ctx: HartContext::kernel(),
            asid_manager: None,
            on_kintr: false,
            on_page_test: false,
            last_page_fault: Ok(()),
            kintr_rec: 0,
        }
    }

    pub fn current_thread(&self) -> Option<&Arc<Thread>> {
        self.ctx.user_task.as_ref().map(|t| &t.thread)
    }

    pub fn switch_ctx(&mut self, another: &mut HartContext) {
        self.disable_kintr();
        let (thread_now, task_next) = (
            self.current_thread(),
            another.user_task.as_mut(),
        );
        if let Some(now) = thread_now {
            now.inner().trap_ctx.fctx.sched_out();
            now.inner().rusage.sched_out();
        }
        if let Some(next) = task_next {
            next.thread.inner().rusage.sched_in();
            let switch_pt = match thread_now {
                Some(now) => now.tid != next.thread.tid,
                None => true,
            };
            if switch_pt {
                if let Some(asid) = next.asid.upgrade() {
                    // Fast path
                    unsafe { AddressSpace::activate_pt_with_asid(next.root_pt, *asid); }
                } else {
                    // Slow path
                    let mut proc_inner = next.thread.process.inner.lock();
                    unsafe { proc_inner.addr_space.activate(); }
                    next.asid = proc_inner.addr_space.asid.clone();
                }
            }
        } else {
            if thread_now.is_some() {
                unsafe { KERNEL_SPACE.lock().activate(); }
            }
        }
        core::mem::swap(&mut self.ctx, another);
        self.enable_kintr();
    }

    pub fn enable_kintr(&mut self) {
        self.kintr_rec -= 1;
        if self.kintr_rec == 0 && !self.on_kintr {
            arch::enable_kernel_interrupt();
        }
    }

    pub fn disable_kintr(&mut self) {
        if self.kintr_rec == 0 {
            arch::disable_kernel_interrupt();
        }
        self.kintr_rec += 1;
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

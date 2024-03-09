#![allow(unused)]

use core::arch::asm;
use sbi_spec::dbcn::{CONSOLE_READ, CONSOLE_WRITE, EID_DBCN};
use sbi_spec::srst::{EID_SRST, RESET_REASON_NO_REASON, RESET_TYPE_SHUTDOWN, SYSTEM_RESET};
use sbi_spec::time::{EID_TIME, SET_TIMER};

pub use sbi_spec::binary::Error as SBIError;
use crate::arch::{kvaddr_to_paddr, VirtAddr};
use crate::processor::hart::local_hart;

#[inline(always)]
fn sbi_call(eid: usize, fid: usize, arg0: usize, arg1: usize, arg2: usize) -> Result<usize, SBIError> {
    let error: usize;
    let value: usize;
    unsafe {
        asm! {
        "ecall",
        inlateout("a0") arg0 => error,
        inlateout("a1") arg1 => value,
        in("a2") arg2,
        in("a6") fid,
        in("a7") eid,
        };
    }
    let ret = sbi_spec::binary::SbiRet { error, value };
    ret.into_result()
}

pub fn set_timer(timer: usize) -> Result<(), SBIError> {
    sbi_call(EID_TIME, SET_TIMER, timer, 0, 0).map(|_| ())
}

pub fn console_read(buffer: &mut [u8]) -> Result<usize, SBIError> {
    sbi_call(EID_DBCN, CONSOLE_READ, buffer.len(), buffer.as_mut_ptr() as usize, 0)
}

pub fn console_write(content: &str) -> Result<usize, SBIError> {
    let content = content.as_bytes();
    let vaddr = VirtAddr(content.as_ptr() as usize);
    let paddr = match &local_hart().ctx.user_task {
        Some(task) => task.root_pt.translate(vaddr),
        None => kvaddr_to_paddr(vaddr),
    };
    sbi_call(EID_DBCN, CONSOLE_WRITE, content.len(), paddr.0, 0)
}

pub fn shutdown() -> Result<!, SBIError> {
    sbi_call(EID_SRST, SYSTEM_RESET, RESET_TYPE_SHUTDOWN as usize, RESET_REASON_NO_REASON as usize, 0)?;
    unreachable!()
}

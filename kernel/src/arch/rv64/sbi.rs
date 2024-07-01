use core::arch::asm;

pub use sbi_spec::binary::Error as SBIError;
use sbi_spec::binary::SbiRet;
use sbi_spec::hsm::{EID_HSM, HART_GET_STATUS, HART_START, HART_STOP};
use sbi_spec::srst::{EID_SRST, RESET_REASON_NO_REASON, RESET_TYPE_SHUTDOWN, SYSTEM_RESET};
use sbi_spec::time::{EID_TIME, SET_TIMER};

#[inline(always)]
fn sbi_call(eid: usize, fid: usize, arg0: usize, arg1: usize, arg2: usize) -> Result<usize, SBIError> {
    let (error, value);
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
    let ret = SbiRet { error, value };
    ret.into_result()
}

pub fn set_timer(timer: usize) -> Result<(), SBIError> {
    sbi_call(EID_TIME, SET_TIMER, timer, 0, 0).map(|_| ())
}

pub fn start_hart(hart_id: usize, start_paddr: usize) -> Result<(), SBIError> {
    sbi_call(EID_HSM, HART_START, hart_id, start_paddr, 0).map(|_| ())
}

pub fn stop_hart(hart_id: usize) -> Result<(), SBIError> {
    sbi_call(EID_HSM, HART_STOP, hart_id, 0, 0).map(|_| ())
}

pub fn hart_status(hart_id: usize) -> Result<usize, SBIError> {
    sbi_call(EID_HSM, HART_GET_STATUS, hart_id, 0, 0)
}

pub fn shutdown() -> Result<!, SBIError> {
    sbi_call(EID_SRST, SYSTEM_RESET, RESET_TYPE_SHUTDOWN as usize, RESET_REASON_NO_REASON as usize, 0)?;
    unreachable!()
}

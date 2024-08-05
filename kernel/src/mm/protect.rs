use core::arch::asm;
use core::cmp::min;
use core::ffi::CStr;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use crate::arch::{PAGE_SIZE, VirtAddr};
use crate::processor::hart::{KIntrGuard, local_hart};
use crate::result::{Errno, SyscallResult};

pub fn user_transmute_r<T: FromBytes>(addr: usize) -> SyscallResult<Option<&'static T>> {
    match addr {
        0 => Ok(None),
        _ => {
            let addr = VirtAddr(addr);
            check_slice_readable(addr, size_of::<T>())?;
            let bytes = unsafe { core::slice::from_raw_parts(addr.as_ptr(), size_of::<T>()) };
            Ok(Some(T::ref_from(bytes).unwrap()))
        }
    }
}

pub fn user_transmute_w<T: AsBytes + FromBytes>(addr: usize) -> SyscallResult<Option<&'static mut T>> {
    match addr {
        0 => Ok(None),
        _ => {
            let addr = VirtAddr(addr);
            check_slice_writable(addr, size_of::<T>())?;
            let bytes = unsafe { core::slice::from_raw_parts_mut(addr.as_ptr(), size_of::<T>()) };
            Ok(Some(T::mut_from(bytes).unwrap()))
        }
    }
}

pub fn user_transmute_str(addr: usize, max_len: usize) -> SyscallResult<Option<&'static str>> {
    match addr {
        0 => Ok(None),
        _ => {
            let mut cur_len = min(max_len, PAGE_SIZE - (addr % PAGE_SIZE));
            while cur_len <= max_len {
                let data = user_slice_r(addr, cur_len)?;
                if let Ok(cstr) = CStr::from_bytes_until_nul(data) {
                    return Ok(Some(cstr.to_str().map_err(|_| Errno::EINVAL)?));
                }
                cur_len = min(cur_len + PAGE_SIZE, max_len);
            }
            Err(Errno::EINVAL)
        }
    }
}

pub fn user_slice_r(addr: usize, len: usize) -> SyscallResult<&'static [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    let addr = VirtAddr(addr);
    check_slice_readable(addr, len)?;
    let bytes = unsafe { core::slice::from_raw_parts(addr.as_ptr(), len) };
    Ok(bytes)
}

pub fn user_slice_w(addr: usize, len: usize) -> SyscallResult<&'static mut [u8]> {
    if len == 0 {
        return Ok(&mut []);
    }
    let addr = VirtAddr(addr);
    check_slice_writable(addr, len)?;
    let bytes = unsafe { core::slice::from_raw_parts_mut(addr.as_ptr(), len) };
    Ok(bytes)
}

fn check_slice_readable(addr: VirtAddr, len: usize) -> SyscallResult {
    let _guard = KIntrGuard::new();
    local_hart().on_page_test = true;
    let start = addr.floor();
    let end = (addr + len).ceil();
    for vpn in start..end {
        if unsafe { try_read_u8(VirtAddr::from(vpn).as_ptr()) } {
            local_hart().on_page_test = false;
            return local_hart().last_page_fault;
        }
    }
    local_hart().on_page_test = false;
    Ok(())
}

fn check_slice_writable(addr: VirtAddr, len: usize) -> SyscallResult {
    if 0xFFFFFFFFFFFFFFFF - addr.0 < len{
    	return Err(Errno::EFAULT);
    }

    let _guard = KIntrGuard::new();
    local_hart().on_page_test = true;
    let start = addr.floor();
    let end = (addr + len).ceil();
    for vpn in start..end {
        if unsafe { try_write_u8(VirtAddr::from(vpn).as_ptr()) } {
            local_hart().on_page_test = false;
            return local_hart().last_page_fault;
        }
    }
    local_hart().on_page_test = false;
    Ok(())
}

#[naked]
unsafe extern "C" fn try_read_u8(addr: *const u8) -> bool {
    asm! {
    "mv t0, a0",
    "li a0, 1",
    "lb t0, 0(t0)",
    "li a0, 0",
    "ret",
    options(noreturn),
    }
}

#[naked]
unsafe extern "C" fn try_write_u8(addr: *mut u8) -> bool {
    asm! {
    "mv t0, a0",
    "li a0, 1",
    "lb t1, 0(t0)",
    "sb t1, 0(t0)",
    "li a0, 0",
    "ret",
    options(noreturn),
    }
}

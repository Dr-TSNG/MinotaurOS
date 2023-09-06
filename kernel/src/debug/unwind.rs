use core::ffi::c_void;
use log::error;
use unwinding::abi::{_Unwind_Backtrace, _Unwind_GetIP, UnwindContext, UnwindReasonCode};

pub fn print_stack_trace() {
    struct CallbackData {
        counter: usize,
    }
    extern "C" fn callback(unwind_ctx: &UnwindContext<'_>, arg: *mut c_void) -> UnwindReasonCode {
        let data = unsafe { &mut *(arg as *mut CallbackData) };
        data.counter += 1;
        error!(
            "{:4}:{:#19x} - <unknown>",
            data.counter,
            _Unwind_GetIP(unwind_ctx),
        );
        UnwindReasonCode::NO_REASON
    }
    let mut data = CallbackData { counter: 0 };
    _Unwind_Backtrace(callback, &mut data as *mut _ as _);
}

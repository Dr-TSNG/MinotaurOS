use alloc::vec::Vec;
use core::arch::global_asm;
use crate::sync::once::LateInit;

#[cfg(debug_assertions)]
global_asm!(include_str!("debug.asm"));

#[cfg(not(debug_assertions))]
global_asm!(include_str!("release.asm"));

extern {
    fn builtin_apps();
    fn builtin_app_names();
}

#[inline]
fn builtin_app_num() -> usize {
    unsafe { *(builtin_apps as usize as *const usize) }
}

fn builtin_app_data(app_id: usize) -> &'static [u8] {
    let app_num_ptr = builtin_apps as usize as *const usize;
    let app_num = builtin_app_num();
    let app_start = unsafe {
        core::slice::from_raw_parts(app_num_ptr.add(1), app_num + 1)
    };
    assert!(app_id < app_num);
    unsafe {
        core::slice::from_raw_parts(
            app_start[app_id] as *const u8,
            app_start[app_id + 1] - app_start[app_id],
        )
    }
}

static APP_NAMES: LateInit<Vec<&'static str>> = LateInit::new();

pub fn init() {
    let app_num = builtin_app_num();
    let mut start = builtin_app_names as usize as *const u8;
    let mut apps = Vec::new();
    unsafe {
        for _ in 0..app_num {
            let mut end = start;
            while *end != b'\0' {
                end = end.add(1);
            }
            let slice = core::slice::from_raw_parts(start, end as usize - start as usize);
            let str = core::str::from_utf8(slice).unwrap();
            apps.push(str);
            start = end.add(1);
        }
        APP_NAMES.init(apps);
    }
}

pub fn builtin_app(name: &str) -> Option<&'static [u8]> {
    let app_num = builtin_app_num();
    (0..app_num)
        .find(|&i| APP_NAMES[i] == name)
        .map(builtin_app_data)
}

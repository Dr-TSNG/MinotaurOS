#![no_std]
#![no_main]

use user_lib::syscall::{mount, sys_execve, sys_fork, sys_mkdir, sys_waitpid};

#[no_mangle]
fn main() {
    sys_mkdir("/dev", 0);
    sys_mkdir("/proc", 0);
    sys_mkdir("/tmp", 0);
    sys_mkdir("/sys", 0);
    mount("devfs", "/dev", "devfs", 0, None);
    if sys_fork() == 0 {
        sys_execve(
            "/busybox",
            &["busybox", "sh"],
            &["PATH=/:/bin:", "LD_LIBRARY_PATH=/:", "TERM=screen"],
        );
    } else {
        let mut result: i32 = 0;
        sys_waitpid(-1, &mut result);
    }
}

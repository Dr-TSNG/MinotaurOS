#![no_std]
#![no_main]

use user_lib::syscall::{mount, sys_execve, sys_fork, sys_mkdir, sys_waitpid};

fn run_cmd(cmd: &str) {
    if sys_fork() == 0 {
        sys_execve(
            "/busybox",
            &["busybox", "sh", "-c", cmd],
            &["PATH=/:/bin:/lib", "LD_LIBRARY_PATH=/lib"],
        );
    } else {
        let mut result: i32 = 0;
        sys_waitpid(-1, &mut result);
    }
}

#[no_mangle]
fn main() {
    sys_mkdir("/dev", 0);
    sys_mkdir("/proc", 0);
    sys_mkdir("/tmp", 0);
    sys_mkdir("/sys", 0);
    mount("devfs", "/dev", "devfs", 0, None);
    run_cmd("busybox cp /lib/dlopen_dso.so /");
    run_cmd("busybox touch sort.src");
    run_cmd("busybox sh");
}

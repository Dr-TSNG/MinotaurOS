#![no_std]
#![no_main]
extern crate alloc;

use alloc::format;
use user_lib::syscall::*;

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

fn init_shell() {
    run_cmd("echo Linking busybox applets...");
    let mut pipes = [0, 0];
    sys_pipe(&mut pipes);
    if sys_fork() == 0 {
        sys_dup2(pipes[1], 1);
        sys_execve("/busybox", &["busybox", "--help"], &[]);
    } else {
        let mut result: i32 = 0;
        sys_waitpid(-1, &mut result);
        let mut buf = [0u8; 4096];
        let len = sys_read(pipes[0], &mut buf) as usize;
        for applet in core::str::from_utf8(&buf[..len])
            .unwrap()
            .lines()
            .skip_while(|line| !line.starts_with("Currently defined functions:"))
            .skip(1)
            .flat_map(|line| line.split(','))
            .map(|line| line.trim())
            .filter(|line| !line.is_empty()) {
            run_cmd(&format!("busybox ln -s /busybox /bin/{} > /dev/null 2>&1", applet));
        }
    }
}

#[no_mangle]
fn main() {
    sys_mkdir("/dev", 0);
    sys_mkdir("/proc", 0);
    sys_mkdir("/tmp", 0);
    sys_mkdir("/sys", 0);
    mount("devfs", "/dev", "devfs", 0, None);
    mount("procfs", "/proc", "procfs", 0, None);
    if sys_access("sort.src", 0) != 0 {
        init_shell();
        run_cmd("busybox ln -s /lib/dlopen_dso.so /dlopen_dso.so");
        run_cmd("busybox touch sort.src");
    }
    run_cmd("busybox sh");
}

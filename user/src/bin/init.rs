#![no_std]
#![no_main]

extern crate user_lib;
extern crate alloc;

use alloc::format;
use user_lib::syscall::{sys_execve, sys_exit, sys_fork, sys_waitpid};

fn execute_process(path: &str) {
    let pid = sys_fork() as usize;
    if pid == 0 {
        sys_execve(path, &[], &[]);
        sys_exit(-1);
    }
    let mut result = 0;
    sys_waitpid(pid, &mut result);
}

#[no_mangle]
fn main() -> i32 {
    let applets = [
        "brk", "chdir", "clone", "close", "dup2", "dup", "execve", "exit",
        "fork", "fstat", "getcwd", "getdents", "getpid", "getppid", "gettimeofday", "mkdir_",
        "mmap", "mount", "munmap", "openat", "open", "pipe", "read", "sleep",
        "times", "umount", "uname", "unlink", "wait", "waitpid", "write", "yield",
    ];
    for applet in applets.into_iter() {
        execute_process(&format!("/{}", applet));
    }
    0
}

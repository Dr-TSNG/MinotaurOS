#![no_std]
#![no_main]

extern crate alloc;
extern crate user_lib;

use user_lib::println;
use user_lib::syscall::{OpenFlags, sys_close, sys_execve, sys_exit, sys_fork, sys_mkdir, sys_open, sys_waitpid, sys_write};

fn execute(path: &str, argv: &[&str], envp: &[&str]) {
    let pid = sys_fork() as usize;
    if pid == 0 {
        sys_execve(path, argv, envp);
        println!("!!! execve failed !!!");
        sys_exit(-1);
    }
    let mut result = 0;
    sys_waitpid(pid, &mut result);
}

fn execute_cmd(cmd: &[u8]) {
    let fd = sys_open("/current_test.sh", OpenFlags::O_WRONLY | OpenFlags::O_CREAT);
    sys_write(fd, cmd);
    sys_close(fd);
    execute("/busybox", &["sh", "/current_test.sh"], &["PATH=/:/bin", "ASH_STANDALONE=1"]);
}

fn busybox_test() {
    let busybox_cmd = include_bytes!("../test/busybox_cmd.txt");
    execute_cmd(busybox_cmd);
}

fn run_testsuits() {
    execute("/time-test", &[], &[]);
    busybox_test();
}

#[no_mangle]
fn main() {
    sys_mkdir("/dev", 0);
    sys_mkdir("/proc", 0);
    sys_mkdir("/tmp", 0);
    sys_mkdir("/sys", 0);
    run_testsuits();
}

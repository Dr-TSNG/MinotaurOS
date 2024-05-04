#![no_std]
#![no_main]

extern crate alloc;
extern crate user_lib;

use user_lib::println;
use user_lib::syscall::{sys_execve, sys_exit, sys_fork, sys_mkdir, sys_waitpid};

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

fn execute_script(script: &str) {
    execute("/busybox", &["sh", script], &["PATH=/:/bin", "ASH_STANDALONE=1"]);
}

fn time_test() {
    println!("run time-test");
    execute("/time-test", &[], &[]);
}

fn busybox_test() {
    println!("run busybox_testcode.sh");
    execute_script("/busybox_testcode.sh");
}

fn lua_test() {
    println!("run lua_testcode.sh");
    execute_script("/lua_testcode.sh");
}

fn run_testsuits() {
    time_test();
    busybox_test();
    lua_test();
}

#[no_mangle]
fn main() {
    sys_mkdir("/dev", 0);
    sys_mkdir("/proc", 0);
    sys_mkdir("/tmp", 0);
    sys_mkdir("/sys", 0);
    run_testsuits();
}

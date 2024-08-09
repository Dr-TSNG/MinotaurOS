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
            &["PATH=/:/bin:/lib", "LD_LIBRARY_PATH=/:/lib:/lib/glibc:/lib/musl"],
        );
    } else {
        let mut result: i32 = 0;
        sys_waitpid(-1, &mut result);
    }
}

extern "C" fn sigchld_handler(signal: i32) {
    if signal == SIGCHLD {
        let mut result: i32 = 0;
        sys_waitpid(-1, &mut result);
    }
}

fn init_shell() {
    mount("tmpfs", "/bin", "tmpfs", VfsFlags::empty(), None);
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
    sys_mkdir("/etc", 0);
    mount("dev", "/dev", "devtmpfs", VfsFlags::empty(), None);
    mount("proc", "/proc", "proc", VfsFlags::empty(), None);
    mount("tmpfs", "/tmp", "tmpfs", VfsFlags::empty(), None);
    let mut sa = SigAction::default();
    sa.sa_handler = sigchld_handler as usize;
    sigaction(SIGCHLD, Some(&sa), None);
    init_shell();
    run_cmd("mv /lib/dlopen_dso.so /dlopen_dso.so");
    run_cmd("mv /lib/glibc/* /lib");
    run_cmd("touch sort.src");

    run_cmd("echo root:x:0:0::/:/busybox sh > /etc/passwd");
    run_cmd("echo daemon:x:2:2::/:/bin/nologin >> /etc/passwd");
    run_cmd("echo nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin >> /etc/passwd");
    run_cmd("echo root:x:0: > /etc/group");
    run_cmd("echo daemon:x:2: >> /etc/group");
    run_cmd("echo nobody:x:65534: >> /etc/group");
    
    run_cmd("busybox sh");
}

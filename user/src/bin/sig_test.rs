#![no_std]
#![no_main]

extern crate alloc;
extern crate user_lib;

use user_lib::*;
use user_lib::syscall::{SIG_BLOCK, SigAction, sigaction, SIGCONT, SIGKILL, sigprocmask, SigSet, SIGSTOP, SIGUSR1, sys_close, sys_exit_group, sys_fork, sys_getpid, sys_kill, sys_pipe, sys_read, sys_sleep, sys_waitpid, sys_write};

fn func() {
    println!("func triggered");
}

fn user_sig_test_kill() {
    let mut new = SigAction::default();
    let mut old = SigAction::default();
    new.sa_handler = func as usize;

    if sigaction(SIGUSR1, Some(&new), Some(&mut old)) < 0 {
        panic!("Sigaction failed!");
    }
    if sys_kill(sys_getpid() as usize, SIGUSR1) < 0 {
        println!("Kill failed!");
        sys_exit_group(1);
    }
}

fn user_sig_test_multiprocsignals() {
    let pid = sys_fork();
    if pid == 0 {
        let mut new = SigAction::default();
        let mut old = SigAction::default();
        new.sa_handler = func as usize;
        if sigaction(SIGUSR1, Some(&new), Some(&mut old)) < 0 {
            panic!("Sigaction failed!");
        }
    } else {
        if sys_kill(pid as usize, SIGUSR1) < 0 {
            println!("Kill failed!");
            sys_exit_group(1);
        }
        let mut exit_code = 0;
        sys_waitpid(-1, &mut exit_code);
    }
}

fn user_sig_test_restore() {
    let mut new = SigAction::default();
    let mut old = SigAction::default();
    let mut old2 = SigAction::default();
    new.sa_handler = func as usize;

    if sigaction(SIGUSR1, Some(&new), Some(&mut old)) < 0 {
        panic!("Sigaction failed!");
    }

    if sigaction(SIGUSR1, Some(&old), Some(&mut old2)) < 0 {
        panic!("Sigaction failed!");
    }

    if old2.sa_handler != new.sa_handler {
        println!("Restore failed!");
        sys_exit_group(-1);
    }
}

fn kernel_sig_test_ignore() {
    let mut set = SigSet::empty();
    set |= SigSet::SIGUSR1;
    sigprocmask(SIG_BLOCK, Some(&set), None);
    if sys_kill(sys_getpid() as usize, SIGUSR1) < 0 {
        println!("kill faild\n");
        sys_exit_group(-1);
    }
}

fn kernel_sig_test_stop_cont() {
    let pid = sys_fork();
    if pid == 0 {
        sys_kill(sys_getpid() as usize, SIGSTOP);
        sys_sleep(1, 0);
        sys_exit_group(-1);
    } else {
        sys_sleep(2, 0);
        sys_kill(pid as usize, SIGCONT);
        let mut exit_code = 0;
        sys_waitpid(-1, &mut exit_code);
    }
}

fn kernel_sig_test_failignorekill() {
    let mut new = SigAction::default();
    let mut old = SigAction::default();
    new.sa_handler = func as usize;

    if sigaction(9, Some(&new), Some(&mut old)) >= 0 {
        panic!("Should not set sigaction to kill!");
    }

    if sigaction(9, Some(&new), None) >= 0 {
        panic!("Should not set sigaction to kill!");
    }

    if sigaction(9, None, Some(&mut old)) >= 0 {
        panic!("Should not set sigaction to kill!");
    }
}

fn final_sig_test() {
    let mut new = SigAction::default();
    let mut old = SigAction::default();
    new.sa_handler = func as usize;

    let mut pipe_fd = [0i32; 2];
    sys_pipe(&mut pipe_fd);

    let pid = sys_fork();
    if pid == 0 {
        sys_close(pipe_fd[0]);
        if sigaction(SIGUSR1, Some(&new), Some(&mut old)) < 0 {
            panic!("Sigaction failed!");
        }
        sys_write(pipe_fd[1], &[0u8]);
        sys_close(pipe_fd[1]);
        loop {}
    } else {
        sys_close(pipe_fd[1]);
        let mut buf = [0u8; 1];
        assert_eq!(sys_read(pipe_fd[0], &mut buf), 1);
        sys_close(pipe_fd[0]);
        if sys_kill(pid as usize, SIGUSR1) < 0 {
            println!("Kill failed!");
            sys_exit_group(-1);
        }
        sys_sleep(1, 0);
        sys_kill(pid as usize, SIGKILL);
    }
}

fn run(f: fn()) -> bool {
    let pid = sys_fork();
    if pid == 0 {
        f();
        sys_exit_group(0);
    } else {
        let mut exit_code: i32 = 0;
        sys_waitpid(-1, &mut exit_code);
        if exit_code != 0 {
            println!("FAILED!");
        } else {
            println!("OK!");
        }
        exit_code == 0
    }
}

#[no_mangle]
pub fn main() -> i32 {
    let tests: [(fn(), &str); 7] = [
        (user_sig_test_kill, "user_sig_test_kill"),
        (user_sig_test_multiprocsignals, "user_sig_test_multiprocsignals"),
        (user_sig_test_restore, "user_sig_test_restore"),
        (kernel_sig_test_ignore, "kernel_sig_test_ignore"),
        (kernel_sig_test_stop_cont, "kernel_sig_test_stop_cont"),
        (kernel_sig_test_failignorekill, "kernel_sig_test_failignorekill"),
        (final_sig_test, "final_sig_test"),
    ];
    let mut fail_num = 0;
    for test in tests {
        println!("Testing {}", test.1);
        if !run(test.0) {
            fail_num += 1;
        }
    }
    if fail_num == 0 {
        println!("ALL TESTS PASSED");
        0
    } else {
        println!("SOME TESTS FAILED");
        -1
    }
}

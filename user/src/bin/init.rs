#![no_std]
#![no_main]

extern crate user_lib;

use user_lib::println;
use user_lib::syscall::{OpenFlags, sys_open, sys_read, sys_yield};

#[no_mangle]
fn main() -> i32 {
    println!("Hello World from userspace!");
    sys_yield();
    
    let fd = sys_open("hello", OpenFlags::O_RDONLY);
    println!("Open hello file, fd = {}", fd);
    let mut buf = [0u8; 100];
    let len = sys_read(fd, &mut buf);
    if len < 0 {
        println!("Read file failed, ret = {}", len);
        return -1;
    } else {
        let str = core::str::from_utf8(&buf[..len as usize]).unwrap();
        println!("Read file content: {}", str);
    }
    0
}

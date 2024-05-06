### release 编译运行卡住

经调试发现问题发生在 `virtio-drivers` 库的 `queue.rs` 下，且行为非常诡异。

```rust
pub fn add_notify_wait_pop<'a>(
    &mut self,
    inputs: &'a [&'a [u8]],
    outputs: &'a mut [&'a mut [u8]],
    transport: &mut impl Transport,
) -> Result<u32> {
    let token = unsafe { self.add(inputs, outputs) }?;

>   if self.should_notify() {
        transport.notify(self.queue_idx);
    }

    while !self.can_pop() {
        spin_loop();
    }

    unsafe { self.pop_used(token, inputs, outputs) }
}
```

在上面代码打上断点后，一直运行都能正常进行下去，但一旦取消断点就会卡死。

经过 gdb 多次 attach 发现卡在 `while !self.can_pop()` 一句上，调试汇编发现是编译器出 bug 了，做了错误的优化导致死循环。更换 rust toolchain 版本到比赛指定版本后恢复正常。

### sys_wait 死锁

在多核环境下，偶尔会出现 `wait` 系统调用死锁的情况。打印日志如下：

```
[2.497s] [TRACE] [HART 1] [4, 4] | [WaitPidFuture] poll enter
[2.498s] [INFO ] [HART 0] [2, 2] | Thread 2 exited with code 0
[2.498s] [TRACE] [HART 1] [4, 4] | [WaitPidFuture] proc_inner locked
[2.498s] [INFO ] [HART 0] [2, 2] | Child 2 exited with code 0
```

死锁发生的先后顺序如下：

1. 进程 A 在 `WaitPidFuture` 进行 `poll` 时对 `A.inner` 加锁；
2. 进程 B 退出，调用 `on_thread_exit`，对 `B.inner` 加锁；
3. 进程 A 在 `poll` 中查询进程 B 状态时，尝试对 `B.inner` 加锁，等待；
4. 进程 B 在 `on_thread_exit` 中调用 `parent.on_child_exit`，尝试对 `A.inner` 加锁，等待；
5. 死锁。

解决方法：在 `ProcessMonitor` 上加一把全局锁，保证任何对进程树的操作都是原子的。

### sigreturn 的坑

`sigreturn` 调用时，需要将返回值设置为 trap context 的 `a0` 寄存器的值，因为 `sigreturn` 会将用户寄存器恢复到信号发生前的状态，而 syscall 统一处理后会将 `a0` 寄存器设置为返回值。

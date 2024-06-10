#import "../components/prelude.typ": *

= 中断处理模块

== 中断切换

为了方便起见，本文不对中断和异常做额外区分。RISC-V 架构有两种处理中断的方式：直接模式（Direct）和向量模式（Vectored）。在直接模式下，所有的中断都会跳转到`stvec`寄存器所设定的基地址进行处理；在向量模式下，不同的中断会根据基地址加中断号确定中断向量表中处理函数的位置。为了方便调试和实现统一的中断处理，MinotaurOS 使用直接模式处理中断。

中断发生时，RISC-V 处理器会将中断号保存到`scause`寄存器中，将中断发生时的指令地址保存到`sepc`寄存器中。之后，跳转到`stvec`寄存器设定的中断处理程序。对于内核态中断和用户态中断，MinotaurOS 使用不同的中断处理函数。

对于内核态中断，MinotaurOS 只需要保存 caller-saved 寄存器，然后调用 `trap_from_kernel` 函数。这是因为内核态中断不会改变内核的栈帧，在控制流角度就像插入了一次普通的函数调用，编译器会自动保存和恢复 callee-saved 寄存器。

对于用户态中断，MinotaurOS 会保存中断上下文（如#[@lst:中断上下文]所示），并恢复内核 callee-saved 寄存器和切换内核栈，然后执行`ret`。这是因为在编译器看来，当前内核栈状态是执行了 `trap_return` 函数，因此需要在返回前恢复 callee-saved 寄存器。此时，内核的控制流会回到协程调度器管理下的 `thread_loop` 函数中（见第 4.1.5 节）。然后，再执行对应的中断处理函数。处理完成后，MinotaurOS 会调用 `trap_return` 函数，恢复之前保存的中断上下文，然后执行`sret`将控制流返回到用户态。整体流程如#[@fig:用户态中断处理流程]所示。

#code-figure(
  ```rs
  pub struct TrapContext {
      /*  0 */ pub user_x: [usize; 32],
      /* 32 */ pub user_f: [usize; 32],
      /* 64 */ pub fcsr: usize,
      /* 65 */ pub sstatus: Sstatus,
      /* 66 */ pub sepc: usize,
      /* 67 */ pub kernel_tp: usize,
      /* 68 */ pub kernel_fp: usize,
      /* 69 */ pub kernel_sp: usize,
      /* 70 */ pub kernel_ra: usize,
      /* 71 */ pub kernel_s: [usize; 12],
  }
  ```,
  caption: [中断上下文],
  label-name: "中断上下文",
)

#figure(
  image("img/thread_loop.png"),
  caption: [用户态中断处理流程],
  supplement: [图],
)<用户态中断处理流程>

== 中断处理

=== 内核态中断处理

内核态中断分为三类，分别是时钟中断、外部中断和缺页异常。目前为止，MinotaurOS 并未实现内核态时钟中断，只实现了外部中断和缺页异常的处理，如#[@lst:内核态中断处理]所示。对于未识别的内核态中断，MinotaurOS 会直接触发崩溃。

#code-figure(
  ```rs
  fn trap_from_kernel() {
      let stval = stval::read();
      let sepc = sepc::read();
      let trap = scause::read().cause();
      debug!(
          "Trap {:?} from kernel at {:#x} for {:#x}",
          trap, sepc, stval,
      );
      match trap {
          | Trap::Exception(Exception::LoadFault)
          | Trap::Exception(Exception::LoadPageFault) => {
              handle_page_fault(VirtAddr(stval), ASPerms::R);
          }
          Trap::Exception(Exception::StoreFault)
          | Trap::Exception(Exception::StorePageFault) => {
              handle_page_fault(VirtAddr(stval), ASPerms::W);
          }
          Trap::Exception(Exception::InstructionFault)
          | Trap::Exception(Exception::InstructionPageFault) => {
              handle_page_fault(VirtAddr(sepc), ASPerms::X);
          }
          _ => {
              panic!("Fatal");
          }
      }
  }
  ```,
  caption: [内核态中断处理],
  label-name: "内核态中断处理",
)

#h(2em) 内核缺页异常通常发生在系统调用，内核向用户传入的地址写入数据时，触发写时复制机制。如果异常处理失败，则根据失败类型做不同处理。如果失败原因是内存不足，则终止当前进程；如果失败原因是非法访问，则发送`SIGSEGV`信号。处理函数如#[@lst:内核缺页异常处理]所示。

#code-figure(
  ```rs
  fn handle_page_fault(addr: VirtAddr, perform: ASPerms) {
      debug!("Kernel page fault at {:?} for {:?}", addr, perform);
      let thread = local_hart()
          .current_thread()
          .expect("Page fault while running kernel thread");
      if thread.process.inner.is_locked() == Some(local_hart().id) {
          warn!("Page fault while holding process lock");
      }
      let mut proc_inner = thread.process.inner.lock();
      match proc_inner.addr_space.handle_page_fault(addr, perform) {
          Ok(()) => debug!("Page fault resolved"),
          Err(Errno::ENOSPC) => {
              error!("Fatal page fault: Out of memory, kill process");
              current_process().terminate(-1);
          }
          Err(e) => {
              error!("Page fault failed: {:?}, send SIGSEGV", e);
              current_thread().signals.recv_signal(Signal::SIGSEGV);
          }
      }
  }
  ```,
  caption: [内核缺页异常处理],
  label-name: "内核缺页异常处理",
)

#h(2em) 对于外部中断，MinotaurOS 使用程序查询的方式来处理。外部中断的触发是由外部设备产生的，例如串口接收到数据、磁盘读写完成等。MinotaurOS 会在每次协程块执行完毕后，检查是否有外部中断发生。外部中断通过 PLIC 进行管理。PLIC 是 RISC-V 的外部中断控制器，用于管理外部中断的优先级和掩码。PLIC 的 MMIO 地址在设备树中定义。MinotaurOS 在解析完设备树后，初始化 PLIC。

=== 用户态中断处理

用户态中断分为三类，分别是系统调用、缺页异常和时钟中断。MinotaurOS 的用户态中断的处理程序如#[@lst:用户态中断处理]所示。对于系统调用，会先将中断上下文中的`sepc`加 4，使得调用完成后能够跳转到下一条指令。然后，调用`syscall`函数执行系统调用。系统调用完成后，将返回值写入`x10`寄存器。对于缺页异常，处理流程与内核态中断相同。对于时钟中断，会设置下一次触发时间，然后调用 `yield_now` 函数切换到下一个线程。对于未识别的用户态中断，MinotaurOS 不会触发崩溃，但会终止当前进程。

用户态中断处理程序是一个异步函数，其执行过程可能不会一次性完成。协程调度器会在等待异步任务完成或使用 `yield_now` 主动让出时间片时切换到其他协程执行。这样，MinotaurOS 能够实现多任务并发。

#code-figure(
  ```rs
  pub async fn trap_from_user() {
      set_kernel_trap_entry();
      let stval = stval::read();
      let sepc = sepc::read();
      let trap = scause::read().cause();
      trace!(
          "Trap {:?} from user at {:#x} for {:#x}",
          trap, sepc, stval,
      );
      match trap {
          Trap::Exception(Exception::UserEnvCall) => {
              let ctx = current_trap_ctx();
              // syscall 完成后，需要跳转到下一条指令
              ctx.sepc += 4;
              let result = syscall(
                  ctx.user_x[17],
                  ctx.user_x[10..=15],
              ).await;
              ctx.user_x[10] = result
                  .unwrap_or_else(|err| -(err as isize) as usize)
          }
          | Trap::Exception(Exception::LoadFault)
          | Trap::Exception(Exception::LoadPageFault) => {
              handle_page_fault(VirtAddr(stval), ASPerms::R);
          }
          Trap::Exception(Exception::StoreFault)
          | Trap::Exception(Exception::StorePageFault) => {
              handle_page_fault(VirtAddr(stval), ASPerms::W);
          }
          Trap::Exception(Exception::InstructionFault)
          | Trap::Exception(Exception::InstructionPageFault) => {
              handle_page_fault(VirtAddr(sepc), ASPerms::X);
          }
          Trap::Interrupt(Interrupt::SupervisorTimer) => {
              set_next_trigger();
              yield_now().await;
          }
          _ => {
              error!("Unhandled trap: {:?}", trap);
              current_thread().terminate(-1);
          }
      }
  }
  ```,
  caption: [用户态中断处理],
  label-name: "用户态中断处理",
)

#pagebreak()

#import "../components/prelude.typ": *

= 进程调度模块

== 内核异步模型：多核无栈协程

=== 传统有栈协程设计

传统的有栈协程设计中，每个用户线程都有自己的内核栈，线程的上下文切换需要保存和恢复栈指针。

以 rCore 为例，如#[@fig:rCore上下文切换]，上下文切换需要首先保存当前线程的 CPU 寄存器快照到当前线程的栈上，并根据目标线程栈上保存的内容来恢复相应的寄存器，最后切换栈指针。这样的设计在多核环境下存在一些问题。首先，每个线程的内核栈占用了大量内存，并且内核栈的大小很难进行动态调整，或是需要付出很大代价。其次，内核栈的保存和恢复需要大量的指令，影响了性能。最后，上下文切换需要考虑是否有互斥锁等资源未释放，一方面容易造成死锁，另一方面也不太符合 Rust RAII 的原则。

#figure(
  image("img/rCore换栈.png"),
  caption: [rCore 上下文切换],
  supplement: [图],
)<rCore上下文切换>

#pagebreak()

=== Rust异步模型：Async 和 Future

Rust 在语言层面提供了异步编程的支持，通过`Future`实现异步模型。`Future`是一个异步计算的抽象，它代表了一个异步计算的结果。`Future`在 Rust 中是惰性的，只有在被轮询（poll）时才会运行。`Future`通过实现`poll`方法来定义异步计算的行为。当`Future`被轮询时，它会返回一个`Poll`枚举，表示异步计算的状态。`Poll`枚举有两个成员：`Ready`表示异步计算已经完成，`Pending`表示异步计算尚未完成。`Future`通过`poll`方法的返回值来告诉调用者异步计算的状态。

Rust 的`async`和`await`关键字用于简化异步编程。`async`关键字用于定义异步函数，`await`关键字用于等待异步计算的结果。`async`函数返回一个`Future`对象，`await`关键字会将`Future`对象的执行挂起，直到异步计算完成。在实现上，`async`函数会被编译成一个状态机，通过`Future`对象的`poll`方法来实现异步计算。

Async 在 Rust 中的脱糖是零开销的，这意味着无需分配任何堆内存、也无需任何动态分发。状态机的构建使得切换异步程序不再需要换栈，而是变为函数调用和返回，本文会在后面详细介绍这点。因此，Rust 的异步模型非常适合用于实现高并发的异步编程，尤其是操作系统内核这种存在大量异步 I/O 的程序。

=== 异步运行时

由于 Rust 没有内置异步调用所必需的运行时，而大部分库都不支持裸机环境，且异步组件往往强依赖于运行时，因此 MinotaurOS 需要自行实现异步运行时及其组件，这包括 executor、异步锁和各种类型的`Future`。

MinotaurOS 的异步执行器基于 async_task 库实现。async_task 库提供了构建执行器的基本抽象，包括`Runnable`和`Task`。一个`Runnable`对象持有一个`Future`句柄，在运行时，会对`Future`轮询一次。然后，`Runnable`会消失，直到`Future`被唤醒才再次进入调度。一个`Task`对象用于获取`Future`的结果，通过`detatch`方法将任务移入后台执行。async_task 提供了`spawn`方法，传入`Future`和调度器，用于创建`Runnable`和`Task`对象。然后，通过`runnable.schedule`方法将`Runnable`加入调度序列。显而易见的优点是，I/O 阻塞的任务不会进入调度序列，避免了忙等待。

MinotaurOS 的调度方式为改进的轮转调度（如#[@lst:调度器实现]所示）。MinotaurOS 维护两个全局的无锁任务队列，一个是 FIFO 队列，一个是优先级队列，保存`Runnable`对象。调度开始时，CPU 核心首先尝试从优先级队列中取出一个`Runnable`运行，若优先级队列为空，则从 FIFO 队列中取出一个`Runnable`运行。在任务调度上，若`Runnable`在运行时被唤醒，通常是因为任务执行了 yield，让出时间片，此时将`Runnable`放入 FIFO 队列；若`Runnable`在其他任务运行时被唤醒，则通常是因为异步 I/O 完成的中断，此时将`Runnable`放入优先队列。

#code-figure(
  ```rs
  struct TaskQueue {
    fifo: SegQueue<Runnable>,
    prio: SegQueue<Runnable>,
  }

  pub fn spawn<F>(future: F) -> (Runnable, Task<F::Output>)
      where
          F: Future + Send + 'static,
          F::Output: Send + 'static,
  {
      let schedule = move |runnable: Runnable, info: ScheduleInfo| {
          if info.woken_while_running {
            TASK_QUEUE.push_fifo(runnable);
          } else {
            TASK_QUEUE.push_prio(runnable);
          }
      };
      async_task::spawn(future, WithInfo(schedule))
  }
  ```,
  caption: [调度器实现],
  label-name: "调度器实现",
)

=== 多核调度和无栈上下文切换

MinotaurOS 支持多个 CPU 核心的运行。每个核心可以平等地从调度序列中取出`Runnable`运行。为了实现这个目的，每个 CPU 核心都有一个 thread local 的数据结构`Hart`，包含核心 ID 和核心上下文。`tp`寄存器保存了当前核心的 ID，通过这个 ID 可以获取到当前核心的`Hart`。核心上下文`HartContext`保存了当前核心正在运行的用户任务，其中包含`Thread`对象的引用、页表和地址空间 token。上述数据结构定义如#[@lst:CPU核心数据结构]所示。

#code-figure(
  ```rs
  pub struct Hart {
      pub id: usize,
      pub ctx: HartContext,
      pub on_kintr: bool,
      pub on_page_test: bool,
      pub last_page_fault: SyscallResult,
      kintr_rec: usize,
      asid_manager: LateInit<ASIDManager>,
  }

  pub struct HartContext {
      pub user_task: Option<UserTask>,
      pub last_syscall: SyscallCode,
      pub timer_during_sys: usize,
  }

  pub struct UserTask {
      pub thread: Arc<Thread>,
      pub token: usize,
      pub root_pt: PageTable,
  }
  ```,
  caption: [CPU核心数据结构],
  label-name: "CPU核心数据结构",
)

#h(2em) 内核线程和用户线程使用统一的数据结构`HartTaskFuture`。该结构包含了核心上下文和具体的异步任务`Future`，其中对于内核线程，核心上下文中保存的`UserTask`为空。`HartTaskFuture`的 poll 过程会首先将当前核心的上下文与该结构中的上下文交换，然后 poll 保存的`Future`，执行异步任务的方法体（若就绪），最后再次交换上下文。上下文切换遵循下面的步骤：

（1）若当前任务是用户线程，则更新线程的调度换出时间；

（2）若目标任务是用户线程，则更新线程的调度换入时间；

（3）若目标任务是用户线程，且当前任务是内核线程或当前用户线程与目标用户线程不属于同一进程，则激活目标进程的地址空间；

（4）若目标任务是内核线程，且当前任务是用户线程，则激活内核地址空间；

（5）交换上下文数据。

与有栈协程相比，上下文切换不涉及到栈指针的切换和寄存器的保存与恢复（上下文数据交换只是两个指针的交换），因此开销更小。同时，由于异步任务的执行是在异步执行器的控制下，因此不需要考虑是否有互斥锁等资源未释放，也不需要考虑是否会因为线程过多而导致栈溢出等问题。这样的设计使得 MinotaurOS 能够充分利用多核特性，实现内核异步模型，如#[@fig:无栈协程调度]所示。

#figure(
  image("img/无栈协程调度.png"),
  caption: [无栈协程调度],
  supplement: [图],
)<无栈协程调度>

=== 线程循环

用户线程的`Future`是一个无限循环（如#[@lst:线程循环]所示）。线程在创建后，首先调用 `trap_return` 从内核态返回用户态。Trap 发生时（无论是系统调用或是时钟中断），寄存器信息会被保存到线程的 Trap 上下文中，然后从 `trap_return` 返回，接着执行异步函数 `trap_from_user`。如果 Trap 来自 yield 系统调用或是时钟中断，`YieldFuture.await` 会使线程挂起，并将线程放回调度序列尾部，接着完成上述的`HartTaskFuture`上下文切换后半部分。下次调度到该线程时，会从挂起的地方继续执行，从而再次通过 `trap_return` 返回用户态。

#code-figure(
  ```rs
  async fn thread_loop(thread: Arc<Thread>) {
    loop {
        trap_return();
        trap_from_user().await;
        check_signal();
        if thread.inner().exit_code.is_some() {
            break;
        }
    }
    thread.on_exit();
  }
  ```,
  caption: [线程循环],
  label-name: "线程循环",
)

== 进程控制块设计

在 Linux 源码中，进程和线程是使用统一的结构 `task_struct` 来表示的。这是由于历史原因，Linux 早期没有线程的概念，线程是通过进程来实现的。在 MinotaurOS 中，为了更加清晰地表示进程和线程的关系，以及减少互斥锁的使用，设计了两个不同的结构`Process`和`Thread`（如#[@lst:进程控制块]和#[@lst:线程控制块]所示）。`Process`结构表示一个进程，`Thread`结构表示一个线程。`Process`结构包含了进程的基本信息，包括父子进程、线程组、地址空间等。`Thread`结构包含了线程的基本信息，包括所属进程、线程上下文等。

#code-figure(
  ```rs
  pub struct Process {
      pub pid: Arc<TidTracker>,
      pub inner: IrqReMutex<ProcessInner>,
  }

  pub struct ProcessInner {
      pub parent: Weak<Process>,                // 父进程
      pub children: Vec<Weak<Process>>,         // 子进程
      pub pgid: Gid,                            // 进程组
      pub threads: BTreeMap<Tid, Weak<Thread>>, // 进程的线程组
      pub addr_space: AddressSpace,             // 地址空间
      pub mnt_ns: Arc<MountNamespace>,          // 挂载命名空间
      pub fd_table: FdTable,                    // 文件描述符表
      pub futex_queue: FutexQueue,              // 互斥锁队列
      pub timers: [ITimerVal; 3],               // 定时器
      pub cwd: String,                          // 工作目录
      pub exe: String,                          // 可执行文件路径
      pub exit_code: Option<i8>,                // 退出状态
  }
  ```,
  caption: [进程控制块],
  label-name: "进程控制块",
)

#code-figure(
  ```rs
  pub struct Thread {
      pub tid: Arc<TidTracker>,
      pub process: Arc<Process>,
      pub signals: SignalController,
      pub event_bus: EventBus,
      pub cpu_set: Mutex<CpuSet>,
      inner: SyncUnsafeCell<ThreadInner>,
  }

  pub struct ThreadInner {
      pub trap_ctx: TrapContext,
      pub tid_address: TidAddress,
      pub rusage: ResourceUsage,
      pub exit_code: Option<i8>,
  }
  ```,
  caption: [线程控制块],
  label-name: "线程控制块",
)

#h(2em) 进程控制块和线程控制块的可变部分使用了不同的可变容器。进程的可变部分需要使用互斥锁进行保护，这是因为可能存在多个 CPU 核心的线程同时访问同一个进程的可变部分。而线程的可变部分只会被当前线程访问，因此使用了`UnsafeCell`来避免互斥锁的开销。

进程控制块中对线程组的引用是弱引用，相反线程控制块中对进程的引用是强引用。这是因为线程才是真正运行在 CPU 核心上的实体，而进程是线程的集合。当所有线程都终止并 drop 后，进程会因为所有强引用都消失而被 drop，从而释放进程占用的资源并向父进程发送 SIGCHLD 信号。而之所以进程控制块中对父进程和子进程的引用都是弱引用，也是这个原因。进程和线程的关系如#[@fig:进程和线程关系]所示。

#figure(
  image("img/进程和线程关系.png", width: 80%),
  caption: [进程和线程关系],
  supplement: [图],
)<进程和线程关系>

#pagebreak()

#import "../components/prelude.typ": *

= 信号系统

== 事件总线

MinotaurOS 在每个线程中设置了一个事件总线`EventBus`，用于处理异步事件。事件总线是一个异步回调机制，保存了当前发生的异步事件和对应的唤醒器。事件的定义如#[@lst:Event定义]所示。

#code-figure(
  ```rs
  pub struct Event: u32 {
      const CHILD_EXIT = 1 << 0;
      const KILL_PROCESS = 1 << 2;
      const COMMON_SIGNAL = 1 << 3;
  }
  ```,
  caption: [Event 定义],
  label-name: "Event定义",
)

#h(2em) 事件总线提供等待事件、发送事件和注册回调的接口。等待事件会创建`WaitEventFuture`将当前协程挂起，直到事件发生。发送事件会触发所有先前注册的等待该事件的唤醒器，实现回调。

#code-figure(
  ```rs
  impl Future for WaitForEventFuture<'_> {
      type Output = Event;

      fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>)
          -> Poll<Self::Output> {
          let mut inner = self.event_bus.0.lock();
          let happened = inner.event.intersection(self.event);
          if happened != Event::empty() {
              inner.event.remove(happened);
              Poll::Ready(happened)
          } else {
              let mut event = self.event;
              inner.callbacks.retain(|(e, waker)| {
                  if waker.will_wake(cx.waker()) {
                      event |= *e;
                      false
                  } else {
                      true
                  }
              });
              inner.callbacks.push((event, cx.waker().clone()));
              Poll::Pending
          }
      }
  }
  ```,
  caption: [WaitEventFuture],
  label-name: "WaitEventFuture",
)

== 信号管理

信号是 UNIX 系统中的一种进程间通信机制，用于通知进程发生了某种事件。MinotaurOS 实现了类似 Linux 的信号系统，支持常见的信号，如`SIGKILL`、`SIGSTOP`、`SIGCHLD`等。MinotaurOS 使用如#[@lst:SignalController结构]所示的`SignalController`结构管理信号。信号管理器内部包含信号等待队列、信号屏蔽集和信号处理程序。每个线程都有一个独立的信号控制器。

#code-figure(
  ```rs
  pub struct SignalController(Mutex<SignalControllerInner>);

  struct SignalControllerInner {
      pending: SignalQueue,
      blocked: SigSet,
      handlers: [SignalHandler; SIG_MAX],
  }
  ```,
  caption: [SignalController 结构],
  label-name: "SignalController结构",
)

#h(2em) 线程结构提供了`recv_signal`方法来向发送一个信号。对于`SIGCHLD`信号和`SIGKILL`信号，会始终向事件总线发送对应事件。其余信号会根据屏蔽集决定是否向事件总线发送事件。之后，信号会被压入信号队列，等待线程处理。

#code-figure(
  ```rs
  pub fn recv_signal(&self, signal: Signal) {
      info!("Thread {} receive signal {:?}", self.tid.0, signal);
      match signal {
          Signal::SIGCHLD =>
              self.event_bus.recv_event(Event::CHILD_EXIT),
          Signal::SIGKILL =>
              self.event_bus.recv_event(Event::KILL_PROCESS),
          _ => {
              if !self.signals.get_mask().contains(signal.into()) {
                  self.event_bus.recv_event(Event::COMMON_SIGNAL);
              }
          }
      }
      self.signals.push(signal);
  }
  ```,
  caption: [recv_signal 方法],
)

#h(2em) 信号队列提供`poll`方法（如#[@lst:查询信号]所示），用于从信号队列中取出一个未被屏蔽的信号。用户定义的信号处理器中有一个值 `sa_mask`，用来设置信号处理器的屏蔽集。当信号处理器被调用时，内核需要将当前线程的屏蔽集暂时设置为 `sa_mask`，以防止信号处理器被信号中断。因此，每次查询信号时，需要将查询前的屏蔽集保存下来，以便在信号处理器执行完毕后恢复，同时将当前的屏蔽集替换为 `sa_mask`。

#code-figure(
  ```rs
  pub struct SignalPoll {
      pub signal: Signal,
      pub handler: SignalHandler,
      pub blocked_before: SigSet,
  }

  pub fn poll(&self) -> Option<SignalPoll> {
      let mut inner = self.0.lock();
      let mut popped = vec![];
      while let Some(signal) = inner.pending.pop() {
          if inner.blocked.contains(signal.into()) {
              debug!("Signal {:?} is blocked", signal);
              popped.push(signal);
              continue;
          }
          let blocked_before = inner.blocked;
          let handler = inner.handlers[signal as usize];
          if let SignalHandler::User(sig_action) = &handler {
              inner.blocked.insert(signal.into());
              inner.blocked |= sig_action.sa_mask;
          }

          inner.pending.extend(popped);
          let poll = SignalPoll { signal, handler, blocked_before };
          return Some(poll);
      }

      inner.pending.extend(popped);
      return None;
  }
  ```,
  caption: [查询信号],
  label-name: "查询信号",
)

#h(2em) 线程循环会在处理完用户态中断后，查询信号队列，如果有未被屏蔽的信号，则会调用默认信号处理器或将用户态的控制流切换到用户定义的信号处理器中（如果有）。

用户定义的信号处理器切换过程分为三步。首先，将当前线程的用户态寄存器保存到用户栈上；然后，将`epc`寄存器设置为信号处理器的入口地址，将返回地址设置为默认跳板或`sa_restorer`指定的地址，并将`a0`和`a1`分别设置为发生的信号和寄存器信息地址（在这里是用户栈），下次线程返回用户态时，会从用户定义的信号处理器开始执行。最后，信号处理器函数会返回到跳板或`sa_restorer`指定的地址，再通过`sigreturn`系统调用恢复信号发生前的用户态寄存器，切换回之前的控制流。

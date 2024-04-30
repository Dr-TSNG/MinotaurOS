use alloc::vec::Vec;
use core::future::Future;
use core::mem::size_of;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use bitflags::bitflags;
use log::debug;
use crate::arch::VirtAddr;
use crate::process::ffi::WaitOptions;
use crate::process::monitor::PROCESS_MONITOR;
use crate::process::Pid;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

bitflags! {
    #[derive(Default)]
    pub struct Event: u32 {
        const CHILD_EXIT = 1 << 0;
        const KILL_PROCESS = 1 << 2;
        const COMMON_SIGNAL = 1 << 3;
    }
}

#[derive(Default)]
pub struct EventBus(Mutex<EventBusInner>);

#[derive(Default)]
struct EventBusInner {
    event: Event,
    callbacks: Vec<(Event, Waker)>,
}

impl EventBus {
    pub async fn wait(&self, event: Event) -> Event {
        WaitForEventFuture::new(self, event).await
    }

    pub(super) fn recv_event(&self, event: Event) {
        debug!("Receive event {:?}", event);
        let mut inner = self.0.lock();
        inner.event |= event;
        let new_event = inner.event;
        inner.callbacks.retain(|(e, waker)| {
            if new_event.intersects(*e) {
                waker.wake_by_ref();
                false
            } else {
                true
            }
        });
    }

    fn register_callback(&self, mut event: Event, waker: Waker) {
        let mut inner = self.0.lock();
        inner.callbacks.retain(|(e, w)| {
            if w.will_wake(&waker) {
                event |= *e;
                false
            } else {
                true
            }
        });
        inner.callbacks.push((event, waker));
    }
}

struct WaitForEventFuture<'a> {
    event_bus: &'a EventBus,
    event: Event,
}

impl<'a> WaitForEventFuture<'a> {
    fn new(event_bus: &'a EventBus, event: Event) -> Self {
        WaitForEventFuture { event_bus, event }
    }
}

impl Future for WaitForEventFuture<'_> {
    type Output = Event;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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

pub struct WaitPidFuture {
    pid: Pid,
    options: WaitOptions,
    wstatus: usize,
}

impl WaitPidFuture {
    pub fn new(pid: Pid, options: WaitOptions, wstatus: usize) -> Self {
        WaitPidFuture { pid, options, wstatus }
    }
}

impl Future for WaitPidFuture {
    type Output = SyscallResult<Pid>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _monitor = PROCESS_MONITOR.lock();
        let mut proc_inner = current_process().inner.lock();
        if !proc_inner.children.iter()
            .any(|p| self.pid as isize == -1 || self.pid == p.pid.0) {
            return Poll::Ready(Err(Errno::ECHILD));
        }
        if let Some((idx, _)) = proc_inner.children.iter().enumerate()
            .find(|p| p.1.inner.lock().exit_code.is_some() && (self.pid as isize == -1 || self.pid == p.1.pid.0)) {
            let child = proc_inner.children.swap_remove(idx);
            if self.wstatus != 0 {
                let addr = proc_inner.addr_space.user_slice_w(VirtAddr(self.wstatus), size_of::<i32>())?;
                drop(proc_inner);
                let exit_status = (child.inner.lock().exit_code.unwrap() as i32) << 8;
                let exit_status: &[u8; size_of::<i32>()] = bytemuck::cast_ref(&exit_status);
                addr.copy_from_slice(exit_status);
            }
            Poll::Ready(Ok(child.pid.0))
        } else {
            if self.options.contains(WaitOptions::WNOHANG) {
                Poll::Ready(Ok(0))
            } else {
                current_thread().event_bus.register_callback(Event::CHILD_EXIT, cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

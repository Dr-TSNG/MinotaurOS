use core::{future::Future, task::Poll};

use crate::arch::VirtAddr;
use crate::fs::ffi::{PollEvents, PollFd};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use alloc::vec::Vec;
use core::mem::size_of;
use core::pin::Pin;
use core::task::Context;
use log::{debug, warn};
use pin_project::pin_project;

#[pin_project]
pub struct IOMultiplexFuture {
    fds: Vec<PollFd>,
    ufds: VirtAddr,
}

impl IOMultiplexFuture {
    pub fn new(fds: Vec<PollFd>, ufds: VirtAddr) -> Self {
        Self { fds, ufds }
    }
}

impl Future for IOMultiplexFuture {
    type Output = SyscallResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut cnt = 0;

        for poll_fd in this.fds.iter_mut() {
            let file = current_process()
                .inner
                .lock()
                .fd_table
                .get(poll_fd.fd)?
                .file;
            let events = PollEvents::from_bits(poll_fd.events).ok_or(Errno::EINVAL)?;
            poll_fd.revents = 0;
            if events.contains(PollEvents::POLLIN) {
                debug!("[IOMultiplexFuture] pollin fd {}", poll_fd.fd);
                match file.pollin(Some(cx.waker().clone())) {
                    Ok(res) if res => {
                        poll_fd.revents |= PollEvents::POLLIN.bits();
                        cnt += 1;
                    }
                    Err(e) => {
                        warn!("[IOMultiplexFuture] pollin error: {:?}", e);
                        poll_fd.revents |= PollEvents::POLLERR.bits();
                        cnt += 1;
                    }
                    _ => {}
                }
            }
            if events.contains(PollEvents::POLLOUT) {
                debug!("[IOMultiplexFuture] pollout fd {}", poll_fd.fd);
                match file.pollout(Some(cx.waker().clone())) {
                    Ok(res) if res => {
                        poll_fd.revents |= PollEvents::POLLOUT.bits();
                        cnt += 1;
                    }
                    Err(e) => {
                        warn!("[IOMultiplexFuture] pollout error: {:?}", e);
                        poll_fd.revents |= PollEvents::POLLERR.bits();
                        cnt += 1;
                    }
                    _ => {}
                }
            }
        }

        if cnt > 0 {
            debug!("[IOMultiplexFuture] event happens: {}", cnt);
            let slice = current_process()
                .inner
                .lock()
                .addr_space
                .user_slice_w(*this.ufds, size_of::<PollFd>() * this.fds.len())?;
            bytemuck::cast_slice_mut(slice).copy_from_slice(&this.fds);
            Poll::Ready(Ok(cnt))
        } else {
            debug!("[IOMultiplexFuture] no event happens");
            Poll::Pending
        }
    }
}

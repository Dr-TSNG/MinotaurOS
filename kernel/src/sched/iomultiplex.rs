use alloc::vec::Vec;
use core::{future::Future, task::Poll};
use core::mem::size_of;
use core::pin::Pin;
use core::task::Context;
use log::{debug, warn};
use pin_project::pin_project;
use zerocopy::FromBytes;
use crate::fs::ffi::{FdSet, PollEvents, PollFd};
use crate::mm::protect::user_slice_w;
use crate::processor::current_process;
use crate::result::SyscallResult;

#[pin_project]
pub struct IOMultiplexFuture {
    fds: Vec<PollFd>,
    ufds: IOFormat,
}

pub enum IOFormat {
    /// used for `ppoll`
    PollFds(usize),
    /// used for `pselect`
    FdSets(FdSetRWE),
}

pub struct FdSetRWE {
    pub rfds: Option<usize>,
    pub wfds: Option<usize>,
    pub efds: Option<usize>,
}

impl FdSetRWE {
    pub fn new(read_ptr: usize, write_ptr: usize, except_ptr: usize) -> Self {
        Self {
            rfds: match read_ptr {
                0 => None,
                _ => Some(read_ptr),
            },
            wfds: match write_ptr {
                0 => None,
                _ => Some(write_ptr),
            },
            efds: match except_ptr {
                0 => None,
                _ => Some(except_ptr),
            },
        }
    }

    pub fn update(&self, fds: &Vec<PollFd>) {
        for fd in fds.iter() {
            if let Some(rfds) = self.rfds {
                let fd_set = unsafe { &mut *(rfds as *mut FdSet) };
                if fd.revents.contains(PollEvents::POLLIN) {
                    fd_set.mark_fd(fd.fd as usize);
                    debug!(
                        "[update]: read fd set {:?}, fd set ptr {:#x}",
                        fd_set, rfds
                    );
                }
            }
            if let Some(wfds) = self.wfds {
                let fd_set = unsafe { &mut *(wfds as *mut FdSet) };
                if fd.revents.contains(PollEvents::POLLOUT) {
                    fd_set.mark_fd(fd.fd as usize);
                    debug!("[update]: write fd set {:?}", fd_set);
                }
            }
            if let Some(efds) = self.efds {
                let fd_set = unsafe { &mut *(efds as *mut FdSet) };
                if fd.revents.contains(PollEvents::POLLPRI) {
                    fd_set.mark_fd(fd.fd as usize);
                    debug!("[update]: except fd set {:?}", fd_set);
                }
            }
        }
    }
}

impl IOMultiplexFuture {
    pub fn new(fds: Vec<PollFd>, ufds: IOFormat) -> Self {
        Self { fds, ufds }
    }
}

impl Future for IOMultiplexFuture {
    type Output = SyscallResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut self.project();
        let mut cnt = 0;

        for poll_fd in this.fds.iter_mut() {
            let file = current_process().inner.lock().fd_table.get(poll_fd.fd)?.file;
            poll_fd.revents = PollEvents::empty();
            if poll_fd.events.contains(PollEvents::POLLIN) {
                debug!("[IOMultiplexFuture] pollin fd {}", poll_fd.fd);
                match file.pollin(Some(cx.waker().clone())) {
                    Ok(res) if res => {
                        poll_fd.revents |= PollEvents::POLLIN;
                        cnt += 1;
                    }
                    Err(e) => {
                        warn!("[IOMultiplexFuture] pollin error: {:?}", e);
                        poll_fd.revents |= PollEvents::POLLERR;
                        cnt += 1;
                    }
                    _ => {}
                }
            }
            if poll_fd.events.contains(PollEvents::POLLOUT) {
                debug!("[IOMultiplexFuture] pollout fd {}", poll_fd.fd);
                match file.pollout(Some(cx.waker().clone())) {
                    Ok(res) if res => {
                        poll_fd.revents |= PollEvents::POLLOUT;
                        cnt += 1;
                    }
                    Err(e) => {
                        warn!("[IOMultiplexFuture] pollout error: {:?}", e);
                        poll_fd.revents |= PollEvents::POLLERR;
                        cnt += 1;
                    }
                    _ => {}
                }
            }
        }

        if cnt > 0 {
            debug!("[IOMultiplexFuture] event happens: {}", cnt);
            match &mut this.ufds {
                IOFormat::PollFds(pollfd) => {
                    let slice = user_slice_w(*pollfd, size_of::<PollFd>() * this.fds.len())?;
                    PollFd::mut_slice_from(slice).unwrap().copy_from_slice(&this.fds);
                }
                IOFormat::FdSets(fdset) => {
                    fdset.update(&this.fds);
                }
            }
            Poll::Ready(Ok(cnt))
        } else {
            debug!("[IOMultiplexFuture] no event happens");
            Poll::Pending
        }
    }
}

use crate::fs::file::{File, FileMeta};
use crate::process::thread::event_bus::Event;
use crate::processor::current_thread;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use async_trait::async_trait;
use core::cmp::min;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use log::debug;

pub struct Pipe {
    metadata: FileMeta,
    is_reader: bool,
    other: LateInit<Weak<Pipe>>,
    inner: Arc<Mutex<PipeInner>>,
}

#[derive(Default)]
struct PipeInner {
    buf: VecDeque<u8>,
    transfer: usize,
    readers: VecDeque<Waker>,
    writers: VecDeque<Waker>,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if self.is_reader {
            while let Some(waker) = inner.writers.pop_front() {
                waker.wake();
            }
        } else {
            while let Some(waker) = inner.readers.pop_front() {
                waker.wake();
            }
        }
    }
}

impl Pipe {
    pub fn new() -> (Arc<Self>, Arc<Self>) {
        let inner = Arc::new(Mutex::new(PipeInner::default()));
        let reader = Arc::new(Pipe {
            metadata: FileMeta::new(None),
            is_reader: true,
            other: LateInit::new(),
            inner: inner.clone(),
        });
        let writer = Arc::new(Pipe {
            metadata: FileMeta::new(None),
            is_reader: false,
            other: LateInit::new(),
            inner,
        });
        reader.other.init(Arc::downgrade(&writer));
        writer.other.init(Arc::downgrade(&reader));
        (reader, writer)
    }
}

#[async_trait]
impl File for Pipe {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        if !self.is_reader {
            return Err(Errno::EBADF);
        }
        let fut = PipeReadFuture {
            pipe: self,
            buf,
            pos: 0,
        };
        current_thread()
            .event_bus
            .suspend_with(Event::KILL_THREAD, fut)
            .await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        if self.is_reader {
            return Err(Errno::EBADF);
        }
        let fut = PipeWriteFuture { pipe: self, buf };
        current_thread()
            .event_bus
            .suspend_with(Event::KILL_THREAD, fut)
            .await
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let mut inner = self.inner.lock();
        if !inner.buf.is_empty() || self.other.strong_count() == 0 {
            Ok(true)
        } else {
            if let Some(waker) = waker {
                inner.readers.push_back(waker);
            }
            Ok(false)
        }
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let mut inner = self.inner.lock();
        if self.other.strong_count() == 0 {
            Ok(true)
        } else {
            if let Some(waker) = waker {
                inner.writers.push_back(waker);
            }
            Ok(false)
        }
    }
}

struct PipeReadFuture<'a> {
    pipe: &'a Pipe,
    buf: &'a mut [u8],
    pos: usize,
}

struct PipeWriteFuture<'a> {
    pipe: &'a Pipe,
    buf: &'a [u8],
}

impl Future for PipeReadFuture<'_> {
    type Output = SyscallResult<isize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.pipe.inner.lock();
        let read = min(self.buf.len() - self.pos, inner.buf.len());
        debug!(
            "[pipe] read poll pos: {}, len: {}, buf.len: {}, read: {}",
            self.pos,
            self.buf.len(),
            inner.buf.len(),
            read,
        );
        if read > 0 {
            for (i, b) in inner.buf.drain(..read).enumerate() {
                self.buf[i] = b;
            }
            self.pos += read;
            inner.transfer += read;
            while let Some(waker) = inner.writers.pop_front() {
                waker.wake();
            }
            Poll::Ready(Ok(read as isize))
        } else {
            if self.pipe.other.strong_count() == 0 {
                return Poll::Ready(Ok(0));
            }
            inner.readers.push_back(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Future for PipeWriteFuture<'_> {
    type Output = SyscallResult<isize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.pipe.inner.lock();
        debug!(
            "[pipe] write poll len: {}, buf.len: {}",
            self.buf.len(),
            inner.buf.len(),
        );
        if self.pipe.other.strong_count() == 0 {
            return Poll::Ready(Err(Errno::EPIPE));
        }
        inner.buf.extend(self.buf);
        while let Some(waker) = inner.readers.pop_front() {
            waker.wake();
        }
        Poll::Ready(Ok(self.buf.len() as isize))
    }
}

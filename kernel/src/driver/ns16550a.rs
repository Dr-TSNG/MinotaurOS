use crate::arch::VirtAddr;
use crate::driver::{CharacterDevice, DeviceMeta, IrqDevice};
use crate::result::SyscallResult;
use alloc::boxed::Box;
use alloc::string::ToString;
use async_trait::async_trait;
use core::future::poll_fn;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Poll, Waker};
use futures::task::AtomicWaker;

pub struct UartDevice {
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    waker: AtomicWaker,
    buf: AtomicU8,
}

impl UartDevice {
    pub fn new(base_addr: VirtAddr) -> Self {
        Self {
            metadata: DeviceMeta::new("uart".to_string()),
            base_addr,
            waker: AtomicWaker::new(),
            buf: AtomicU8::new(0xff),
        }
    }

    fn rxdata_ptr(&self) -> *mut u8 {
        self.base_addr.as_ptr()
    }

    fn txdata_ptr(&self) -> *mut u8 {
        self.base_addr.as_ptr()
    }

    fn ie_ptr(&self) -> *mut u8 {
        (self.base_addr + 1).as_ptr()
    }

    fn fifo_ctrl_ptr(&self) -> *mut u8 {
        (self.base_addr + 2).as_ptr()
    }

    fn is_ptr(&self) -> *mut u8 {
        (self.base_addr + 2).as_ptr()
    }

    fn line_ctrl_ptr(&self) -> *mut u8 {
        (self.base_addr + 3).as_ptr()
    }

    fn line_status_ptr(&self) -> *mut u8 {
        (self.base_addr + 5).as_ptr()
    }
}

#[async_trait]
impl CharacterDevice for UartDevice {
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn init(&self) {
        unsafe {
            self.ie_ptr().write_volatile(0);
            self.fifo_ctrl_ptr().write_volatile((1 << 0) | (3 << 1));
            self.ie_ptr().write_volatile(1);
        }
    }

    fn has_data(&self) -> bool {
        self.buf.load(Ordering::Relaxed) != 0xff
            || unsafe { self.line_status_ptr().read_volatile() & 0x01 == 0x01 }
    }

    fn register_waker(&self, waker: Waker) {
        self.waker.register(&waker);
    }

    async fn getchar(&self) -> SyscallResult<u8> {
        poll_fn(|cx| unsafe {
            // Fast path
            let val = self.buf.swap(0xff, Ordering::Relaxed);
            if val != 0xff {
                return Poll::Ready(Ok(val));
            } else if self.line_status_ptr().read_volatile() & 0x01 == 0x01 {
                return Poll::Ready(Ok(self.rxdata_ptr().read_volatile()));
            }

            self.waker.register(cx.waker());

            // Slow path
            if self.buf.swap(0xff, Ordering::Relaxed) != 0xff {
                Poll::Ready(Ok(self.buf.load(Ordering::Relaxed)))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    async fn putchar(&self, ch: u8) -> SyscallResult<()> {
        unsafe {
            while (self.line_status_ptr().read_volatile() & (1 << 5)) == 0 {}
            self.txdata_ptr().write_volatile(ch);
        }
        Ok(())
    }
}

impl IrqDevice for UartDevice {
    fn handle_irq(&self) {
        let ch = unsafe { self.rxdata_ptr().read_volatile() };
        self.buf.store(ch, Ordering::Relaxed);
        self.waker.wake();
    }
}

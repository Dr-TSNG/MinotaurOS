use alloc::boxed::Box;
use alloc::string::ToString;
use core::cell::RefCell;
use core::future::poll_fn;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Poll, Waker};
use async_trait::async_trait;

use futures::task::AtomicWaker;
use jh71xx_hal::pac;
use jh71xx_hal::pac::Uart0;

use crate::arch::VirtAddr;
use crate::driver::{CharacterDevice, DeviceMeta, IrqDevice};
use crate::driver::ffi::DEV_CHAR_TTY;
use crate::fs::devfs::tty::DEFAULT_TTY;
use crate::result::SyscallResult;

const CTRL_C: u8 = 3;

pub struct Jh7710Uart{
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    uart: RefCell<jh71xx_hal::uart::Uart<Uart0>>,
    waker: AtomicWaker,
    buf: AtomicU8,
}

impl Jh7710Uart{
    pub fn new(base_addr: VirtAddr) -> Self{
        let dp = pac::Peripherals::take().unwrap();
        Self{
            metadata: DeviceMeta::new(DEV_CHAR_TTY,0,"uart".to_string()),
            base_addr,
            uart: RefCell::from(jh71xx_hal::uart::Uart::new(dp.uart0)),
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
impl CharacterDevice for Jh7710Uart{
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
        self.buf.load(Ordering::Relaxed) != 0xff ||
            unsafe { self.line_status_ptr().read_volatile() & 0x01 == 0x01 }
    }

    fn register_waker(&self, waker: Waker) {
        self.waker.register(&waker);
    }

    async fn getchar(&self) -> SyscallResult<u8> {
        /*
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
        }).await
         */
        let res = self.uart.read_byte();
        Ok(res.unwrap())
    }

    async fn putchar(&self, ch: u8) -> SyscallResult {
        /*
        unsafe {
            while (self.line_status_ptr().read_volatile() & (1 << 5)) == 0 {}
            self.txdata_ptr().write_volatile(ch);
        }
         */
        self.uart.write_byte(ch);
        Ok(())
    }
}


impl IrqDevice for Jh7710Uart{
    fn handle_irq(&self) {
        // let ch = unsafe { self.rxdata_ptr().read_volatile() };
        let ch = self.uart.read_byte().unwrap();
        if ch == crate::driver::jh7110::uart::CTRL_C {
            DEFAULT_TTY.handle_ctrl_c();
        }
        // self.buf.store(ch, Ordering::Relaxed);
        // self.waker.wake();
    }
}
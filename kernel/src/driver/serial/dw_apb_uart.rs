use alloc::boxed::Box;
use alloc::string::ToString;
use core::future::poll_fn;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Poll, Waker};
use async_trait::async_trait;
use futures::task::AtomicWaker;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_structs;
use tock_registers::registers::{ReadOnly, ReadWrite};
use crate::arch::VirtAddr;
use crate::driver::{CharacterDevice, DeviceMeta, IrqDevice};
use crate::driver::ffi::DEV_CHAR_TTY;
use crate::driver::serial::CHAR_TTY_COUNTER;
use crate::fs::devfs::tty::DEFAULT_TTY;
use crate::result::SyscallResult;

const CTRL_C: u8 = 3;

pub struct UartDevice {
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    waker: AtomicWaker,
    buf: AtomicU8,
}

register_structs! {
    Registers {
        /// Get or Put Register.
        (0x00 => rbr: ReadWrite<u32>),
        (0x04 => ier: ReadWrite<u32>),
        (0x08 => fcr: ReadWrite<u32>),
        (0x0c => lcr: ReadWrite<u32>),
        (0x10 => mcr: ReadWrite<u32>),
        (0x14 => lsr: ReadOnly<u32>),
        (0x18 => msr: ReadOnly<u32>),
        (0x1c => scr: ReadWrite<u32>),
        (0x20 => lpdll: ReadWrite<u32>),
        (0x24 => _reserved0),
        /// Uart Status Register.
        (0x7c => usr: ReadOnly<u32>),
        (0x80 => _reserved1),
        (0xc0 => dlf: ReadWrite<u32>),
        (0xc4 => @END),
    }
}

impl UartDevice {
    pub fn new(base_addr: VirtAddr) -> Self {
        let minor = CHAR_TTY_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            metadata: DeviceMeta::new(DEV_CHAR_TTY, minor, "uart".to_string()),
            base_addr,
            waker: AtomicWaker::new(),
            buf: AtomicU8::new(0xff),
        }
    }

    fn regs(&self) -> &Registers {
        unsafe { &*(self.base_addr.as_ptr().cast()) }
    }
}

#[async_trait]
impl CharacterDevice for UartDevice {
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn init(&self) {
        const UART_SRC_CLK: u32 = 25000000;
        const BST_UART_DLF_LEN: u32 = 6;
        const BAUDRATE: u32 = 115200;
        const DIVIDER: u32 = (UART_SRC_CLK << (BST_UART_DLF_LEN - 4)) / BAUDRATE;

        /* Disable interrupts and Enable FIFOs */
        self.regs().ier.set(0);
        self.regs().fcr.set(1);

        /* Disable flow ctrl */
        self.regs().mcr.set(0);

        /* Clear MCR_RTS */
        self.regs().mcr.set(self.regs().mcr.get() | (1 << 1));

        /* Enable access DLL & DLH. Set LCR_DLAB */
        self.regs().lcr.set(self.regs().lcr.get() | (1 << 7));

        /* Set baud rate. Set DLL, DLH, DLF */
        self.regs().rbr.set((DIVIDER >> BST_UART_DLF_LEN) & 0xff);
        self.regs().ier.set((DIVIDER >> (BST_UART_DLF_LEN + 8)) & 0xff);
        self.regs().dlf.set(DIVIDER & ((1 << BST_UART_DLF_LEN) - 1));

        /* Clear DLAB bit */
        self.regs().lcr.set(self.regs().lcr.get() & !(1 << 7));

        /* Set data length to 8 bit, 1 stop bit, no parity. Set LCR_WLS1 | LCR_WLS0 */
        self.regs().lcr.set(self.regs().lcr.get() | 0b11);

        self.regs().ier.set(1);
    }

    fn has_data(&self) -> bool {
        self.buf.load(Ordering::Relaxed) != 0xff || self.regs().lsr.get() & 0x01 == 0x01
    }

    fn register_waker(&self, waker: Waker) {
        self.waker.register(&waker);
    }

    async fn getchar(&self) -> SyscallResult<u8> {
        poll_fn(|cx| {
            // Fast path
            let val = self.buf.swap(0xff, Ordering::Relaxed);
            if val != 0xff {
                return Poll::Ready(Ok(val));
            } else if self.regs().lsr.get() & 0x01 == 0x01 {
                return Poll::Ready(Ok(self.regs().rbr.get() as u8));
            }

            self.waker.register(cx.waker());

            // Slow path
            if self.buf.swap(0xff, Ordering::Relaxed) != 0xff {
                Poll::Ready(Ok(self.buf.load(Ordering::Relaxed)))
            } else {
                Poll::Pending
            }
        }).await
    }

    async fn putchar(&self, ch: u8) -> SyscallResult {
        if ch == b'\n' {
            while self.regs().lsr.get() & (1 << 6) == 0 {}
            self.regs().rbr.set(b'\r' as u32);
        }
        while self.regs().lsr.get() & (1 << 6) == 0 {}
        self.regs().rbr.set(ch as u32);
        Ok(())
    }
}

impl IrqDevice for UartDevice {
    fn handle_irq(&self) {
        let ch = self.regs().rbr.get() as u8;
        if ch == CTRL_C {
            DEFAULT_TTY.handle_ctrl_c();
        }
        self.buf.store(ch, Ordering::Relaxed);
        self.waker.wake();
    }
}

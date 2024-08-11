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
use crate::sync::mutex::Mutex;

const CTRL_C: u8 = 3;
/*
register_structs! {
    DW8250Regs {
        /// Get or Put Register.
        (0x00 => rbr: ReadWrite<u32>),    // 用于读取接收到的数据。当UART接收到数据时，该寄存器会存储接收到的字节。通常情况下，这个寄存器会与发送寄存器共享同一个地址
        (0x04 => ier: ReadWrite<u32>),    // 用于控制UART中断的使能。通过设置该寄存器的位，可以启用或禁用特定类型的中断
        (0x08 => fcr: ReadWrite<u32>),    // 控制FIFO缓冲区的操作，例如清除发送和接收FIFO，设置FIFO触发级别等
        (0x0c => lcr: ReadWrite<u32>),    // 用于配置数据格式，包括数据位长度、停止位、校验位等。
        (0x10 => mcr: ReadWrite<u32>),    // 控制调制解调器的操作，比如RTS（请求发送）、DTR（数据终端就绪）等控制信号的状态。
        (0x14 => lsr: ReadOnly<u32>),     // 用于指示UART的当前状态，包括接收FIFO是否有数据可读、发送FIFO是否为空、接收缓冲区是否溢出、帧错误、校验错误等
        (0x18 => msr: ReadOnly<u32>),     // 提供调制解调器控制信号的当前状态，比如CTS（清除发送）、DSR（数据设置就绪）、RI（振铃指示）和DCD（数据载波检测）等信号的状态
        (0x1c => scr: ReadWrite<u32>),    // 通常作为临时存储数据的寄存器，没有特定的硬件功能，供用户自定义用途。
        (0x20 => lpdll: ReadWrite<u32>),  // 设置波特率分频器的低字节。与高字节寄存器一起控制UART的波特率
        (0x24 => _reserved0),
        /// Uart Status Register.
        (0x7c => usr: ReadOnly<u32>),     // 提供UART内部状态的摘要，比如发送和接收FIFO的状态、是否正在忙碌等。这是一个只读寄存器。
        (0x80 => _reserved1),
        (0xc0 => dlf: ReadWrite<u32>),    // 用于调整波特率的分数部分，以提高波特率的分辨率。这个寄存器结合lpdll和lpdhl（高位寄存器）可以精确控制UART的波特率。
        (0xc4 => @END),
    }
}
*/

pub struct Jh7710Uart{
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    // uart: Mutex<jh71xx_hal::uart::Uart<Uart0>>,
    dw8250: dw_apb_uart::DW8250,
    waker: AtomicWaker,
    buf: AtomicU8,
}

impl Jh7710Uart{
    pub fn new(base_addr: VirtAddr) -> Self{
        let dp = pac::Peripherals::take().unwrap();
        Self{
            metadata: DeviceMeta::new(DEV_CHAR_TTY,0,"uart".to_string()),
            base_addr,
            // uart: Mutex::new(jh71xx_hal::uart::Uart::new(dp.uart0)),
            dw8250: dw_apb_uart::DW8250::new(base_addr.0),
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

    /* fn is_ptr(&self) -> *mut u8 {
        (self.base_addr + 2).as_ptr()
    }*/

    fn line_ctrl_ptr(&self) -> *mut u8 {
        (self.base_addr + 3).as_ptr()
    }

    fn line_status_ptr(&self) -> *mut u8 {
        (self.base_addr + 5).as_ptr()
    }

    fn modem_ctrl_ptr(&self) -> *mut u8 {
        (self.base_addr + 4).as_ptr()
    }

    fn modem_status_ptr(&self) -> *mut u8 {
        (self.base_addr + 6).as_ptr()
    }

    fn scr_ptr(&self) -> *mut u8 {
        (self.base_addr + 7).as_ptr()
    }
}

#[async_trait]
impl CharacterDevice for Jh7710Uart{
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn init(&self) {
        unsafe {
            /*self.ie_ptr().write_volatile(0);
            self.fifo_ctrl_ptr().write_volatile((1 << 0) | (3 << 1));
            self.ie_ptr().write_volatile(1);*/
            self.dw8250.lock().init();
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

        /*
        let res = self.uart.lock().read_byte();
        Ok(res.unwrap())
         */
    }

    async fn putchar(&self, ch: u8) -> SyscallResult {
        unsafe {
            while (self.line_status_ptr().read_volatile() & (1 << 5)) == 0 {}
            self.txdata_ptr().write_volatile(ch);
        }
        Ok(())
        /*
       self.uart.lock().write_byte(ch).expect("TODO: panic message");
        */
    }
}


impl IrqDevice for Jh7710Uart{
    fn handle_irq(&self) {
        let ch = unsafe { self.rxdata_ptr().read_volatile() };
        // let ch = self.uart.lock().read_byte().unwrap();
        if ch == crate::driver::jh7110::uart::CTRL_C {
            DEFAULT_TTY.handle_ctrl_c();
        }
        self.buf.store(ch, Ordering::Relaxed);
        self.waker.wake();
    }
}
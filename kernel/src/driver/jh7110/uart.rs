use alloc::boxed::Box;

macro_rules! wait_for {
    ($cond:expr) => {{
        let mut timeout = 10000000;
        while !$cond && timeout > 0 {
            core::hint::spin_loop();
            timeout -= 1;
        }
    }};
}
use alloc::string::ToString;
use core::task::Waker;
use async_trait::async_trait;
pub(crate) use wait_for;

use bitflags::{bitflags,Flags};
use log::info;
use crate::driver::{CharacterDevice, DeviceMeta, IrqDevice};
use crate::driver::ffi::DEV_CHAR_TTY;
use crate::result::SyscallResult;

const RHR: usize = 0; // receive holding register (for input bytes)
const THR: usize = 0; // transmit holding register (for output bytes)
const IER: usize = 1; // interrupt enable register
const FCR: usize = 2; // FIFO control register
const ISR: usize = 2; // interrupt status register
const LCR: usize = 3; // line control register
const MCR: usize = 4; // modem control register
const LSR: usize = 5; // line status register

bitflags! {
    /// Interrupt enable flags
    struct IntEnFlags: u8 {
        const RECEIVED = 1;
        const SENT = 1 << 1;
        const ERRORED = 1 << 2;
        const STATUS_CHANGE = 1 << 3;
        // 4 to 7 are unused
    }
}

bitflags! {
    /// Line status flags
    struct LineStsFlags: u8 {
        const INPUT_FULL = 1;
        // 1 to 4 unknown
        const OUTPUT_EMPTY = 1 << 5;
        // 6 and 7 unknown
    }
}

pub struct Uart {
    metadata: DeviceMeta,
    /// UART MMIO base address
    mmio_base_vaddr: usize,
    clock_frequency: u32,
    baud_rate: u32,
    reg_io_width: usize,
    reg_shift: usize,
    is_snps: bool,
}

impl Uart{
    pub unsafe fn new(
        mmio_base_vaddr: usize,
        clock_frequency: usize,
        baud_rate: usize,
        reg_io_width: usize,
        reg_shift: usize,
        is_snps: bool,
    ) -> Self {
        Self {
            metadata: DeviceMeta::new(DEV_CHAR_TTY,0,"uart".to_string()),
            mmio_base_vaddr,
            clock_frequency: clock_frequency as u32,
            baud_rate: baud_rate as u32,
            reg_io_width,
            reg_shift,
            is_snps,
        }
    }

    pub fn _init(&self) {
        match self.reg_io_width {
            1 => self.init_u8(),
            4 => self.init_u32(),
            _ => {
                panic!("Unsupported UART register width");
            }
        }
    }

    pub fn send(&self, c: u8) {
        match self.reg_io_width {
            1 => self.send_u8(c),
            4 => self.send_u32(c),
            _ => {
                panic!("Unsupported UART register width");
            }
        }
    }

    fn init_u8(&self) {
        let reg = self.mmio_base_vaddr as *mut u8;

        unsafe {
            // Disable Interrupt
            reg.byte_add(IER << self.reg_shift).write_volatile(0x00);

            // Enable DLAB
            // Enter a setting mode to set baud rate
            reg.byte_add(LCR << self.reg_shift).write_volatile(0x80);

            // Set baud rate
            let divisor = self.clock_frequency / (16 * self.baud_rate);
            reg.byte_add(0 << self.reg_shift)
                .write_volatile(divisor as u8);
            reg.byte_add(1 << self.reg_shift)
                .write_volatile((divisor >> 8) as u8);

            // Disable DLAB and set data word length to 8 bits
            // Leave setting mode
            reg.byte_add(LCR << self.reg_shift).write_volatile(0x03);

            // // Enable FIFO
            // reg.byte_add(FCR << self.reg_shift).write_volatile(0x01);

            // No modem control
            reg.byte_add(MCR << self.reg_shift).write_volatile(0x00);

            // Enable interrupts now
            reg.byte_add(IER << self.reg_shift).write_volatile(0x01);
        }
    }

    fn init_u32(&self) {
        let reg = self.mmio_base_vaddr as *mut u32;

        unsafe {
            // Disable Interrupt
            reg.byte_add(IER << self.reg_shift).write_volatile(0x00);

            // Enable DLAB
            // Enter a setting mode to set baud rate
            reg.byte_add(LCR << self.reg_shift).write_volatile(0x80);

            // Set baud rate
            let divisor = self.clock_frequency / (16 * self.baud_rate);
            reg.byte_add(0 << self.reg_shift)
                .write_volatile(divisor & 0xff);
            reg.byte_add(1 << self.reg_shift)
                .write_volatile((divisor >> 8) & 0xff);

            // Disable DLAB and set data word length to 8 bits
            // Leave setting mode
            reg.byte_add(LCR << self.reg_shift).write_volatile(0x03);

            // Enable FIFO
            reg.byte_add(FCR << self.reg_shift).write_volatile(0x01);

            // No modem control
            reg.byte_add(MCR << self.reg_shift).write_volatile(0x00);

            // Enable interrupts now
            reg.byte_add(IER << self.reg_shift).write_volatile(0x01);
        }
        info!("IER register: 0b{:b}", unsafe {
            reg.byte_add(IER << self.reg_shift).read_volatile()
        });
    }

    fn line_sts_u8(&self) -> LineStsFlags {
        let ptr = self.mmio_base_vaddr as *mut u8;
        unsafe {
            LineStsFlags::from_bits_truncate(ptr.byte_add(LSR << self.reg_shift).read_volatile())
        }
    }

    fn line_sts_u32(&self) -> LineStsFlags {
        let ptr = self.mmio_base_vaddr as *mut u32;
        unsafe {
            LineStsFlags::from_bits_truncate(
                ptr.byte_add(LSR << self.reg_shift).read_volatile() as u8
            )
        }
    }

    /// Sends a byte on the serial port.
    pub fn send_u8(&self, c: u8) {
        let ptr = self.mmio_base_vaddr as *mut u8;
        unsafe {
            match c {
                8 | 0x7F => {
                    // For backspace and delete char
                    wait_for!(self.line_sts_u8().contains(LineStsFlags::OUTPUT_EMPTY));
                    ptr.byte_add(THR << self.reg_shift).write_volatile(8);
                    wait_for!(self.line_sts_u8().contains(LineStsFlags::OUTPUT_EMPTY));
                    ptr.byte_add(THR << self.reg_shift).write_volatile(b' ');
                    wait_for!(self.line_sts_u8().contains(LineStsFlags::OUTPUT_EMPTY));
                    ptr.byte_add(THR << self.reg_shift).write_volatile(8);
                }
                _ => {
                    // Wait until previous data is flushed
                    wait_for!(self.line_sts_u8().contains(LineStsFlags::OUTPUT_EMPTY));
                    // Write data
                    ptr.byte_add(THR << self.reg_shift).write_volatile(c);
                }
            }
        }
    }

    pub fn send_u32(&self, c: u8) {
        let ptr = self.mmio_base_vaddr as *mut u32;
        unsafe {
            match c {
                8 | 0x7F => {
                    wait_for!(self.line_sts_u32().contains(LineStsFlags::OUTPUT_EMPTY));
                    ptr.byte_add(THR << self.reg_shift).write_volatile(8);
                    wait_for!(self.line_sts_u32().contains(LineStsFlags::OUTPUT_EMPTY));
                    ptr.byte_add(THR << self.reg_shift)
                        .write_volatile(b' '.into());
                    wait_for!(self.line_sts_u32().contains(LineStsFlags::OUTPUT_EMPTY));
                    ptr.byte_add(THR << self.reg_shift).write_volatile(8);
                }
                _ => {
                    // Wait until previous data is flushed
                    wait_for!(self.line_sts_u32().contains(LineStsFlags::OUTPUT_EMPTY));
                    // Write data
                    ptr.byte_add(THR << self.reg_shift).write_volatile(c.into());
                }
            }
        }
    }

    /// Receives a byte on the serial port.
    pub fn receive(&self) -> u8 {
        let ptr = self.mmio_base_vaddr as *mut u32;
        unsafe {
            wait_for!(self.line_sts_u8().contains(LineStsFlags::INPUT_FULL));
            if self.is_snps {
                // Clear busy detect interrupt
                // by reading UART status register. see Synopsys documentation
                // hard-coded register offset
                ptr.byte_add(31 << self.reg_shift).read_volatile();
            }
            ptr.add(0).read_volatile() as u8
        }
    }

}

#[async_trait]
impl CharacterDevice for Uart{
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn init(&self) {
        self._init();
    }

    fn has_data(&self) -> bool {
        match self.reg_io_width {
            1 => self.line_sts_u8().contains(LineStsFlags::INPUT_FULL),
            4 => self.line_sts_u32().contains(LineStsFlags::INPUT_FULL),
            _ => unimplemented!(),
        }
    }

    fn register_waker(&self, waker: Waker) {
        todo!()
    }

    async fn getchar(&self) -> SyscallResult<u8> {
        Ok(self.receive())
    }

    async fn putchar(&self, ch: u8) -> SyscallResult {
        Ok(self.send(ch))
    }
}

impl IrqDevice for Uart{
    fn handle_irq(&self) {
        todo!()
    }
}

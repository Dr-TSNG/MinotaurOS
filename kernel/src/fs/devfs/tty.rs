use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::task::Waker;
use async_trait::async_trait;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::driver::CharacterDevice;
use crate::fs::file::{File, FileMeta};
use crate::mm::protect::{user_transmute_r, user_transmute_w};
use crate::process::monitor::MONITORS;
use crate::process::Pid;
use crate::result::{Errno, SyscallResult};
use crate::signal::ffi::Signal;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

pub static DEFAULT_TTY: LateInit<Arc<TtyFile>> = LateInit::new();

pub struct TtyFile {
    metadata: FileMeta,
    device: Weak<dyn CharacterDevice>,
    inner: Mutex<TtyFileInner>,
}

struct TtyFileInner {
    win_size: WinSize,
    termios: Termios,
    fg_pgid: Pid,
}

impl Default for TtyFileInner {
    fn default() -> Self {
        Self {
            win_size: Default::default(),
            termios: Default::default(),
            fg_pgid: 1,
        }
    }
}

impl TtyFile {
    pub fn new(metadata: FileMeta, device: Arc<dyn CharacterDevice>) -> Arc<Self> {
        Arc::new(Self {
            metadata,
            device: Arc::downgrade(&device),
            inner: Default::default(),
        })
    }

    pub fn handle_ctrl_c(&self) {
        let monitors = MONITORS.lock();
        if let Some(group) = monitors.group.get_group(self.inner.lock().fg_pgid) {
            for pid in group.iter() {
                if let Some(process) = monitors.process.get(*pid).upgrade() {
                    let proc_inner = process.inner.lock();
                    for thread in proc_inner.threads.values() {
                        if let Some(thread) = thread.upgrade() {
                            thread.recv_signal(Signal::SIGINT);
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl File for TtyFile {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let mut device = self.device.upgrade().ok_or(Errno::ENODEV)?;
        for i in 0..buf.len() {
            buf[i] = device.getchar().await?;
        }
        Ok(buf.len() as isize)
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let mut device = self.device.upgrade().ok_or(Errno::ENODEV)?;
        for ch in buf.iter() {
            device.putchar(*ch).await?;
            // sbi_rt::legacy::console_putchar(*ch as usize);
        }
        Ok(buf.len() as isize)
    }

    async fn ioctl(&self, request: usize, value: usize, _: usize, _: usize, _: usize) -> SyscallResult<i32> {
        let request = TermiosType::try_from(request).map_err(|_| Errno::EINVAL)?;
        match request {
            TermiosType::TCGETS => {
                let value = user_transmute_w(value)?.ok_or(Errno::EINVAL)?;
                *value = self.inner.lock().termios.clone();
            }
            TermiosType::TCSETS | TermiosType::TCSETSW | TermiosType::TCSETSF => {
                let value = user_transmute_r::<Termios>(value)?.ok_or(Errno::EINVAL)?;
                self.inner.lock().termios = value.clone();
            }
            TermiosType::TIOCGPGRP => {
                let value = user_transmute_w(value)?.ok_or(Errno::EINVAL)?;
                *value = self.inner.lock().fg_pgid;
            }
            TermiosType::TIOCSPGRP => {
                let value = user_transmute_r(value)?.ok_or(Errno::EINVAL)?;
                self.inner.lock().fg_pgid = *value;
            }
            TermiosType::TIOCGWINSZ => {
                let value = user_transmute_w(value)?.ok_or(Errno::EINVAL)?;
                *value = self.inner.lock().win_size;
            }
            TermiosType::TIOCSWINSZ => {
                let value = user_transmute_r(value)?.ok_or(Errno::EINVAL)?;
                self.inner.lock().win_size = *value;
            }
            TermiosType::RTC_RD_TIME => {}
        }
        Ok(0)
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let device = self.device.upgrade().ok_or(Errno::ENODEV)?;
        if device.has_data() {
            Ok(true)
        } else {
            if let Some(waker) = waker {
                device.register_waker(waker);
            }
            Ok(false)
        }
    }
}

#[repr(usize)]
#[derive(TryFromPrimitive)]
#[allow(non_camel_case_types)]
enum TermiosType {
    /// Get the current serial port settings.
    TCGETS = 0x5401,
    /// Set the current serial port settings.
    TCSETS = 0x5402,
    /// Allow the output buffer to drain,
    /// and set the current serial port settings.
    TCSETSW = 0x5403,
    /// Allow the output buffer to drain, discard pending input,
    /// and set the current serial port settings.
    TCSETSF = 0x5404,
    /// Get the process group ID of the foreground process group on this terminal.
    TIOCGPGRP = 0x540F,
    /// Set the foreground process group ID of this terminal.
    TIOCSPGRP = 0x5410,
    /// Get the window size of the terminal.
    TIOCGWINSZ = 0x5413,
    /// Set the window size of the terminal.
    TIOCSWINSZ = 0x5414,
    /// Read time
    RTC_RD_TIME = 0x80247009,
}

#[repr(C)]
#[derive(Copy, Clone, AsBytes, FromZeroes, FromBytes)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    xpixel: u16,
    ypixel: u16,
}

impl Default for WinSize {
    fn default() -> Self {
        Self {
            ws_row: 60,
            ws_col: 120,
            xpixel: 0,
            ypixel: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, AsBytes, FromZeroes, FromBytes)]
struct Termios {
    /// Input mode
    pub iflag: u32,
    /// Ouput mode
    pub oflag: u32,
    /// Control mode
    pub cflag: u32,
    /// Local mode
    pub lflag: u32,
    /// line discipline
    pub line: u8,
    /// control characters
    pub cc: [u8; 19],
}

impl Default for Termios {
    fn default() -> Self {
        Self {
            // BRKINT | ICRNL | IMAXBEL | IUTF8
            iflag: 0x6102,
            // OPOST | ONLCR
            oflag: 0x5,
            cflag: 0,
            lflag: 0,
            line: 0,
            cc: [
                3,   // VINTR Ctrl-C
                28,  // VQUIT
                127, // VERASE
                21,  // VKILL
                4,   // VEOF Ctrl-D
                0,   // VTIME
                1,   // VMIN
                0,   // VSWTC
                17,  // VSTART
                19,  // VSTOP
                26,  // VSUSP Ctrl-Z
                255, // VEOL
                18,  // VREPAINT
                15,  // VDISCARD
                23,  // VWERASE
                22,  // VLNEXT
                255, // VEOL2
                0, 0,
            ],
        }
    }
}

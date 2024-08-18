use alloc::boxed::Box;
use alloc::string::ToString;
use core::ops::Add;
use core::sync::atomic::Ordering;
use core::time::Duration;
use async_trait::async_trait;
use visionfive2_sd::{SDIo, SleepOps, Vf2SdDriver};
use crate::arch::VirtAddr;
use crate::driver::{BlockDevice, DeviceMeta};
use crate::driver::ffi::DEV_BLOCK_MMC;
use crate::driver::mmc::MMC_COUNTER;
use crate::result::SyscallResult;
use crate::sched::time::cpu_time;
use crate::sync::mutex::Mutex;

const BLOCK_SIZE: usize = 512;

struct SdIoImpl(VirtAddr);

impl SDIo for SdIoImpl {
    fn read_data_at(&self, offset: usize) -> u64 {
        unsafe {
            self.0.add(offset).as_ptr().cast::<u64>().read_volatile()
        }
    }

    fn read_reg_at(&self, offset: usize) -> u32 {
        unsafe {
            self.0.add(offset).as_ptr().cast::<u32>().read_volatile()
        }
    }

    fn write_data_at(&mut self, offset: usize, val: u64) {
        unsafe {
            self.0.add(offset).as_ptr().cast::<u64>().write_volatile(val)
        }
    }

    fn write_reg_at(&mut self, offset: usize, val: u32) {
        unsafe {
            self.0.add(offset).as_ptr().cast::<u32>().write_volatile(val)
        }
    }
}

struct SleepOpsImpl;

impl SleepOps for SleepOpsImpl {
    fn sleep_ms(ms: usize) {
        let start = cpu_time();
        while cpu_time() - start < Duration::from_micros(ms as u64 * 1000) {
            core::hint::spin_loop();
        }
    }

    fn sleep_ms_until(ms: usize, mut f: impl FnMut() -> bool) {
        let start = cpu_time();
        while cpu_time() - start < Duration::from_micros(ms as u64 * 1000) {
            if f() {
                return;
            }
            core::hint::spin_loop();
        }
    }
}

pub struct MmcDevice {
    metadata: DeviceMeta,
    driver: Mutex<Vf2SdDriver<SdIoImpl, SleepOpsImpl>>,
}

impl MmcDevice {
    pub fn new(base_addr: VirtAddr) -> Self {
        let minor = MMC_COUNTER.fetch_add(1, Ordering::Relaxed) * 8;
        let sdio = SdIoImpl(base_addr);
        let driver = Vf2SdDriver::new(sdio);
        Self {
            metadata: DeviceMeta::new(DEV_BLOCK_MMC, minor, "uart".to_string()),
            driver: Mutex::new(driver),
        }
    }
}

#[async_trait]
impl BlockDevice for MmcDevice {
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn sector_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn dev_size(&self) -> usize {
        4 * 1024 * 1024 * 1024 // 4 GB
    }

    fn init(&self) {
        self.driver.lock().init();
    }

    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> SyscallResult {
        self.driver.lock().read_block(block_id, buf);
        Ok(())
    }

    async fn write_block(&self, block_id: usize, buf: &[u8]) -> SyscallResult {
        self.driver.lock().write_block(block_id, buf);
        Ok(())
    }
}

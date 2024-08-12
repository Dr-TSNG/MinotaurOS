use crate::arch::VirtAddr;

pub struct SPI{
    base_addr: VirtAddr,
}

impl SPI{
    pub fn init(&mut self){
        todo!()
    }
    pub fn new(base_addr: VirtAddr) -> Self {
        Self { base_addr }
    }
    fn cr0_ptr(&self) -> *mut u32 {
        self.base_addr.0 as *mut u32
    }
    fn cr1_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x4).0 as *mut u32
    }
    fn dr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x8).0 as *mut u32
    }
    fn sr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0xc).0 as *mut u32
    }
    fn cpsr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x10).0 as *mut u32
    }
    fn im_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x14).0 as *mut u32
    }
    fn ris_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x18).0 as *mut u32
    }
    fn mis_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x1c).0 as *mut u32
    }
    fn icr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x20).0 as *mut u32
    }
    fn dmactl_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x24).0 as *mut u32
    }
    fn cc_ptr(&self) -> *mut u32 {
        (self.base_addr + 0xfc8).0 as *mut u32
    }


}


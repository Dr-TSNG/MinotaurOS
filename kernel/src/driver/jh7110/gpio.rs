use crate::arch::VirtAddr;

pub struct Gpio{
    base_addr: VirtAddr,
}

impl Gpio{
    pub fn new(base_addr: VirtAddr) -> Self{
        Self{
            base_addr
        }
    }

    fn get_gpio_reg(&self , offset: usize) -> *mut u32{
        (self.base_addr + offset).0 as *mut u32
    }

    pub fn set_val(&self, val: u8) {
        todo!()
    }
}
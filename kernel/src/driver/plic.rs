use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use log::warn;
use crate::arch::VirtAddr;
use crate::driver::IrqDevice;
use crate::sync::mutex::IrqMutex;

pub struct PLIC {
    base_addr: VirtAddr,
    devices: IrqMutex<BTreeMap<usize, Weak<dyn IrqDevice>>>,
}

impl PLIC {
    pub(super) fn new(base_addr: VirtAddr) -> Self {
        Self { base_addr, devices: IrqMutex::default() }
    }

    pub(super) fn init(&self, harts: usize) {
        for context_id in 1..harts + 1 {
            self.set_threshold(context_id, 0);
            for intr_id in self.devices.lock().keys() {
                self.enable_intr(context_id, *intr_id);
                self.set_priority(*intr_id, 1);
            }
        }
    }

    pub(super) fn register_device(&self, intr_id: usize, device: Arc<dyn IrqDevice>) {
        self.devices.lock().insert(intr_id, Arc::downgrade(&device));
    }

    pub fn handle_irq(&self, hart_id: usize) {
        let context_id = hart_id + 1;
        let intr = self.claim(context_id);
        if intr != 0 {
            if let Some(device) = self.devices.lock().get(&intr) {
                match device.upgrade() {
                    Some(device) => device.handle_irq(),
                    None => warn!("[plic] Device {} is already dropped", intr),
                }
            }
            self.complete(context_id, intr);
        }
    }

    fn get_priority(&self, intr_id: usize) -> u32 {
        unsafe { self.priority_ptr(intr_id).read_volatile() & 7 }
    }

    fn set_priority(&self, intr_id: usize, priority: u32) {
        unsafe { self.priority_ptr(intr_id).write_volatile(priority & 7); }
    }

    fn is_pending(&self, intr_id: usize) -> bool {
        unsafe { ((self.pending_ptr(intr_id).read_volatile() >> (intr_id % 32)) & 1) == 1 }
    }

    fn is_intr_enabled(&self, context_id: usize, intr_id: usize) -> bool {
        unsafe { ((self.intr_enable_ptr(context_id, intr_id).read_volatile() >> (intr_id % 32)) & 1) == 1 }
    }

    fn enable_intr(&self, context_id: usize, intr_id: usize) {
        let ptr = self.intr_enable_ptr(context_id, intr_id);
        unsafe {
            let r = ptr.read_volatile();
            ptr.write_volatile(r | (1 << (intr_id % 32)));
        }
    }

    fn disable_intr(&self, context_id: usize, intr_id: usize) {
        let ptr = self.intr_enable_ptr(context_id, intr_id);
        unsafe {
            let r = ptr.read_volatile();
            ptr.write_volatile(r & !(1 << (intr_id % 32)));
        }
    }

    fn get_threshold(&self, context_id: usize) -> u32 {
        unsafe { self.threshold_ptr(context_id).read_volatile() & 7 }
    }

    fn set_threshold(&self, context_id: usize, threshold: u32) {
        unsafe { self.threshold_ptr(context_id).write_volatile(threshold & 7); }
    }

    fn claim(&self, context_id: usize) -> usize {
        unsafe { self.claim_complete_ptr(context_id).read_volatile() as usize }
    }

    fn complete(&self, context_id: usize, intr_id: usize) {
        unsafe { self.claim_complete_ptr(context_id).write_volatile(intr_id as u32); }
    }
}

impl PLIC {
    fn priority_ptr(&self, intr_id: usize) -> *mut u32 {
        (self.base_addr + intr_id * 4).as_ptr().cast()
    }

    fn pending_ptr(&self, intr_id: usize) -> *mut u32 {
        (self.base_addr + 0x1000 + 4 * (intr_id / 32)).as_ptr().cast()
    }

    fn intr_enable_ptr(&self, context_id: usize, intr_id: usize) -> *mut u32 {
        (self.base_addr + 0x2000 + 0x80 * context_id + 4 * (intr_id / 32)).as_ptr().cast()
    }

    fn threshold_ptr(&self, context_id: usize) -> *mut u32 {
        (self.base_addr + 0x200000 + 0x1000 * context_id).as_ptr().cast()
    }

    fn claim_complete_ptr(&self, context_id: usize) -> *mut u32 {
        (self.base_addr + 0x200000 + 0x1000 * context_id + 4).as_ptr().cast()
    }
}

use alloc::sync::Arc;
use core::cmp::min;
use core::num::NonZeroUsize;
use lru::LruCache;
use riscv::register::satp;
use crate::config::MAX_ASID;

pub type ASID = u16;

pub struct ASIDManager(LruCache<ASID, Arc<ASID>>);

impl ASIDManager {
    pub fn new() -> Self {
        let asid_cap = unsafe {
            let satp = satp::read();
            satp::set(satp.mode(), ASID::MAX as usize, satp.ppn());
            let cap = satp::read().asid();
            satp::set(satp.mode(), satp.asid(), satp.ppn());
            min(cap, MAX_ASID)
        };
        let mut cache = LruCache::new(NonZeroUsize::new(asid_cap).unwrap());
        for i in 0..asid_cap as ASID {
            cache.put(i, Arc::new(i));
        }
        Self(cache)
    }

    pub fn alloc(&mut self) -> Arc<ASID> {
        let asid = self.0.pop_lru().unwrap().0;
        let tracker = Arc::new(asid);
        self.0.push(asid, tracker.clone());
        tracker
    }
}

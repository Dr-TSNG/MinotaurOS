use core::cmp::min;
use core::num::NonZeroUsize;
use lru::LruCache;
use riscv::register::satp;
use crate::config::MAX_ASID;
use crate::println;

pub type ASID = u16;

pub struct ASIDManager {
    cache: LruCache<usize, ASID>,
    allocated: usize,
}

impl ASIDManager {
    pub fn new() -> Option<Self> {
        println!("asid manager new begin ... ");
        let asid_cap = unsafe {
            let satp = satp::read();
            satp::set(satp.mode(), ASID::MAX as usize, satp.ppn());
            let cap = satp::read().asid();
            satp::set(satp.mode(), satp.asid(), satp.ppn());
            min(cap, MAX_ASID)
        };
        println!("asid manager new end ");
        println!("asid_cap is {}",asid_cap);
        let temp = NonZeroUsize::new(asid_cap);
        if temp.is_none(){
            return None;
        }
        println!("temp new end ");
        let cache = LruCache::new(temp.unwrap());
        println!("cache new end ");
        Some(Self {
            cache,
            allocated: 0,
        })
    }

    pub fn get(&mut self, token: usize) -> Option<ASID> {
        self.cache.get(&token).copied()
    }

    pub fn assign(&mut self, token: usize) -> ASID {
        if self.allocated < self.cache.cap().get() {
            let asid = self.allocated as ASID;
            self.allocated += 1;
            self.cache.put(token, asid);
            asid
        } else {
            let recycled = self.cache.pop_lru().unwrap().1;
            self.cache.put(token, recycled);
            recycled
        }
    }
}

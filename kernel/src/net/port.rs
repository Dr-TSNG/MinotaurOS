use bitvec_rs::BitVec;
use rand::RngCore;
use crate::driver::random::KRNG;

pub struct PortContext {
    physical: BitVec,
}

impl PortContext {
    pub fn new() -> Self {
        let mut physical = BitVec::with_capacity(65536);
        physical.resize(65536, false);
        Self { physical }
    }

    pub fn alloc_physical(&mut self) -> u16 {
        let mut rng = KRNG.lock();
        loop {
            let port = rng.next_u32() as u16;
            if !self.physical[port as usize] {
                self.physical.set(port as usize, true);
                return port;
            }
        }
    }

    #[allow(unused)]
    pub fn recycle_physical(&mut self, port: u16) {
        self.physical.set(port as usize, false);
    }
}

use alloc::sync::Weak;
use alloc::vec;
use alloc::vec::Vec;
use bitvec_rs::BitVec;
use rand::RngCore;
use smoltcp::iface::SocketHandle;
use crate::driver::random::KRNG;
use crate::net::Socket;

pub struct PortContext {
    physical: BitVec,
}

struct UDPMultiplex {
    handle: SocketHandle,
    sockets: Vec<Weak<dyn Socket>>,
}

impl UDPMultiplex {
    fn new(create_fn: impl Fn() -> SocketHandle) -> Self {
        let handle = create_fn();
        Self {
            handle,
            sockets: vec![],
        }
    }
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

    pub fn recycle_physical(&mut self, port: u16) {
        self.physical.set(port as usize, false);
    }
}

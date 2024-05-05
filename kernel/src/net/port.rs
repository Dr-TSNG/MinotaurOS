use alloc::collections::VecDeque;
use lazy_static::lazy_static;
use log::info;
use spin::Mutex;

const MAX_PORT: u16 = 0xFFFF;

lazy_static! {
    pub static ref PORT_ALLOCATOR: PortAllocator = PortAllocator::new(MAX_PORT);
}

pub struct PortAllocator {
    pub ports: Mutex<VecDeque<u16>>,
}

impl PortAllocator {
    pub fn new(max_port: u16) -> Self {
        let mut decode: VecDeque<u16> = VecDeque::with_capacity(max_port as usize);
        for i in 0..decode.len() {
            decode[i] = i as u16;
        }
        PortAllocator {
            ports: Mutex::new(decode),
        }
    }

    pub fn take(&self) -> Option<u16> {
        if self.is_empty() {
            info!("Net Port is Not Enough!!");
            None
        } else {
            Some(self.ports.lock().pop_front().unwrap())
        }
    }

    pub fn is_empty(&self) -> bool {
        return self.ports.lock().is_empty();
    }

    pub fn recycle(&self, port: u16) {
        self.ports.lock().push_back(port);
    }
}

use rand::RngCore;
use crate::driver::random::KRNG;

pub fn random_port() -> u16 {
    loop {
        let port = KRNG.lock().next_u32() as u16;
        if port == 0 {
            continue;
        }
        return port;
    }
}

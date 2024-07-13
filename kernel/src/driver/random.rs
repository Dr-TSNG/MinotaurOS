use lazy_static::lazy_static;
use rand::rngs::SmallRng;
use rand::{Error, RngCore, SeedableRng};
use crate::arch;
use crate::sync::mutex::Mutex;

lazy_static! {
    pub static ref KRNG: Mutex<SmallRng> = Mutex::new(SmallRng::from_rng(SeedGenerator(19260817)).unwrap());
}

struct SeedGenerator(usize);

impl RngCore for SeedGenerator {
    fn next_u32(&mut self) -> u32 {
        let next = self.0 + arch::hardware_ts();
        self.0 = next;
        next as u32
    }

    fn next_u64(&mut self) -> u64 {
        let next = self.0 + arch::hardware_ts();
        self.0 = next;
        next as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            let number = self.next_u32();
            dest[i] = ((number >> 16) ^ (number << 8) ^ number) as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

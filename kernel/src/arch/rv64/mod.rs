pub mod sbi;
pub mod address;
pub mod pte;

pub fn hardware_ts() -> usize {
    riscv::register::time::read()
}

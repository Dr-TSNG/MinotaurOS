#[cfg(debug_assertions)]
static INIT: &[u8] = include_bytes!("../../target/riscv64gc-unknown-none-elf/debug/init");

#[cfg(not(debug_assertions))]
static INIT: &[u8] = include_bytes!("../../target/riscv64imac-unknown-none-elf/release/init");

pub fn builtin_app(name: &str) -> Option<&'static [u8]> {
    match name {
        "init" => Some(INIT),
        _ => None,
    }
}

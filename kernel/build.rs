fn main() {
    let board = std::env::var("BOARD").unwrap();
    println!("cargo:rustc-link-arg=-Tkernel/src/board/{}.ld", board);
}

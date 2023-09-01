#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::ops::Add;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};
use riscv::register::satp;
use common::config::*;
use common::arch::{PAGE_BITS, PageTableEntry, PhysAddr, PhysPageNum, PTE_SLOTS, PTEFlags, shutdown, VirtPageNum};
use common::{include_bytes_aligned, println};

const PADDR_LV0_SLOT: usize = VirtPageNum(KERNEL_PADDR_BASE >> PAGE_BITS).index(0);
const VADDR_LV0_SLOT: usize = VirtPageNum(KERNEL_VADDR_BASE >> PAGE_BITS).index(0);

global_asm!(include_str!("boot.asm"));

#[repr(align(2097152))] // 2 MiB
struct AlignLv1;

#[repr(align(4096))]
struct PageTable([PageTableEntry; PTE_SLOTS]);

impl PageTable {
    pub const fn new() -> Self {
        Self([PageTableEntry::empty(); PTE_SLOTS])
    }
}

static KERNEL_BIN: &[u8] = include_bytes_aligned!(AlignLv1, env!("KERNEL_BIN"));

static mut LV0_PT: PageTable = PageTable::new();

static mut BOOT_LV1_PT: PageTable = PageTable::new();

static mut KERNEL_LV1_PT: PageTable = PageTable::new();

static BOOT_COMPLETE: AtomicBool = AtomicBool::new(false);

fn init_lv1_pt(pt: &mut PageTable, mut ppn: PhysPageNum) {
    for pte in pt.0.iter_mut() {
        *pte = PageTableEntry::new(
            ppn,
            PTEFlags::R | PTEFlags::W | PTEFlags::X | PTEFlags::V | PTEFlags::A | PTEFlags::D,
        );
        ppn = ppn.add(0x200);
    }
}

#[cfg(feature = "board_qemu")]
fn hart_id() -> usize {
    let hart;
    unsafe {
        asm! {
        "mv {}, tp",
        out(reg) hart
        };
    }
    hart
}

#[cfg(feature = "board_fu740")]
pub fn hart_id() -> usize {
    0
}

unsafe fn setup_pt() {
    println!("[bootloader] Minotaur Bootloader: Hello RISC-V!");

    for pte in LV0_PT.0.iter_mut() {
        *pte = PageTableEntry::empty();
    }


    let boot_lv0_pte = PageTableEntry::new(
        PhysPageNum::from(PhysAddr(BOOT_LV1_PT.0.as_ptr() as usize)),
        PTEFlags::V,
    );
    LV0_PT.0[PADDR_LV0_SLOT] = boot_lv0_pte;
    let boot_lv1_pt_start_ppn = PhysPageNum::from(PhysAddr(KERNEL_PADDR_BASE)).lv0_mask();
    init_lv1_pt(&mut BOOT_LV1_PT, boot_lv1_pt_start_ppn);

    let kernel_lv0_pte = PageTableEntry::new(
        PhysPageNum::from(PhysAddr(KERNEL_LV1_PT.0.as_ptr() as usize)),
        PTEFlags::V,
    );
    LV0_PT.0[VADDR_LV0_SLOT] = kernel_lv0_pte;
    let kernel_lv1_pt_start_ppn = PhysPageNum::from(PhysAddr(KERNEL_BIN.as_ptr() as usize));
    init_lv1_pt(&mut KERNEL_LV1_PT, kernel_lv1_pt_start_ppn);

    let lv0_pt_ppn = PhysPageNum::from(PhysAddr(LV0_PT.0.as_ptr() as usize));
    let boot_lv1_pt_ppn = PhysPageNum::from(PhysAddr(BOOT_LV1_PT.0.as_ptr() as usize));
    let kernel_lv1_pt_ppn = PhysPageNum::from(PhysAddr(KERNEL_LV1_PT.0.as_ptr() as usize));
    println!(
        "[bootloader] lv0_pt_ppn: {} boot_lv1_pt_ppn: {} kernel_lv1_pt_ppn: {}",
        lv0_pt_ppn, boot_lv1_pt_ppn, kernel_lv1_pt_ppn
    );
    println!(
        "[bootloader] PADDR_LV0_SLOT: {} VADDR_LV0_SLOT: {}",
        PADDR_LV0_SLOT, VADDR_LV0_SLOT
    );
    println!(
        "[bootloader] boot_lv1_pt_start_ppn: {} kernel_lv1_pt_start_ppn: {}",
        boot_lv1_pt_start_ppn, kernel_lv1_pt_start_ppn
    );
}

#[no_mangle]
pub unsafe fn boot_entry() -> ! {
    let hart = hart_id();
    if hart == 0 {
        setup_pt();
        BOOT_COMPLETE.store(true, Ordering::Release);
    } else {
        while !BOOT_COMPLETE.load(Ordering::Acquire) {}
    }

    let lv0_pt_ppn = PhysPageNum::from(PhysAddr(LV0_PT.0.as_ptr() as usize));
    satp::set(satp::Mode::Sv39, 0, lv0_pt_ppn.0);
    asm!("sfence.vma");

    let kernel_entry: fn(usize) -> ! = core::mem::transmute(KERNEL_VADDR_BASE);
    kernel_entry(hart)
}

#[no_mangle]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("----------------------------------");
    println!("     !!!   KERNEL PANIC   !!!     ");
    println!("----------------------------------");
    println!("{}", info);
    shutdown()
}

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::{format, vec};
use alloc::vec::Vec;
use async_trait::async_trait;
use fdt_rs::base::DevTree;
use fdt_rs::error::DevTreeError;
use fdt_rs::index::{DevTreeIndex, DevTreeIndexNode};
use fdt_rs::prelude::PropReader;
use log::info;
use crate::arch::{PhysAddr, VirtAddr};
use crate::config::{KERNEL_ADDR_OFFSET, KERNEL_MMIO_BASE};
use crate::driver::tty::{DEFAULT_TTY, SBITtyDevice};
use crate::driver::virtio::VirtIODevice;
use crate::fs::file::{CharacterFile, FileMeta};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::IdAllocator;
use crate::result::SyscallResult;
use crate::sync::mutex::{Mutex, RwLock};
use crate::sync::once::LateInit;

pub mod tty;
pub mod virtio;

pub static BOARD_INFO: LateInit<BoardInfo> = LateInit::new();
pub static GLOBAL_MAPPINGS: LateInit<Vec<GlobalMapping>> = LateInit::new();
pub static DEVICES: RwLock<BTreeMap<usize, Device>> = RwLock::new(BTreeMap::new());

static DEV_ID_ALLOCATOR: Mutex<IdAllocator> = Mutex::new(IdAllocator::new(1));

#[derive(Debug)]
pub struct BoardInfo {
    pub smp: usize,
    pub freq: usize,
}

pub struct GlobalMapping {
    pub name: String,
    pub phys_start: PhysAddr,
    pub virt_start: VirtAddr,
    pub size: usize,
    pub perms: ASPerms,
}

impl GlobalMapping {
    const fn new(
        name: String,
        phys_start: PhysAddr,
        virt_start: VirtAddr,
        size: usize,
        perms: ASPerms,
    ) -> Self {
        Self { name, phys_start, virt_start, size, perms }
    }

    pub const fn phys_end(&self) -> PhysAddr {
        PhysAddr(self.phys_start.0 + self.size)
    }

    pub const fn virt_end(&self) -> VirtAddr {
        VirtAddr(self.virt_start.0 + self.size)
    }
}

#[derive(Clone)]
pub enum Device {
    Block(Arc<dyn BlockDevice>),
    Character(Arc<dyn CharacterDevice>),
}

impl Device {
    pub fn metadata(&self) -> &DeviceMeta {
        match self {
            Device::Block(dev) => dev.metadata(),
            Device::Character(dev) => dev.metadata(),
        }
    }
}

pub struct DeviceMeta {
    pub dev_id: usize,
    pub dev_name: String,
}

impl DeviceMeta {
    fn new(dev_name: String) -> DeviceMeta {
        Self {
            dev_id: DEV_ID_ALLOCATOR.lock().alloc(),
            dev_name,
        }
    }
}

/// 块设备
#[async_trait]
pub trait BlockDevice: Send + Sync {
    /// 设备元数据
    fn metadata(&self) -> &DeviceMeta;

    /// 从块设备读取数据
    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> SyscallResult;

    /// 向块设备写入数据
    async fn write_block(&self, block_id: usize, buf: &[u8]) -> SyscallResult;
}

#[async_trait]
pub trait CharacterDevice: Send + Sync {
    /// 设备元数据
    fn metadata(&self) -> &DeviceMeta;

    /// 从字符设备读取数据
    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize>;

    /// 向字符设备写入数据
    async fn write(&self, buf: &[u8]) -> SyscallResult<isize>;
}

pub fn init_dtb(dtb_paddr: usize) {
    parse_dev_tree(dtb_paddr).unwrap()
}

pub fn init_driver() -> SyscallResult<()> {
    for map in GLOBAL_MAPPINGS.iter() {
        if map.name == "[virtio]" {
            let dev = VirtIODevice::new(map.virt_start)?;
            DEVICES.write().insert(dev.metadata().dev_id, Device::Block(dev));
            info!("Initialize virtio device at {:?}", map.virt_start);
        }
    }

    let sbi_tty = Arc::new(SBITtyDevice::new());
    let sbi_tty: Arc<dyn CharacterDevice> = sbi_tty.clone();
    let tty_file = CharacterFile::new(FileMeta::new(None), Arc::downgrade(&sbi_tty));
    DEFAULT_TTY.init(tty_file);
    DEVICES.write().insert(sbi_tty.metadata().dev_id, Device::Character(sbi_tty));
    info!("Initialize SBI tty device");

    Ok(())
}

pub fn total_memory() -> usize {
    GLOBAL_MAPPINGS.iter().fold(0, |acc, map| {
        if map.name.starts_with("[memory") { acc + map.size } else { acc }
    })
}

fn parse_dev_tree(dtb_paddr: usize) -> Result<(), DevTreeError> {
    let mut board_info = BoardInfo {
        smp: 0,
        freq: 0,
    };
    let mut g_mappings = Vec::new();
    let mut mmio_offset = 0;
    let fdt = unsafe {
        DevTree::from_raw_pointer(dtb_paddr as *const u8)?
    };
    let layout = DevTreeIndex::get_layout(&fdt)?;
    let mut buf = vec![0u8; layout.size() + layout.align()];
    let dti = DevTreeIndex::new(fdt, &mut buf)?;
    let root = dti.root();
    let addr_cells = root
        .props()
        .find(|prop| prop.name() == Ok("#address-cells"))
        .unwrap()
        .u32(0)? as usize;
    let size_cells = root
        .props()
        .find(|prop| prop.name() == Ok("#size-cells"))
        .unwrap()
        .u32(0)? as usize;
    for node in root.children() {
        let name = node.name()?;
        if name == "cpus" {
            let freq = node
                .props()
                .find(|prop| prop.name() == Ok("timebase-frequency"))
                .unwrap()
                .propbuf();
            board_info.freq = match freq.len() {
                4 => u32::from_be_bytes(freq.try_into().unwrap()) as usize,
                8 => u64::from_be_bytes(freq.try_into().unwrap()) as usize,
                _ => return Err(DevTreeError::ParseError),
            };
            for cpu in node.children() {
                if cpu.name()?.starts_with("cpu@") {
                    board_info.smp += 1;
                }
            }
        } else if name.starts_with("memory") {
            let reg = parse_reg(&node, addr_cells, size_cells);
            for (phys_start, size) in reg {
                let mapping = GlobalMapping::new(
                    format!("[memory@{:x}]", phys_start),
                    PhysAddr(phys_start),
                    VirtAddr(KERNEL_ADDR_OFFSET + phys_start),
                    size,
                    ASPerms::R | ASPerms::W | ASPerms::X,
                );
                g_mappings.push(mapping);
            }
        } else if name == "soc" {
            for node in node.children() {
                let name = node.name()?;
                if name == "virtio_mmio@10001000" {
                    let reg = parse_reg(&node, addr_cells, size_cells);
                    let mapping = GlobalMapping::new(
                        "[virtio]".to_string(),
                        PhysAddr(reg[0].0),
                        KERNEL_MMIO_BASE + mmio_offset,
                        reg[0].1,
                        ASPerms::R | ASPerms::W,
                    );
                    mmio_offset += reg[0].1;
                    g_mappings.push(mapping);
                }
            }
        }
    }

    BOARD_INFO.init(board_info);
    GLOBAL_MAPPINGS.init(g_mappings);
    Ok(())
}

fn parse_reg(node: &DevTreeIndexNode, addr_cells: usize, size_cells: usize) -> Vec<(usize, usize)> {
    let reg = node
        .props()
        .find(|prop| prop.name() == Ok("reg"))
        .unwrap()
        .propbuf();
    let reg: &[u32] = bytemuck::cast_slice(reg); // Big endian
    let mut res = Vec::new();
    for pos in (0..reg.len()).step_by(addr_cells + size_cells) {
        let phys_start = reg[pos..pos + addr_cells]
            .iter()
            .fold(0, |acc, &x| acc << 32 | x.swap_bytes() as usize);
        let size = reg[pos + addr_cells..pos + addr_cells + size_cells]
            .iter()
            .fold(0, |acc, &x| acc << 32 | x.swap_bytes() as usize);
        res.push((phys_start, size));
    }
    res
}

use log::error;
use crate::fs::fat32::bpb::BPBOffset;
use crate::result::{Errno, SyscallResult};

#[derive(Debug)]
pub struct FAT32Meta {
    /// 活跃 FAT 表的扇区偏移
    pub fat_offset: usize,
    /// 数据区的扇区偏移
    pub data_offset: usize,
    /// 每扇区的字节数
    pub bytes_per_sector: usize,
    /// 每簇的扇区数
    pub sectors_per_cluster: usize,
    /// 每簇的字节数
    pub bytes_per_cluster: usize,
    /// 根目录所在的簇号
    pub root_cluster: usize,
    /// 最大簇号
    pub max_cluster: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FATEnt {
    /// 空簇
    EMPTY,
    /// 坏簇
    BAD,
    /// 簇链结束
    EOF,
    /// 下个簇号
    NEXT(u32),
}

impl From<u32> for FATEnt {
    fn from(value: u32) -> Self {
        match value {
            0 => FATEnt::EMPTY,
            0x0FFFFFF7 => FATEnt::BAD,
            0x0FFFFFF8.. => FATEnt::EOF,
            _ => FATEnt::NEXT(value),
        }
    }
}

impl From<FATEnt> for u32 {
    fn from(value: FATEnt) -> Self {
        match value {
            FATEnt::EMPTY => 0,
            FATEnt::BAD => 0x0FFFFFF7,
            FATEnt::EOF => 0x0FFFFFF8,
            FATEnt::NEXT(v) => v,
        }
    }
}

impl FAT32Meta {
    pub fn new(boot_sector: &[u8]) -> SyscallResult<Self> {
        let ext_flags = BPBOffset::extend_flags(boot_sector);
        if ext_flags & (1 << 7) != 0 {
            error!("Mirrored FAT is not supported");
            return Err(Errno::EINVAL);
        }
        let active = ext_flags & 0b1111;
        let reserved = BPBOffset::reserved_sectors(boot_sector) as usize;
        let fat_offset = reserved + active as usize;
        let fat_size = BPBOffset::fat_size(boot_sector) as usize;
        let data_offset = reserved + BPBOffset::fats_number(boot_sector) as usize * fat_size;
        let total_sectors = BPBOffset::total_sectors(boot_sector) as usize;
        let bytes_per_sector = BPBOffset::bytes_per_sector(boot_sector) as usize;
        let sectors_per_cluster = BPBOffset::sector_per_cluster(boot_sector) as usize;
        let bytes_per_cluster = bytes_per_sector * sectors_per_cluster;
        let root_cluster = BPBOffset::root_cluster(boot_sector) as usize;
        let max_cluster = (total_sectors - data_offset) / sectors_per_cluster;
        if total_sectors / sectors_per_cluster < 65525 {
            error!("Not a FAT32 file system");
            return Err(Errno::EINVAL);
        }
        let metadata = Self {
            fat_offset,
            data_offset,
            bytes_per_sector,
            sectors_per_cluster,
            bytes_per_cluster,
            root_cluster,
            max_cluster,
        };
        Ok(metadata)
    }

    /// 根据簇号获取 FAT 表项的扇区号
    pub fn ent_sector_for_cluster(&self, cluster: usize) -> usize {
        self.fat_offset + cluster * 4 / self.bytes_per_sector
    }

    /// 根据簇号获取 FAT 表项的扇区偏移
    pub fn ent_offset_for_cluster(&self, cluster: usize) -> usize {
        cluster * 4 % self.bytes_per_sector
    }
    
    /// 根据簇号获取数据的起始扇区号
    pub fn data_sector_for_cluster(&self, cluster: usize) -> usize {
        self.data_offset + (cluster - 2) * self.sectors_per_cluster
    }
}

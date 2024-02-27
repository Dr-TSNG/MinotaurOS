use crate::fs::fat32::boot_sector::BPBOffset;
use crate::result::MosError::UnsupportedFileSystem;
use crate::result::MosResult;

#[derive(Debug)]
pub struct FAT32Meta {
    /// 活跃 FAT 表的扇区偏移
    pub fat_offset: usize,
    /// FAT 表占的扇区数
    pub fat_size: usize,
    /// 数据区的扇区偏移
    pub data_offset: usize,
    /// 最后扇区
    pub total_sectors: usize,
    /// 每扇区的字节数
    pub bytes_per_sector: usize,
    /// 每簇的扇区数
    pub sectors_per_cluster: usize,
}

impl FAT32Meta {
    pub fn new(boot_sector: &[u8]) -> MosResult<Self> {
        let ext_flags = BPBOffset::extend_flags(boot_sector);
        if ext_flags & (1 << 7) != 0 {
            return Err(UnsupportedFileSystem("Mirrored FAT is not supported"));
        }
        let active = ext_flags & 0b1111;
        let reserved = BPBOffset::reserved_sectors(boot_sector) as usize;
        let fat_offset = reserved + active as usize;
        let fat_size = BPBOffset::fat_size(boot_sector) as usize;
        let data_offset = reserved + BPBOffset::fats_number(boot_sector) as usize * fat_size;
        let total_sectors = BPBOffset::total_sectors(boot_sector) as usize;
        let bytes_per_sector = BPBOffset::bytes_per_sector(boot_sector) as usize;
        let sectors_per_cluster = BPBOffset::sector_per_cluster(boot_sector) as usize;
        if total_sectors / sectors_per_cluster < 65525 {
            return Err(UnsupportedFileSystem("Not a FAT32 file system"));
        }
        let metadata = Self {
            fat_offset,
            fat_size,
            data_offset,
            total_sectors,
            bytes_per_sector,
            sectors_per_cluster,
        };
        Ok(metadata)
    }
}

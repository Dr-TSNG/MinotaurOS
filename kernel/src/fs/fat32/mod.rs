use alloc::sync::Arc;
use log::info;
use crate::driver::BlockDevice;
use crate::fs::block_cache::BlockCache;
use crate::fs::fat32::fat::FAT32Meta;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::result::{MosResult, SyscallResult};

macro_rules! section {
    ($buf:ident, $start:ident, $end:ident) => {
        Self::split($buf, Self::$start, Self::$end).try_into().unwrap()
    }
}

mod bpb;
mod inode;
mod fat;
mod fsinfo;

const BLOCK_SIZE: usize = 512;
const BLOCK_CACHE_CAP: usize = 100;

const BOOT_SECTOR_ID: usize = 0;

pub struct FAT32FileSystem {
    device: Arc<dyn BlockDevice>,
    vfsmeta: FileSystemMeta,
    fat32meta: FAT32Meta,
    cache: BlockCache<BLOCK_SIZE>,
}

impl FAT32FileSystem {
    pub async fn new(
        device: Arc<dyn BlockDevice>,
        flags: VfsFlags,
    ) -> MosResult<Self> {
        let mut boot_sector = [0; BLOCK_SIZE];
        device.read_block(BOOT_SECTOR_ID, &mut boot_sector).await?;
        let vfsmeta = FileSystemMeta::new(FileSystemType::FAT32, flags);
        let fat32meta = FAT32Meta::new(&boot_sector)?;
        let cache = BlockCache::new(device.clone(), BLOCK_CACHE_CAP);
        let fs = FAT32FileSystem { device, vfsmeta, fat32meta, cache };
        info!("FAT32 metadata: {:?}", fs.fat32meta);
        Ok(fs)
    }

    pub async fn get_fat_ent(&self, cluster: usize) -> MosResult<u32> {
        let (block_id, block_offset) = self.cluster_to_block(cluster);
        let mut ent = [0; 4];
        self.cache.read_block(block_id, &mut ent, block_offset).await?;
        Ok(u32::from_le_bytes(ent))
    }

    pub async fn set_fat_ent(&self, cluster: usize, ent: u32) -> MosResult {
        let (block_id, block_offset) = self.cluster_to_block(cluster);
        self.cache.write_block(block_id, &ent.to_le_bytes(), block_offset).await?;
        Ok(())
    }
    
    /// 根据簇号计算块号和块偏移
    fn cluster_to_block(&self, cluster: usize) -> (usize, usize) {
        let sector = self.fat32meta.sector_for_cluster(cluster);
        let ent_offset = self.fat32meta.ent_offset_for_cluster(cluster);
        let block_id = self.fat32meta.bytes_per_sector / BLOCK_SIZE * sector;
        let block_offset = ent_offset % BLOCK_SIZE;
        (block_id, block_offset)
    }
}

impl FileSystem for FAT32FileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn root(&self) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }
}

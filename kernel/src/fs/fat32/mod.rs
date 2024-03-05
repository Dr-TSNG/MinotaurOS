use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use async_trait::async_trait;
use log::{info, trace};
use crate::driver::BlockDevice;
use crate::fs::block_cache::BlockCache;
use crate::fs::fat32::dir::FAT32Dirent;
use crate::fs::fat32::fat::{FAT32Meta, FATEnt};
use crate::fs::fat32::inode::FAT32Inode;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::result::{MosError, MosResult};

macro_rules! section {
    ($buf:ident, $start:ident, $end:ident) => {
        Self::split($buf, Self::$start, Self::$end).try_into().unwrap()
    }
}

mod bpb;
mod dir;
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
    ) -> MosResult<Arc<Self>> {
        let mut boot_sector = [0; BLOCK_SIZE];
        device.read_block(BOOT_SECTOR_ID, &mut boot_sector).await?;
        let vfsmeta = FileSystemMeta::new(FileSystemType::FAT32, flags);
        let fat32meta = FAT32Meta::new(&boot_sector)?;
        let cache = BlockCache::new(device.clone(), BLOCK_CACHE_CAP);
        let fs = FAT32FileSystem { device, vfsmeta, fat32meta, cache };
        info!("FAT32 metadata: {:?}", fs.fat32meta);
        Ok(Arc::new(fs))
    }

    /// 获取 FAT 表项
    pub async fn read_fat_ent(&self, cluster: usize) -> MosResult<FATEnt> {
        let (block_id, block_offset) = self.ent_block_for_cluster(cluster);
        let mut ent = [0; 4];
        self.cache.read_block(block_id, &mut ent, block_offset).await?;
        Ok(FATEnt::from(u32::from_le_bytes(ent)))
    }

    /// 写入 FAT 表项
    pub async fn write_fat_ent(&self, cluster: usize, ent: FATEnt) -> MosResult {
        let (block_id, block_offset) = self.ent_block_for_cluster(cluster);
        self.cache.write_block(block_id, &u32::from(ent).to_le_bytes(), block_offset).await?;
        Ok(())
    }

    /// 根据簇号和偏移读取数据
    pub async fn read_data(&self, cluster: usize, buf: &mut [u8], mut offset: usize) -> MosResult {
        buf.len().checked_add(offset)
            .take_if(|v| *v <= self.fat32meta.sectors_per_cluster)
            .ok_or(MosError::CrossBoundary)?;

        let mut cur = 0;
        let sector_start = self.fat32meta.data_sector_for_cluster(cluster);
        let sector_end = sector_start + self.fat32meta.sectors_per_cluster;
        'outer: for sector in sector_start..sector_end {
            let block_start = self.fat32meta.bytes_per_sector / BLOCK_SIZE * sector;
            let block_end = self.fat32meta.bytes_per_sector / BLOCK_SIZE * (sector + 1);
            for block_id in block_start..block_end {
                if offset >= BLOCK_SIZE {
                    offset -= BLOCK_SIZE;
                    continue;
                }
                let next = min(BLOCK_SIZE - offset, buf.len() - cur);
                self.cache.read_block(block_id, &mut buf[cur..next], offset).await?;
                offset = 0;
                cur = next;
                if cur == buf.len() {
                    break 'outer;
                }
            }
        }

        Ok(())
    }

    /// 根据簇号和偏移写入数据
    pub async fn write_data(&self, cluster: usize, buf: &[u8], mut offset: usize) -> MosResult {
        buf.len().checked_add(offset)
            .take_if(|v| *v <= self.fat32meta.bytes_per_cluster)
            .ok_or(MosError::CrossBoundary)?;

        let mut cur = 0;
        let sector_start = self.fat32meta.data_sector_for_cluster(cluster);
        let sector_end = sector_start + self.fat32meta.sectors_per_cluster;
        'outer: for sector in sector_start..sector_end {
            let block_start = self.fat32meta.bytes_per_sector / BLOCK_SIZE * sector;
            let block_end = self.fat32meta.bytes_per_sector / BLOCK_SIZE * (sector + 1);
            for block_id in block_start..block_end {
                if offset >= BLOCK_SIZE {
                    offset -= BLOCK_SIZE;
                    continue;
                }
                let next = min(BLOCK_SIZE - offset, buf.len() - cur);
                self.cache.write_block(block_id, &buf[cur..next], offset).await?;
                offset = 0;
                cur = next;
                if cur == buf.len() {
                    break 'outer;
                }
            }
        }

        Ok(())
    }

    pub async fn read_dir(self: Arc<Self>, clusters: &[usize]) -> MosResult<Vec<Arc<FAT32Inode>>> {
        let mut inodes = vec![];
        let mut dir = FAT32Dirent::default();
        'outer: for cluster in clusters {
            let sector_start = self.fat32meta.data_sector_for_cluster(*cluster);
            let sector_end = sector_start + self.fat32meta.sectors_per_cluster;
            for sector in sector_start..sector_end {
                let block_start = self.fat32meta.bytes_per_sector / BLOCK_SIZE * sector;
                let block_end = self.fat32meta.bytes_per_sector / BLOCK_SIZE * (sector + 1);
                for block_id in block_start..block_end {
                    let mut buf = [0; BLOCK_SIZE];
                    self.cache.read_block(block_id, &mut buf, 0).await?;
                    for i in (0..BLOCK_SIZE).step_by(32) {
                        let value = &buf[i..i + 32];
                        if FAT32Dirent::is_empty(value) {
                            break 'outer;
                        } else if FAT32Dirent::is_long_dirent(value) {
                            dir.append(value);
                        } else {
                            dir.last(value);
                            let byte_offset = block_id * BLOCK_SIZE + i;
                            trace!("Read FAT32 dirent: {} \tat {:#x} \tattr {:?}", dir.name, byte_offset, dir.attr);
                            let inode = FAT32Inode::new(&self, dir).await?;
                            inodes.push(inode);
                            dir = FAT32Dirent::default();
                        }
                    }
                }
            }
        }
        Ok(inodes)
    }

    /// 根据簇号计算 FAT 表项所在的块号和块偏移
    fn ent_block_for_cluster(&self, cluster: usize) -> (usize, usize) {
        let ent_sector = self.fat32meta.ent_sector_for_cluster(cluster);
        let ent_offset = self.fat32meta.ent_offset_for_cluster(cluster);
        let block_id = self.fat32meta.bytes_per_sector / BLOCK_SIZE * ent_sector;
        let block_offset = ent_offset % BLOCK_SIZE;
        (block_id, block_offset)
    }

    async fn walk_ent(&self, mut ent: FATEnt) -> MosResult<Vec<usize>> {
        let mut clusters = vec![];
        while let FATEnt::NEXT(cluster) = ent {
            clusters.push(cluster as usize);
            ent = self.read_fat_ent(cluster as usize).await?;
        }
        Ok(clusters)
    }
}

#[async_trait]
impl FileSystem for FAT32FileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    async fn root(self: Arc<Self>) -> MosResult<Arc<dyn Inode>> {
        let root_cluster = self.fat32meta.root_cluster as u32;
        let inode = FAT32Inode::root(&self, None, root_cluster).await?;
        Ok(inode)
    }
}

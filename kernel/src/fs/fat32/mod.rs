use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use log::{info, trace, warn};
use crate::driver::BlockDevice;
use crate::fs::block_cache::BlockCache;
use crate::fs::fat32::dir::FAT32Dirent;
use crate::fs::fat32::fat::{FAT32Meta, FATEnt};
use crate::fs::fat32::inode::FAT32Inode;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::result::{Errno, SyscallResult};
use crate::sync::once::LateInit;

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
    root: LateInit<Arc<FAT32Inode>>,
}

impl FAT32FileSystem {
    pub async fn new(
        device: Arc<dyn BlockDevice>,
        flags: VfsFlags,
    ) -> SyscallResult<Arc<Self>> {
        let mut boot_sector = [0; BLOCK_SIZE];
        device.read_block(BOOT_SECTOR_ID, &mut boot_sector).await?;
        let fs = Arc::new(FAT32FileSystem {
            device: device.clone(),
            vfsmeta: FileSystemMeta::new(FileSystemType::FAT32, flags),
            fat32meta: FAT32Meta::new(&boot_sector)?,
            cache: BlockCache::new(device, BLOCK_CACHE_CAP),
            root: LateInit::new(),
        });
        let root_cluster = fs.fat32meta.root_cluster as u32;
        fs.root.init(FAT32Inode::root(&fs, None, root_cluster).await?);
        info!("FAT32 metadata: {:?}", fs.fat32meta);
        Ok(fs)
    }

    /// 根据簇号和偏移读取数据
    pub async fn read_data(&self, cluster: usize, buf: &mut [u8], mut offset: usize) -> SyscallResult {
        buf.len().checked_add(offset)
            .take_if(|v| *v <= self.fat32meta.bytes_per_cluster)
            .expect("Cross boundary");

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
                let next = min(cur + BLOCK_SIZE - offset, buf.len());
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
    pub async fn write_data(&self, cluster: usize, buf: &[u8], mut offset: usize) -> SyscallResult {
        buf.len().checked_add(offset)
            .take_if(|v| *v <= self.fat32meta.bytes_per_cluster)
            .expect("Cross boundary");

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
                let next = min(cur + BLOCK_SIZE - offset, buf.len());
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

    pub async fn read_dir(self: Arc<Self>, parent: Arc<dyn Inode>, clusters: &[usize]) -> SyscallResult<Vec<Arc<FAT32Inode>>> {
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
                            let inode = FAT32Inode::new(&self, &parent, dir).await?;
                            inodes.push(inode);
                            dir = FAT32Dirent::default();
                        }
                    }
                }
            }
        }
        Ok(inodes)
    }
}

impl FileSystem for FAT32FileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn root(self: Arc<Self>) -> Arc<dyn Inode> {
        self.root.clone()
    }
}

impl FAT32FileSystem {
    /// 根据簇号计算 FAT 表项所在的块号和块偏移
    fn ent_block_for_cluster(&self, cluster: usize) -> (usize, usize) {
        let ent_sector = self.fat32meta.ent_sector_for_cluster(cluster);
        let ent_offset = self.fat32meta.ent_offset_for_cluster(cluster);
        let block_id = self.fat32meta.bytes_per_sector / BLOCK_SIZE * ent_sector;
        let block_offset = ent_offset % BLOCK_SIZE;
        (block_id, block_offset)
    }

    /// 获取 FAT 表项
    async fn read_fat_ent(&self, cluster: usize) -> SyscallResult<FATEnt> {
        let (block_id, block_offset) = self.ent_block_for_cluster(cluster);
        let mut ent = [0; 4];
        self.cache.read_block(block_id, &mut ent, block_offset).await?;
        Ok(FATEnt::from(u32::from_le_bytes(ent)))
    }

    /// 写入 FAT 表项
    async fn write_fat_ent(&self, cluster: usize, ent: FATEnt) -> SyscallResult {
        let (block_id, block_offset) = self.ent_block_for_cluster(cluster);
        self.cache.write_block(block_id, &u32::from(ent).to_le_bytes(), block_offset).await?;
        Ok(())
    }

    /// 分配一个簇
    async fn alloc_cluster(&self) -> SyscallResult<usize> {
        let mut cluster = 0;
        for pos in 2..self.fat32meta.max_cluster {
            let fat_ent = self.read_fat_ent(cluster).await?;
            if fat_ent == FATEnt::EMPTY {
                cluster = pos;
                break;
            }
        }
        if cluster == 0 {
            warn!("Disk is full");
            return Err(Errno::ENOSPC);
        }
        self.write_fat_ent(cluster, FATEnt::EOF).await?;
        Ok(cluster)
    }

    async fn walk_ent(&self, mut ent: FATEnt) -> SyscallResult<Vec<usize>> {
        let mut clusters = vec![];
        while let FATEnt::NEXT(cluster) = ent {
            clusters.push(cluster as usize);
            ent = self.read_fat_ent(cluster as usize).await?;
        }
        Ok(clusters)
    }
}

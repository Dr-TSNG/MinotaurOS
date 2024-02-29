use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cmp::min;
use async_trait::async_trait;
use log::error;
use crate::fs::fat32::dir::{FAT32Dirent, FileAttr};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::fat32::fat::FATEnt;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeMeta, InodeMetaInner};
use crate::result::{Errno, MosResult, SyscallResult};
use crate::result::Errno::EIO;
use crate::sync::mutex::{AsyncMutex, Mutex};

pub struct FAT32Inode {
    metadata: InodeMeta,
    fs: Weak<FAT32FileSystem>,
    inner: AsyncMutex<Fat32InodeInner>,
}

struct Fat32InodeInner {
    clusters: Vec<usize>,
}

impl FAT32Inode {
    pub async fn new(
        fs: Arc<FAT32FileSystem>,
        dir: FAT32Dirent,
    ) -> MosResult<Arc<Self>> {
        let mode = match dir.attr.contains(FileAttr::ATTR_DIRECTORY) {
            true => InodeMode::DIR,
            false => InodeMode::IFREG,
        };
        let metadata = InodeMeta {
            ino: 0,
            dev: fs.device.metadata().dev_id,
            mode,
            inner: Mutex::new(InodeMetaInner {
                name: dir.name,
                uid: 0,
                gid: 0,
                nlink: 0,
                atime: dir.acc_time,
                mtime: dir.wrt_time,
                ctime: dir.crt_time,
                size: dir.size as isize,
                parent: None,
                children: BTreeMap::new(),
            }),
        };
        let inode = Self {
            metadata,
            fs: Arc::downgrade(&fs),
            inner: AsyncMutex::new(Fat32InodeInner {
                clusters: fs.walk_ent(FATEnt::NEXT(dir.cluster)).await?,
            }),
        };
        Ok(Arc::new(inode))
    }
}

#[async_trait]
impl Inode for FAT32Inode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    async fn read(&self, mut buf: &mut [u8], mut offset: usize) -> SyscallResult<isize> {
        let fs = self.fs.upgrade().ok_or(Errno::EINVAL)?;
        let file_size = self.metadata.inner.lock().size as usize;

        if offset >= file_size { return Ok(0); }
        let buf_end = min(buf.len(), file_size - offset);
        buf = &mut buf[..buf_end];

        let inner = self.inner.lock().await;
        let mut cur = 0;
        'outer: for id in &inner.clusters {
            if offset >= fs.fat32meta.bytes_per_cluster {
                offset -= fs.fat32meta.bytes_per_cluster;
                continue;
            }
            let next = min(fs.fat32meta.bytes_per_cluster - offset, buf.len() - cur);
            if let Err(e) = fs.read_data(inner.clusters[*id], &mut buf[cur..next], offset).await {
                error!("IO Error: {:?}", e);
                return Err(EIO);
            }
            offset = 0;
            cur = next;
            if cur == buf.len() {
                break 'outer;
            }
        }

        Ok(buf.len() as isize)
    }
}

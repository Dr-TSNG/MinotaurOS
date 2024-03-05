use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use log::{debug, error, trace};
use crate::fs::fat32::dir::{FAT32Dirent, FileAttr};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::fat32::fat::FATEnt;
use crate::fs::ffi::{InodeMode, OpenFlags, TimeSpec};
use crate::fs::file::{File, FileMeta, RegularFile};
use crate::fs::inode::{Inode, InodeMeta, InodeMetaInner};
use crate::result::{Errno, MosResult, SyscallResult};
use crate::sync::mutex::{AsyncMutex, Mutex};

pub struct FAT32Inode {
    metadata: InodeMeta,
    fs: Weak<FAT32FileSystem>,
    inner: AsyncMutex<Fat32InodeInner>,
}

struct Fat32InodeInner {
    clusters: Vec<usize>,
    children: Vec<Arc<dyn Inode>>,
}

static INO_POOL: AtomicUsize = AtomicUsize::new(0);

impl FAT32Inode {
    pub async fn root(
        fs: &Arc<FAT32FileSystem>,
        parent: Option<Weak<dyn Inode>>,
        root_cluster: u32,
    ) -> MosResult<Arc<Self>> {
        let metadata = InodeMeta {
            ino: INO_POOL.fetch_add(1, Ordering::Acquire),
            dev: fs.device.metadata().dev_id,
            mode: InodeMode::DIR,
            inner: Mutex::new(InodeMetaInner {
                name: ".".to_string(),
                uid: 0,
                gid: 0,
                nlink: 0,
                atime: TimeSpec::default(),
                mtime: TimeSpec::default(),
                ctime: TimeSpec::default(),
                size: 0,
                parent,
                children: BTreeMap::new(),
            }),
        };
        let inode = Self {
            metadata,
            fs: Arc::downgrade(&fs),
            inner: AsyncMutex::new(Fat32InodeInner {
                clusters: fs.walk_ent(FATEnt::NEXT(root_cluster)).await?,
                children: vec![],
            }),
        };
        Ok(Arc::new(inode))
    }

    pub async fn new(
        fs: &Arc<FAT32FileSystem>,
        dir: FAT32Dirent,
    ) -> MosResult<Arc<Self>> {
        let mode = match dir.attr.contains(FileAttr::ATTR_DIRECTORY) {
            true => InodeMode::DIR,
            false => InodeMode::IFREG,
        };
        let metadata = InodeMeta {
            ino: INO_POOL.fetch_add(1, Ordering::Acquire),
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
                children: vec![],
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

    async fn open(self: Arc<Self>) -> SyscallResult<Arc<dyn File>> {
        Ok(Arc::new(RegularFile::new(FileMeta::new(self))))
    }

    async fn read(&self, mut buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let file_size = self.metadata.inner.lock().size as usize;

        let mut offset = offset as usize;
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
                return Err(Errno::EIO);
            }
            offset = 0;
            cur = next;
            if cur == buf.len() {
                break 'outer;
            }
        }

        Ok(buf.len() as isize)
    }

    async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        todo!()
    }

    async fn lookup(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        trace!(
            "[fat32] Lookup from {} ino {} for {}",
            self.metadata().inner.lock().name,
            self.metadata().ino,
            name,
        );
        if inner.children.is_empty() {
            inner.load_children(fs).await?;
        }
        for inode in inner.children.iter() {
            if inode.metadata().inner.lock().name == name {
                return Ok(inode.clone());
            }
        }
        Err(Errno::ENOENT)
    }

    async fn list(&self, iter: usize) -> SyscallResult<Arc<dyn Inode>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        trace!(
            "[fat32] List from {} ino {} at {}",
            self.metadata().inner.lock().name,
            self.metadata().ino,
            iter,
        );
        if inner.children.is_empty() {
            inner.load_children(fs).await?;
        }
        if iter < inner.children.len() {
            Ok(inner.children[iter].clone())
        } else {
            Err(Errno::ENOENT)
        }
    }

    async fn create(&self, name: &str, mode: OpenFlags) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }

    async fn mkdir(&self, name: &str, mode: OpenFlags) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }

    async fn unlink(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }
}

impl Fat32InodeInner {
    async fn load_children(&mut self, fs: Arc<FAT32FileSystem>) -> SyscallResult {
        debug!("[fat32] Load children");
        let inodes = fs.read_dir(&self.clusters).await.map_err(|e| {
            error!("IO Error: {:?}", e);
            Errno::EIO
        })?;
        for inode in inodes {
            self.children.push(inode);
        }
        Ok(())
    }
}

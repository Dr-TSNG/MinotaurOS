use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::{format, vec};
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use log::{debug, error, trace};
use crate::fs::fat32::dir::{FAT32Dirent, FileAttr};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::fat32::fat::FATEnt;
use crate::fs::ffi::{InodeMode, TimeSpec};
use crate::fs::file::{File, FileMeta, RegularFile};
use crate::fs::inode::{Inode, InodeMeta};
use crate::result::{Errno, MosResult, SyscallResult};
use crate::sync::mutex::AsyncMutex;

pub struct FAT32Inode {
    metadata: InodeMeta,
    fs: Weak<FAT32FileSystem>,
    inner: AsyncMutex<FAT32InodeInner>,
}

struct FAT32InodeInner {
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
        let metadata = InodeMeta::new(
            INO_POOL.fetch_add(1, Ordering::Acquire),
            fs.device.metadata().dev_id,
            InodeMode::DIR,
            "/".to_string(),
            "/".to_string(),
            TimeSpec::default(),
            TimeSpec::default(),
            TimeSpec::default(),
            0,
            parent,
        );
        let inode = Self {
            metadata,
            fs: Arc::downgrade(&fs),
            inner: AsyncMutex::new(FAT32InodeInner {
                clusters: fs.walk_ent(FATEnt::NEXT(root_cluster)).await?,
                children: vec![],
            }),
        };
        Ok(Arc::new(inode))
    }

    pub async fn new(
        fs: &Arc<FAT32FileSystem>,
        parent: &Arc<dyn Inode>,
        dir: FAT32Dirent,
    ) -> MosResult<Arc<Self>> {
        let mode = match dir.attr.contains(FileAttr::ATTR_DIRECTORY) {
            true => InodeMode::DIR,
            false => InodeMode::IFREG,
        };
        let path = format!("{}/{}", parent.metadata().path, dir.name);
        let metadata = InodeMeta::new(
            INO_POOL.fetch_add(1, Ordering::Acquire),
            fs.device.metadata().dev_id,
            mode,
            dir.name,
            path,
            dir.acc_time,
            dir.wrt_time,
            dir.crt_time,
            dir.size as isize,
            Some(Arc::downgrade(parent)),
        );
        let inode = Self {
            metadata,
            fs: Arc::downgrade(&fs),
            inner: AsyncMutex::new(FAT32InodeInner {
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

    fn open(self: Arc<Self>) -> SyscallResult<Arc<dyn File>> {
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
        'outer: for cluster in &inner.clusters {
            if offset >= fs.fat32meta.bytes_per_cluster {
                offset -= fs.fat32meta.bytes_per_cluster;
                continue;
            }
            let next = min(cur + fs.fat32meta.bytes_per_cluster - offset, buf.len());
            if let Err(e) = fs.read_data(*cluster, &mut buf[cur..next], offset).await {
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

    async fn lookup(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        trace!(
            "[fat32] Lookup from {} ino {} for {}",
            self.metadata().name,
            self.metadata().ino,
            name,
        );
        if inner.children.is_empty() {
            self.load_children(&mut inner, fs).await?;
        }
        for inode in inner.children.iter() {
            if inode.metadata().name == name {
                return Ok(inode.clone());
            }
        }
        Err(Errno::ENOENT)
    }

    async fn list(self: Arc<Self>, index: usize) -> SyscallResult<Vec<Arc<dyn Inode>>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        trace!(
            "[fat32] List from {} ino {} at {}",
            self.metadata().name,
            self.metadata().ino,
            index,
        );
        if inner.children.is_empty() {
            self.load_children(&mut inner, fs).await?;
        }
        let mut ret = vec![];
        for child in inner.children.iter().skip(index) {
            ret.push(child.clone());
        }
        Ok(ret)
    }

    async fn create(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }

    async fn mkdir(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }

    async fn unlink(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }
}

impl FAT32Inode {
    async fn load_children(self: &Arc<Self>, inner: &mut FAT32InodeInner, fs: Arc<FAT32FileSystem>) -> SyscallResult {
        debug!("[fat32] Load children");
        let inodes = fs.read_dir(self.clone(), &inner.clusters).await.map_err(|e| {
            error!("IO Error: {:?}", e);
            Errno::EIO
        })?;
        for inode in inodes {
            inner.children.push(inode);
        }
        Ok(())
    }
}

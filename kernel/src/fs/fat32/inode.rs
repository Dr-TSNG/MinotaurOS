use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::{format, vec};
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use bitvec_rs::BitVec;
use log::{debug, trace};
use crate::fs::fat32::dir::{FAT32Dirent, FileAttr};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::fat32::fat::FATEnt;
use crate::fs::ffi::{InodeMode, TimeSpec};
use crate::fs::file::{File, FileMeta, RegularFile};
use crate::fs::inode::{Inode, InodeMeta};
use crate::result::{Errno, SyscallResult};
use crate::sched::time::current_time;
use crate::sync::mutex::AsyncMutex;

pub struct FAT32Inode {
    metadata: InodeMeta,
    fs: Weak<FAT32FileSystem>,
    inner: AsyncMutex<FAT32InodeInner>,
}

struct FAT32InodeInner {
    dir_occupy: BitVec,
    clusters: Vec<usize>,
    children: Vec<FAT32Child>,
    children_loaded: bool,
}

#[derive(Clone)]
pub struct FAT32Child {
    inode: Arc<dyn Inode>,
    dir_pos: usize,
    dir_len: usize,
}

impl FAT32Child {
    pub fn new(inode: Arc<dyn Inode>, dir_pos: usize, dir_len: usize) -> Self {
        Self { inode, dir_pos, dir_len }
    }
}

static INO_POOL: AtomicUsize = AtomicUsize::new(0);

impl FAT32Inode {
    pub async fn root(
        fs: &Arc<FAT32FileSystem>,
        parent: Option<Weak<dyn Inode>>,
        root_cluster: u32,
    ) -> SyscallResult<Arc<Self>> {
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
            fs: Arc::downgrade(fs),
            inner: AsyncMutex::new(FAT32InodeInner {
                dir_occupy: BitVec::new(),
                clusters: fs.walk_fat_ent(FATEnt::NEXT(root_cluster)).await?,
                children: vec![],
                children_loaded: false,
            }),
        };
        Ok(Arc::new(inode))
    }

    pub async fn new(
        fs: &Arc<FAT32FileSystem>,
        parent: Arc<dyn Inode>,
        dir: FAT32Dirent,
    ) -> SyscallResult<Arc<Self>> {
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
            Some(Arc::downgrade(&parent)),
        );
        let inode = Self {
            metadata,
            fs: Arc::downgrade(&fs),
            inner: AsyncMutex::new(FAT32InodeInner {
                dir_occupy: BitVec::new(),
                clusters: fs.walk_fat_ent(FATEnt::NEXT(dir.cluster)).await?,
                children: vec![],
                children_loaded: false,
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
        Ok(Arc::new(RegularFile::new(FileMeta::new(Some(self)))))
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
            fs.read_data(*cluster, &mut buf[cur..next], offset).await?;
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
        if !inner.children_loaded {
            self.load_children(&mut inner, &fs).await?;
        }
        for child in inner.children.iter() {
            if child.inode.metadata().name == name {
                return Ok(child.inode.clone());
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
        if !inner.children_loaded {
            self.load_children(&mut inner, &fs).await?;
        }
        let mut ret = vec![];
        for child in inner.children.iter().skip(index) {
            ret.push(child.inode.clone());
        }
        Ok(ret)
    }

    async fn create(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }

    async fn mkdir(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let inner = &mut *self.inner.lock().await;
        if !inner.children_loaded {
            self.load_children(inner, &fs).await?;
        }
        for child in inner.children.iter() {
            if child.inode.metadata().name == name {
                return Err(Errno::EEXIST);
            }
        }
        let cluster = fs.alloc_cluster().await?;
        let dirent = FAT32Dirent::new(name.to_string(), FileAttr::ATTR_DIRECTORY, cluster as u32, 0);
        let (dir_pos, dir_len) = fs.append_dir(&mut inner.clusters, &mut inner.dir_occupy, &dirent).await?;
        let now = current_time();
        let this: Arc<dyn Inode> = self.clone();
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                INO_POOL.fetch_add(1, Ordering::Acquire),
                fs.device.metadata().dev_id,
                InodeMode::DIR,
                name.to_string(),
                format!("{}/{}", self.metadata().path, name),
                now.into(),
                now.into(),
                now.into(),
                0,
                Some(Arc::downgrade(&this)),
            ),
            fs: Arc::downgrade(&fs),
            inner: AsyncMutex::new(FAT32InodeInner {
                dir_occupy: BitVec::new(),
                clusters: vec![cluster],
                children: vec![],
                children_loaded: true,
            }),
        });
        {
            let child_inner = &mut *inode.inner.lock().await;
            let parent_dir = FAT32Dirent::new("..".to_string(), FileAttr::ATTR_DIRECTORY, inner.clusters[0] as u32, 0);
            let mut child_dir = dirent.clone();
            child_dir.name = ".".to_string();
            fs.append_dir(&mut child_inner.clusters, &mut child_inner.dir_occupy, &parent_dir).await?;
            fs.append_dir(&mut child_inner.clusters, &mut child_inner.dir_occupy, &child_dir).await?;
        }
        inner.children.push(FAT32Child::new(inode.clone(), dir_pos, dir_len));
        Ok(inode)
    }

    async fn unlink(self: Arc<Self>, name: &str) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let inner = &mut *self.inner.lock().await;
        if !inner.children_loaded {
            self.load_children(inner, &fs).await?;
        }
        let mut target: Option<FAT32Child> = None;
        for child in inner.children.iter().cloned() {
            if child.inode.metadata().name == name {
                if child.inode.metadata().mode == InodeMode::DIR && child.inode.clone().list(0).await.is_ok() {
                    return Err(Errno::ENOTEMPTY);
                } else {
                    target = Some(child);
                    break;
                }
            }
        }
        let target = target.ok_or(Errno::ENOENT)?;
        fs.remove_dir(&mut inner.clusters, &mut inner.dir_occupy, target.dir_pos, target.dir_len).await?;
        Ok(())
    }
}

impl FAT32Inode {
    async fn load_children(self: &Arc<Self>, inner: &mut FAT32InodeInner, fs: &Arc<FAT32FileSystem>) -> SyscallResult {
        debug!("[fat32] Load children");
        let inodes = fs.read_dir(self.clone(), &inner.clusters, &mut inner.dir_occupy).await?;
        for inode in inodes {
            inner.children.push(inode);
        }
        inner.children_loaded = true;
        Ok(())
    }
}

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::{format, vec};
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use bitvec_rs::BitVec;
use log::debug;
use crate::fs::fat32::dir::{FAT32Dirent, FileAttr};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::fat32::fat::FATEnt;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeChild, InodeInternal, InodeMeta, InodeMetaInner};
use crate::fs::page_cache::PageCache;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sched::time::current_time;
use crate::sync::block_on;
use crate::sync::mutex::AsyncMutex;

pub struct FAT32Inode {
    metadata: InodeMeta,
    fs: Weak<FAT32FileSystem>,
    ext: Arc<AsyncMutex<FAT32InodeExt>>,
}

struct FAT32InodeExt {
    dir_occupy: BitVec,
    clusters: Vec<usize>,
}

pub struct FAT32ChildExt {
    dir_pos: usize,
    dir_len: usize,
}

impl FAT32ChildExt {
    pub fn new(dir_pos: usize, dir_len: usize) -> Box<Self> {
        Box::new(Self { dir_pos, dir_len })
    }
}

static INO_POOL: AtomicUsize = AtomicUsize::new(0);

impl FAT32Inode {
    pub async fn root(
        fs: &Arc<FAT32FileSystem>,
        parent: Option<Arc<dyn Inode>>,
        root_cluster: u32,
    ) -> SyscallResult<Arc<Self>> {
        let inode = Self {
            metadata: InodeMeta::new(
                INO_POOL.fetch_add(1, Ordering::Acquire),
                fs.device.metadata().dev_id,
                InodeMode::IFDIR,
                "/".to_string(),
                "/".to_string(),
                parent,
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            fs: Arc::downgrade(fs),
            ext: Arc::new(AsyncMutex::new(FAT32InodeExt {
                dir_occupy: BitVec::new(),
                clusters: fs.walk_fat_ent(FATEnt::NEXT(root_cluster)).await?,
            })),
        };
        Ok(Arc::new(inode))
    }

    pub async fn new(
        fs: &Arc<FAT32FileSystem>,
        parent: Arc<dyn Inode>,
        dir: FAT32Dirent,
    ) -> SyscallResult<Arc<Self>> {
        let (mode, page_cache) = match dir.attr.contains(FileAttr::ATTR_DIRECTORY) {
            true => (InodeMode::IFDIR, None),
            false => (InodeMode::IFREG, Some(PageCache::new())),
        };
        let path = format!("{}/{}", parent.metadata().path, dir.name);
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                INO_POOL.fetch_add(1, Ordering::Acquire),
                fs.device.metadata().dev_id,
                mode,
                dir.name,
                path,
                Some(parent),
                page_cache,
                dir.acc_time,
                dir.wrt_time,
                dir.crt_time,
                dir.size as isize,
            ),
            fs: Arc::downgrade(&fs),
            ext: Arc::new(AsyncMutex::new(FAT32InodeExt {
                dir_occupy: BitVec::new(),
                clusters: fs.walk_fat_ent(FATEnt::NEXT(dir.cluster)).await?,
            })),
        });
        Ok(inode)
    }
}

#[async_trait]
impl Inode for FAT32Inode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }
}

#[async_trait]
impl InodeInternal for FAT32Inode {
    async fn read_direct(&self, mut buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let file_size = self.metadata.inner.lock().size as usize;
        let mut offset = offset as usize;
        if offset >= file_size { return Ok(0); }
        let buf_end = min(buf.len(), file_size - offset);
        buf = &mut buf[..buf_end];

        let ext = self.ext.lock().await;
        let mut cur = 0;
        let cluster_start = offset / fs.fat32meta.bytes_per_cluster;
        offset %= fs.fat32meta.bytes_per_cluster;
        for cluster in &ext.clusters[cluster_start..] {
            let next = min(cur + fs.fat32meta.bytes_per_cluster - offset, buf.len());
            fs.read_data(*cluster, &mut buf[cur..next], offset).await?;
            offset = 0;
            cur = next;
            if cur == buf.len() {
                break;
            }
        }

        Ok(buf.len() as isize)
    }

    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let file_size = self.metadata.inner.lock().size as usize;
        let mut offset = offset as usize;
        if offset + buf.len() > file_size {
            self.truncate_direct((offset + buf.len()) as isize).await?;
        }

        let ext = self.ext.lock().await;
        let mut cur = 0;
        let cluster_start = offset / fs.fat32meta.bytes_per_cluster;
        offset %= fs.fat32meta.bytes_per_cluster;
        for cluster in &ext.clusters[cluster_start..] {
            let next = min(cur + fs.fat32meta.bytes_per_cluster - offset, buf.len());
            fs.write_data(*cluster, &buf[cur..next], offset).await?;
            offset = 0;
            cur = next;
            if cur == buf.len() {
                break;
            }
        }

        Ok(buf.len() as isize)
    }

    async fn truncate_direct(&self, new_size: isize) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let file_size = self.metadata.inner.lock().size as usize;
        let new_size = new_size as usize;
        if new_size == file_size {
            return Ok(());
        } else if new_size < file_size {
            let mut ext = self.ext.lock().await;
            let mut cluster_start = new_size.div_ceil(fs.fat32meta.bytes_per_cluster);
            if cluster_start == 0 {
                cluster_start = 1;
            }
            fs.write_fat_ent(ext.clusters[cluster_start - 1], FATEnt::EOF).await?;
            if cluster_start < ext.clusters.len() {
                for cluster in &ext.clusters[cluster_start..] {
                    fs.write_fat_ent(*cluster, FATEnt::EMPTY).await?;
                }
                ext.clusters.truncate(cluster_start);
            }
        } else {
            let mut ext = self.ext.lock().await;
            let mut cluster_start = file_size.div_ceil(fs.fat32meta.bytes_per_cluster);
            let cluster_end = new_size.div_ceil(fs.fat32meta.bytes_per_cluster);
            if cluster_start == 0 {
                cluster_start = 1;
            }
            if cluster_start < cluster_end {
                let mut prev = ext.clusters[cluster_start - 1];
                for _ in cluster_start..cluster_end {
                    let cluster = fs.alloc_cluster().await?;
                    fs.write_fat_ent(prev, FATEnt::NEXT(cluster as u32)).await?;
                    prev = cluster;
                    ext.clusters.push(cluster);
                }
                fs.write_fat_ent(prev, FATEnt::EOF).await?;
            }
        }
        self.metadata.inner.lock().size = new_size as isize;

        Ok(())
    }

    async fn load_children(self: Arc<Self>, inner: &mut InodeMetaInner) -> SyscallResult {
        debug!("[fat32] Load children");
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let ext = &mut *self.ext.lock().await;
        let children = fs.read_dir(self.clone(), &ext.clusters, &mut ext.dir_occupy).await?;
        for child in children {
            let name = child.inode.metadata().name.clone();
            if name == "." || name == ".." {
                continue;
            }
            inner.children.insert(name, child);
        }
        inner.children_loaded = true;
        Ok(())
    }

    async fn do_create(
        self: Arc<Self>,
        inner: &mut InodeMetaInner,
        mode: InodeMode,
        name: &str,
    ) -> SyscallResult<InodeChild> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        if !inner.children_loaded {
            self.clone().load_children(inner).await?;
        }
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let ext = &mut *self.ext.lock().await;
        let cluster = fs.alloc_cluster().await?;
        let attr = if mode == InodeMode::IFDIR { FileAttr::ATTR_DIRECTORY } else { FileAttr::empty() };
        let dirent = FAT32Dirent::new(name.to_string(), attr, cluster as u32, 0);
        let (dir_pos, dir_len) = fs.append_dir(&mut ext.clusters, &mut ext.dir_occupy, &dirent).await?;
        let now = current_time();
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                INO_POOL.fetch_add(1, Ordering::Acquire),
                fs.device.metadata().dev_id,
                mode,
                name.to_string(),
                format!("{}/{}", self.metadata().path, name),
                Some(self.clone()),
                Some(PageCache::new()),
                now.into(),
                now.into(),
                now.into(),
                0,
            ),
            fs: Arc::downgrade(&fs),
            ext: Arc::new(AsyncMutex::new(FAT32InodeExt {
                dir_occupy: BitVec::new(),
                clusters: vec![cluster],
            })),
        });
        if mode == InodeMode::IFDIR {
            let child_ext = &mut *inode.ext.lock().await;
            let parent_dir = FAT32Dirent::new("..".to_string(), FileAttr::ATTR_DIRECTORY, ext.clusters[0] as u32, 0);
            let mut child_dir = dirent.clone();
            child_dir.name = ".".to_string();
            fs.append_dir(&mut child_ext.clusters, &mut child_ext.dir_occupy, &parent_dir).await?;
            fs.append_dir(&mut child_ext.clusters, &mut child_ext.dir_occupy, &child_dir).await?;
        }
        Ok(InodeChild::new(inode.clone(), FAT32ChildExt::new(dir_pos, dir_len)))
    }

    async fn do_movein(
        self: Arc<Self>,
        inner: &mut InodeMetaInner,
        name: &str,
        inode: Arc<dyn Inode>,
    ) -> SyscallResult<InodeChild> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        if !inner.children_loaded {
            self.clone().load_children(inner).await?;
        }
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let ext = &mut *self.ext.lock().await;

        match inode.downcast_arc::<FAT32Inode>() {
            Ok(inode) => {
                let attr = if inode.metadata().mode == InodeMode::IFDIR { FileAttr::ATTR_DIRECTORY } else { FileAttr::empty() };
                let cluster = inode.ext.lock().await.clusters[0];
                let dirent = FAT32Dirent::new(name.to_string(), attr, cluster as u32, 0);
                let (dir_pos, dir_len) = fs.append_dir(&mut ext.clusters, &mut ext.dir_occupy, &dirent).await?;
                let inode = Arc::new(Self {
                    metadata: InodeMeta::movein(
                        inode.as_ref(),
                        name.to_string(),
                        format!("{}/{}", self.metadata().path, name),
                        self.clone(),
                    ),
                    fs: Arc::downgrade(&fs),
                    ext: inode.ext.clone(),
                });
                Ok(InodeChild::new(inode.clone(), FAT32ChildExt::new(dir_pos, dir_len)))
            }
            Err(_) => {
                todo!("Moving across file systems is not supported yet");
            }
        }
    }

    async fn do_unlink(
        self: Arc<Self>,
        inner: &mut InodeMetaInner,
        name: &str,
    ) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        if !inner.children_loaded {
            self.clone().load_children(inner).await?;
        }
        let target = inner.children.get(name).ok_or(Errno::ENOENT)?;
        let ext = &mut *self.ext.lock().await;
        let child_ext = target.ext.downcast_ref::<FAT32ChildExt>().unwrap();
        fs.remove_dir(&mut ext.clusters, &mut ext.dir_occupy, child_ext.dir_pos, child_ext.dir_len).await?;
        Ok(())
    }
}

impl Drop for FAT32Inode {
    fn drop(&mut self) {
        if let Some(page_cache) = self.metadata.page_cache.as_ref() {
            block_on(page_cache.sync_all(self)).unwrap();
        }
    }
}

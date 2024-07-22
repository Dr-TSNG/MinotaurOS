use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use log::debug;
use tap::Tap;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::page_cache::PageCache;
use crate::fs::path::append_path;
use crate::fs::tmpfs::TmpFileSystem;
use crate::result::{Errno, SyscallResult};
use crate::sched::time::real_time;
use crate::sync::mutex::AsyncMutex;

pub struct TmpfsInode {
    metadata: InodeMeta,
    fs: Weak<TmpFileSystem>,
    inner: Arc<AsyncMutex<TmpfsInodeInner>>,
}

#[derive(Default)]
struct TmpfsInodeInner {
    link: String,
    children: BTreeMap<String, Arc<TmpfsInode>>,
}

impl TmpfsInode {
    pub fn root(fs: &Arc<TmpFileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                InodeMode::IFDIR,
                "/".to_string(),
                "/".to_string(),
                parent,
                None,
                Default::default(),
                Default::default(),
                Default::default(),
                0,
            ),
            fs: Arc::downgrade(fs),
            inner: Default::default(),
        })
    }
}

impl TmpfsInodeInner {
    fn new_with_link(link: String) -> Arc<AsyncMutex<Self>> {
        Arc::new(AsyncMutex::new(Self { link, ..Default::default() }))
    }
}

#[async_trait]
impl InodeInternal for TmpfsInode {
    async fn read_direct(&self, _: &mut [u8], _: isize) -> SyscallResult<isize> {
        panic!("Tmpfs file should always be read from page cache");
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        panic!("Tmpfs file should always be written to page cache");
    }

    async fn truncate_direct(&self, _: isize) -> SyscallResult {
        panic!("Tmpfs file should always be truncated in page cache");
    }

    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let inner = self.inner.lock().await;
        match inner.children.get(name) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        let inner = self.inner.lock().await;
        match inner.children.values().nth(idx) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_create(self: Arc<Self>, mode: InodeMode, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        debug!("[tmpfs] Create file {} for {:?}", name, mode);
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let page_cache = match mode {
            InodeMode::IFREG => Some(PageCache::new().tap_mut(|it| it.set_deleted())),
            _ => None,
        };
        let now = real_time();
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                mode,
                name.to_string(),
                format!("{}/{}", self.metadata().path, name),
                Some(self.clone()),
                page_cache,
                now.into(),
                now.into(),
                now.into(),
                0,
            ),
            fs: Arc::downgrade(&fs),
            inner: Default::default(),
        });
        inner.children.insert(name.to_string(), inode.clone());
        Ok(inode)
    }

    async fn do_symlink(self: Arc<Self>, name: &str, target: &str) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let now = real_time();
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                InodeMode::IFLNK,
                name.to_string(),
                format!("{}/{}", self.metadata().path, name),
                Some(self.clone()),
                None,
                now.into(),
                now.into(),
                now.into(),
                0,
            ),
            fs: Arc::downgrade(&fs),
            inner: TmpfsInodeInner::new_with_link(target.to_string()),
        });
        inner.children.insert(name.to_string(), inode);
        Ok(())
    }

    async fn do_movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        if let Ok(inode) = inode.downcast_arc::<TmpfsInode>() {
            let inode = Arc::new(Self {
                metadata: InodeMeta::movein(
                    inode.as_ref(),
                    name.to_string(),
                    append_path(&self.metadata.path, &name),
                    self.clone(),
                ),
                fs: Arc::downgrade(&fs),
                inner: inode.inner.clone(),
            });
            inner.children.insert(name.to_string(), inode);
        } else {
            todo!("Moving across file systems is not supported yet");
        }
        Ok(())
    }

    async fn do_unlink(self: Arc<Self>, target: Arc<dyn Inode>) -> SyscallResult {
        let mut inner = self.inner.lock().await;
        if inner.children.remove(&target.metadata().name).is_none() {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }

    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        let inner = self.inner.lock().await;
        Ok(inner.link.clone())
    }
}

impl Inode for TmpfsInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}

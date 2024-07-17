use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use core::time::Duration;
use async_trait::async_trait;
use log::{debug, trace};
use lwext4_rust::Ext4File;
use lwext4_rust::bindings::{EXT4_INODE_ROOT_INDEX, O_CREAT, O_RDWR, SEEK_SET};
use lwext4_rust::dir::Ext4Dir;
use crate::fs::ext4::Ext4FileSystem;
use crate::fs::ext4::wrapper::i32_to_err;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::page_cache::PageCache;
use crate::fs::path::append_path;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::AsyncMutex;

pub struct Ext4Inode {
    metadata: InodeMeta,
    fs: Weak<Ext4FileSystem>,
    inner: Arc<AsyncMutex<Ext4InodeInner>>,
}

struct Ext4InodeInner {
    children_loaded: bool,
    children: BTreeMap<String, Arc<Ext4Inode>>,
}

impl Ext4InodeInner {
    fn new() -> Arc<AsyncMutex<Self>> {
        Arc::new(AsyncMutex::new(Self {
            children_loaded: false,
            children: Default::default(),
        }))
    }
}

impl Ext4Inode {
    pub fn root(fs: &Arc<Ext4FileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let inode_ref = fs.ext4.ext4_get_inode_ref(EXT4_INODE_ROOT_INDEX).unwrap();
        Arc::new(Self {
            metadata: InodeMeta::new(
                2,
                fs.device.metadata().dev_id,
                InodeMode::IFDIR,
                "/".to_string(),
                "/".to_string(),
                parent,
                None,
                Duration::from_secs(inode_ref.access_time as u64).into(),
                Duration::from_secs(inode_ref.modification_time as u64).into(),
                Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                fs.ext4.ext4_get_inode_size(&inode_ref) as isize,
            ),
            fs: Arc::downgrade(fs),
            inner: Ext4InodeInner::new(),
        })
    }

    fn load_children(self: Arc<Self>, inner: &mut Ext4InodeInner) -> SyscallResult {
        debug!("[ext4] Load children");
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        for dirent in Ext4Dir::open(&self.metadata.path).map_err(i32_to_err)? {
            trace!("[ext4] Dirent: {}", dirent.name);
            if dirent.name == "." || dirent.name == ".." {
                continue;
            }
            let path = append_path(&self.metadata.path, &dirent.name);
            let inode_ref = fs.ext4.ext4_get_inode_ref(dirent.inode).map_err(i32_to_err)?;
            let mode = InodeMode::try_from(inode_ref.mode & 0xf000).unwrap();
            let page_cache = match mode {
                InodeMode::IFREG => Some(PageCache::new()),
                _ => None,
            };
            let inode = Arc::new(Self {
                metadata: InodeMeta::new(
                    dirent.inode as usize,
                    fs.device.metadata().dev_id,
                    mode,
                    dirent.name.clone(),
                    path,
                    Some(self.clone()),
                    page_cache,
                    Duration::from_secs(inode_ref.access_time as u64).into(),
                    Duration::from_secs(inode_ref.modification_time as u64).into(),
                    Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                    fs.ext4.ext4_get_inode_size(&inode_ref) as isize,
                ),
                fs: self.fs.clone(),
                inner: Ext4InodeInner::new(),
            });
            inner.children.insert(dirent.name, inode);
        }
        inner.children_loaded = true;
        Ok(())
    }

    fn check_exists(self: Arc<Self>, inner: &mut Ext4InodeInner, name: &str, should: bool) -> SyscallResult {
        if !inner.children_loaded {
            self.load_children(inner)?;
        }
        if should ^ inner.children.contains_key(name) {
            Err(Errno::EEXIST)
        } else {
            Ok(())
        }
    }
}

impl Inode for Ext4Inode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}

#[async_trait]
impl InodeInternal for Ext4Inode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let mut file = Ext4File::open(&self.metadata.path, O_RDWR).map_err(i32_to_err)?;
        file.seek(offset as i64, SEEK_SET).map_err(i32_to_err)?;
        let read = file.read(buf).map_err(i32_to_err)?;
        Ok(read as isize)
    }

    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let mut file = Ext4File::open(&self.metadata.path, O_RDWR).map_err(i32_to_err)?;
        file.seek(offset as i64, SEEK_SET).map_err(i32_to_err)?;
        let written = file.write(buf).map_err(i32_to_err)?;
        self.metadata.inner.lock().size = file.size() as isize;
        Ok(written as isize)
    }

    async fn truncate_direct(&self, size: isize) -> SyscallResult {
        let old_size = self.metadata.inner.lock().size;
        if old_size < size {
            // lwext4 driver does not extend file size, so we need to write zeros manually
            let buf = vec![0u8; (size - old_size) as usize];
            self.write_direct(&buf, old_size).await?;
        } else {
            let mut file = Ext4File::open(&self.metadata.path, O_RDWR).map_err(i32_to_err)?;
            file.truncate(size as u64).map_err(i32_to_err)?;
        }
        self.metadata.inner.lock().size = size;
        Ok(())
    }

    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let mut inner = self.inner.lock().await;
        if !inner.children_loaded {
            self.clone().load_children(&mut inner)?;
        }
        match inner.children.get(name) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        let mut inner = self.inner.lock().await;
        if !inner.children_loaded {
            self.clone().load_children(&mut inner)?;
        }
        match inner.children.values().nth(idx) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_create(self: Arc<Self>, mode: InodeMode, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        debug!("[ext4] Create file: {}", name);
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        self.clone().check_exists(&mut inner, name, false)?;

        let path = append_path(&self.metadata.path, &name);
        let inode = if mode == InodeMode::IFDIR {
            Ext4Dir::mkdir(&path).map_err(i32_to_err)?;
            Ext4Dir::open(&path).map_err(i32_to_err)?.inode()
        } else {
            Ext4File::open(&path, O_RDWR | O_CREAT).map_err(i32_to_err)?.inode()
        };
        let page_cache = match mode {
            InodeMode::IFREG => Some(PageCache::new()),
            _ => None,
        };
        let inode_ref = fs.ext4.ext4_get_inode_ref(inode).map_err(i32_to_err)?;
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                inode as usize,
                fs.device.metadata().dev_id,
                mode,
                name.to_string(),
                append_path(&self.metadata.path, &name),
                Some(self.clone()),
                page_cache,
                Duration::from_secs(inode_ref.access_time as u64).into(),
                Duration::from_secs(inode_ref.modification_time as u64).into(),
                Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                0,
            ),
            fs: self.fs.clone(),
            inner: Ext4InodeInner::new(),
        });
        inner.children.insert(name.to_string(), inode.clone());
        Ok(inode)
    }

    async fn do_symlink(self: Arc<Self>, name: &str, target: &str) -> SyscallResult {
        debug!("[ext4] Symlink {} -> {}", name, target);
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut inner = self.inner.lock().await;
        self.clone().check_exists(&mut inner, name, false)?;

        let path = append_path(&self.metadata.path, &name);
        Ext4Dir::symlink(&path, target).map_err(i32_to_err)?;
        let inode = fs.ext4.ext4_get_ino_by_path(&path).map_err(i32_to_err)?;
        let inode_ref = fs.ext4.ext4_get_inode_ref(inode).map_err(i32_to_err)?;
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                inode as usize,
                fs.device.metadata().dev_id,
                InodeMode::IFLNK,
                name.to_string(),
                append_path(&self.metadata.path, &name),
                Some(self.clone()),
                None,
                Duration::from_secs(inode_ref.access_time as u64).into(),
                Duration::from_secs(inode_ref.modification_time as u64).into(),
                Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                0,
            ),
            fs: self.fs.clone(),
            inner: Ext4InodeInner::new(),
        });
        inner.children.insert(name.to_string(), inode);
        Ok(())
    }

    async fn do_movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> SyscallResult {
        let mut inner = self.inner.lock().await;
        self.clone().check_exists(&mut inner, name, false)?;

        if let Ok(inode) = inode.downcast_arc::<Ext4Inode>() {
            let old_path = append_path(&inode.metadata().path, &name);
            let new_path = append_path(&self.metadata.path, &name);
            if self.metadata.mode == InodeMode::IFDIR {
                Ext4Dir::movedir(&old_path, &new_path).map_err(i32_to_err)?;
            } else {
                Ext4Dir::movefile(&old_path, &new_path).map_err(i32_to_err)?;
            }
            let inode = Arc::new(Self {
                metadata: InodeMeta::movein(
                    inode.as_ref(),
                    name.to_string(),
                    append_path(&self.metadata.path, &name),
                    self.clone(),
                ),
                fs: self.fs.clone(),
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
        self.clone().check_exists(&mut inner, &target.metadata().name, true)?;

        if target.metadata().mode == InodeMode::IFDIR {
            Ext4Dir::rmdir(&target.metadata().path).map_err(i32_to_err)?;
        } else {
            Ext4Dir::rmfile(&target.metadata().path).map_err(i32_to_err)?;
        }
        inner.children.remove(&target.metadata().name);
        Ok(())
    }

    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        Ext4Dir::readlink(&self.metadata.path).map_err(i32_to_err)
    }
}

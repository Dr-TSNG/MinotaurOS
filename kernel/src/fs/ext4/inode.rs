use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::{format, vec};
use core::cell::SyncUnsafeCell;
use core::time::Duration;
use async_trait::async_trait;
use log::{debug, trace};
use lwext4_rust::Ext4File;
use lwext4_rust::bindings::{EXT4_INODE_ROOT_INDEX, O_CREAT, O_RDWR, SEEK_SET};
use lwext4_rust::dir::{lwext4_movedir, lwext4_movefile, lwext4_readlink, lwext4_rmdir, lwext4_rmfile, lwext4_symlink};
use crate::fs::ext4::Ext4FileSystem;
use crate::fs::ext4::wrapper::i32_to_err;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::page_cache::PageCache;
use crate::result::{Errno, SyscallResult};

pub struct Ext4Inode {
    metadata: InodeMeta,
    fs: Weak<Ext4FileSystem>,
    inner: Arc<SyncUnsafeCell<Ext4InodeInner>>,
}

struct Ext4InodeInner {
    file: Option<Ext4File>,
    children_loaded: bool,
    children: BTreeMap<String, Arc<Ext4Inode>>,
}

// Safety: We use global lock to ensure that only one thread can access the inode at the same time
unsafe impl Send for Ext4InodeInner {}
unsafe impl Sync for Ext4InodeInner {}

impl Ext4InodeInner {
    fn new(file: Option<Ext4File>) -> Arc<SyncUnsafeCell<Self>> {
        Arc::new(SyncUnsafeCell::new(Self {
            file,
            children_loaded: false,
            children: Default::default(),
        }))
    }
}

impl Ext4Inode {
    pub fn root(fs: &Arc<Ext4FileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let file = Ext4File::open_dir("/", false).unwrap();
        let inode_ref = fs.ext4.ext4_get_inode_ref(EXT4_INODE_ROOT_INDEX).unwrap();
        Arc::new(Self {
            metadata: InodeMeta::new(
                2,
                fs.device.metadata().dev_id,
                InodeMode::IFDIR,
                String::new(),
                String::new(),
                parent,
                None,
                Duration::from_secs(inode_ref.access_time as u64).into(),
                Duration::from_secs(inode_ref.modification_time as u64).into(),
                Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                fs.ext4.ext4_get_inode_size(&inode_ref) as isize,
            ),
            fs: Arc::downgrade(fs),
            inner: Ext4InodeInner::new(Some(file)),
        })
    }

    fn inner(&self) -> &mut Ext4InodeInner {
        unsafe { &mut *self.inner.get() }
    }

    fn load_children(self: Arc<Self>) -> SyscallResult {
        debug!("[ext4] Load children");
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut iter = self.inner().file.as_ref().unwrap().iter_dir();
        while let Some(dirent) = iter.next() {
            trace!("[ext4] Dirent: {}", dirent.name);
            if dirent.name == "." || dirent.name == ".." {
                continue;
            }
            let path = format!("{}/{}", self.metadata.path, dirent.name);
            let inode_ref = fs.ext4.ext4_get_inode_ref(dirent.inode).map_err(i32_to_err)?;
            let mode = InodeMode::try_from(inode_ref.mode & 0xf000).unwrap();
            let file = match mode {
                InodeMode::IFDIR => Some(Ext4File::open_dir(&path, false).map_err(i32_to_err)?),
                InodeMode::IFREG => Some(Ext4File::open_file(&path, O_RDWR).map_err(i32_to_err)?),
                _ => None,
            };
            let page_cache = match mode {
                InodeMode::IFREG => Some(PageCache::new()),
                _ => None,
            };
            let inode = Arc::new(Self {
                metadata: InodeMeta::new(
                    dirent.inode as usize,
                    fs.device.metadata().dev_id,
                    mode,
                    dirent.name.to_string(),
                    path,
                    Some(self.clone()),
                    page_cache,
                    Duration::from_secs(inode_ref.access_time as u64).into(),
                    Duration::from_secs(inode_ref.modification_time as u64).into(),
                    Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                    fs.ext4.ext4_get_inode_size(&inode_ref) as isize,
                ),
                fs: self.fs.clone(),
                inner: Ext4InodeInner::new(file),
            });
            self.inner().children.insert(dirent.name.to_string(), inode);
        }
        self.inner().children_loaded = true;
        Ok(())
    }

    fn check_exists(self: Arc<Self>, name: &str, should: bool) -> SyscallResult {
        if !self.inner().children_loaded {
            self.clone().load_children()?;
        }
        if should ^ self.inner().children.contains_key(name) {
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
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        let file = self.inner().file.as_mut().unwrap();
        file.seek(offset as i64, SEEK_SET).map_err(i32_to_err)?;
        let read = file.read(buf).map_err(i32_to_err)?;
        Ok(read as isize)
    }

    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        let file = self.inner().file.as_mut().unwrap();
        file.seek(offset as i64, SEEK_SET).map_err(i32_to_err)?;
        let written = file.write(buf).map_err(i32_to_err)?;
        self.metadata.inner.lock().size = file.size() as isize;
        Ok(written as isize)
    }

    async fn truncate_direct(&self, size: isize) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        let file = self.inner().file.as_mut().unwrap();
        let old_size = self.metadata.inner.lock().size;
        if old_size < size {
            // lwext4 driver does not extend file size, so we need to write zeroes manually
            let buf = vec![0u8; (size - old_size) as usize];
            file.seek(old_size as i64, SEEK_SET).map_err(i32_to_err)?;
            file.write(&buf).map_err(i32_to_err)?;
        } else {
            file.truncate(size as u64).map_err(i32_to_err)?;
        }
        self.metadata.inner.lock().size = size;
        Ok(())
    }

    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        if !self.inner().children_loaded {
            self.clone().load_children()?;
        }
        match self.inner().children.get(name) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        if !self.inner().children_loaded {
            self.clone().load_children()?;
        }
        match self.inner().children.values().nth(idx) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_create(self: Arc<Self>, mode: InodeMode, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        debug!("[ext4] Create file: {}", name);
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        self.clone().check_exists(name, false)?;

        let path = format!("{}/{}", self.metadata.path, name);
        let file = if mode == InodeMode::IFDIR {
            Ext4File::open_dir(&path, true).map_err(i32_to_err)?
        } else {
            Ext4File::open_file(&path, O_RDWR | O_CREAT).map_err(i32_to_err)?
        };
        let page_cache = match mode {
            InodeMode::IFREG => Some(PageCache::new()),
            _ => None,
        };
        let inode_ref = fs.ext4.ext4_get_inode_ref(file.inode()).map_err(i32_to_err)?;
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                file.inode() as usize,
                fs.device.metadata().dev_id,
                mode,
                name.to_string(),
                path,
                Some(self.clone()),
                page_cache,
                Duration::from_secs(inode_ref.access_time as u64).into(),
                Duration::from_secs(inode_ref.modification_time as u64).into(),
                Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                0,
            ),
            fs: self.fs.clone(),
            inner: Ext4InodeInner::new(Some(file)),
        });
        self.inner().children.insert(name.to_string(), inode.clone());
        Ok(inode)
    }

    async fn do_symlink(self: Arc<Self>, name: &str, target: &str) -> SyscallResult {
        debug!("[ext4] Symlink {} -> {}", name, target);
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        self.clone().check_exists(name, false)?;

        let path = format!("{}/{}", self.metadata.path, name);
        lwext4_symlink(&path, target).map_err(i32_to_err)?;
        let inode = fs.ext4.ext4_get_ino_by_path(&path).map_err(i32_to_err)?;
        let inode_ref = fs.ext4.ext4_get_inode_ref(inode).map_err(i32_to_err)?;
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                inode as usize,
                fs.device.metadata().dev_id,
                InodeMode::IFLNK,
                name.to_string(),
                path,
                Some(self.clone()),
                None,
                Duration::from_secs(inode_ref.access_time as u64).into(),
                Duration::from_secs(inode_ref.modification_time as u64).into(),
                Duration::from_secs(inode_ref.change_inode_time as u64).into(),
                0,
            ),
            fs: self.fs.clone(),
            inner: Ext4InodeInner::new(None),
        });
        self.inner().children.insert(name.to_string(), inode);
        Ok(())
    }

    async fn do_movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        self.clone().check_exists(name, false)?;

        if let Ok(inode) = inode.downcast_arc::<Ext4Inode>() {
            let old_path = inode.metadata().path.as_str();
            let new_path = format!("{}/{}", self.metadata.path, name);
            if self.metadata.mode == InodeMode::IFDIR {
                lwext4_movedir(&old_path, &new_path).map_err(i32_to_err)?;
            } else {
                lwext4_movefile(&old_path, &new_path).map_err(i32_to_err)?;
            }
            let inode = Arc::new(Self {
                metadata: InodeMeta::movein(
                    inode.as_ref(),
                    name.to_string(),
                    new_path,
                    self.clone(),
                ),
                fs: self.fs.clone(),
                inner: inode.inner.clone(),
            });
            self.inner().children.insert(name.to_string(), inode);
        } else {
            todo!("Moving across file systems is not supported yet");
        }
        Ok(())
    }

    async fn do_unlink(self: Arc<Self>, target: Arc<dyn Inode>) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        self.clone().check_exists(&target.metadata().name, true)?;

        if target.metadata().mode == InodeMode::IFDIR {
            lwext4_rmdir(&target.metadata().path).map_err(i32_to_err)?;
        } else {
            lwext4_rmfile(&target.metadata().path).map_err(i32_to_err)?;
        }
        self.inner().children.remove(&target.metadata().name);
        Ok(())
    }

    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let _guard = fs.driver_lock.lock().await;
        lwext4_readlink(&self.metadata.path).map_err(i32_to_err)
    }
}

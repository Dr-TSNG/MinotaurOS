use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use core::time::Duration;
use async_trait::async_trait;
use log::{debug, trace};
use lwext4_rust::Ext4File;
use lwext4_rust::bindings::{EXT4_INODE_ROOT_INDEX, O_CREAT, O_RDWR, SEEK_SET};
use lwext4_rust::dir::Ext4Dir;
use lwext4_rust::inode::Ext4InodeRef;
use crate::fs::ext4::Ext4FileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeChild, InodeInternal, InodeMeta, InodeMetaInner};
use crate::fs::page_cache::PageCache;
use crate::fs::path::append_path;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

pub struct Ext4Inode {
    metadata: InodeMeta,
    fs: Weak<Ext4FileSystem>,
    inode_ref: Arc<Mutex<Ext4InodeRef>>,
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
            inode_ref: Arc::new(Mutex::new(inode_ref)),
        })
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
        let mut file = Ext4File::open(&self.metadata.path, O_RDWR).map_err(|e| e.try_into().unwrap())?;
        file.seek(offset as i64, SEEK_SET).map_err(|e| e.try_into().unwrap())?;
        let read = file.read(buf).map_err(|e| e.try_into().unwrap())?;
        Ok(read as isize)
    }

    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let mut file = Ext4File::open(&self.metadata.path, O_RDWR).map_err(|e| e.try_into().unwrap())?;
        file.seek(offset as i64, SEEK_SET).map_err(|e| e.try_into().unwrap())?;
        let written = file.write(buf).map_err(|e| e.try_into().unwrap())?;
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
            let mut file = Ext4File::open(&self.metadata.path, O_RDWR).map_err(|e| e.try_into().unwrap())?;
            file.truncate(size as u64).map_err(|e| e.try_into().unwrap())?;
        }
        self.metadata.inner.lock().size = size;
        Ok(())
    }

    async fn load_children(self: Arc<Self>, inner: &mut InodeMetaInner) -> SyscallResult {
        debug!("[ext4] Load children");
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        for dirent in Ext4Dir::open(&self.metadata.path).map_err(|e| e.try_into().unwrap())? {
            trace!("[ext4] Dirent: {}", dirent.name);
            if dirent.name == "." || dirent.name == ".." {
                continue;
            }
            let path = append_path(&self.metadata.path, &dirent.name);
            let inode_ref = fs.ext4.ext4_get_inode_ref(dirent.inode).map_err(|e| e.try_into().unwrap())?;
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
                inode_ref: Arc::new(Mutex::new(inode_ref)),
            });
            let child = InodeChild::new(inode, Box::new(()));
            inner.children.insert(dirent.name, child);
        }
        inner.children_loaded = true;
        Ok(())
    }

    async fn do_create(self: Arc<Self>, mode: InodeMode, name: &str) -> SyscallResult<InodeChild> {
        debug!("[ext4] Create file: {}", name);
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let path = append_path(&self.metadata.path, &name);
        let inode = if mode == InodeMode::IFDIR {
            Ext4Dir::mkdir(&path).map_err(|e| e.try_into().unwrap())?;
            Ext4Dir::open(&path).map_err(|e| e.try_into().unwrap())?.inode()
        } else {
            Ext4File::open(&path, O_RDWR | O_CREAT).map_err(|e| e.try_into().unwrap())?.inode()
        };
        let page_cache = match mode {
            InodeMode::IFREG => Some(PageCache::new()),
            _ => None,
        };
        let inode_ref = fs.ext4.ext4_get_inode_ref(inode).map_err(|e| e.try_into().unwrap())?;
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
            inode_ref: Arc::new(Mutex::new(inode_ref)),
        });
        Ok(InodeChild::new(inode, Box::new(())))
    }

    async fn do_movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> SyscallResult<InodeChild> {
        if let Ok(inode) = inode.downcast_arc::<Ext4Inode>() {
            let old_path = append_path(&inode.metadata().path, &name);
            let new_path = append_path(&self.metadata.path, &name);
            if self.metadata.mode == InodeMode::IFDIR {
                Ext4Dir::movedir(&old_path, &new_path).map_err(|e| e.try_into().unwrap())?;
            } else {
                Ext4Dir::movefile(&old_path, &new_path).map_err(|e| e.try_into().unwrap())?;
            }
            let inode = Arc::new(Self {
                metadata: InodeMeta::movein(
                    inode.as_ref(),
                    name.to_string(),
                    append_path(&self.metadata.path, &name),
                    self.clone(),
                ),
                fs: self.fs.clone(),
                inode_ref: inode.inode_ref.clone(),
            });
            Ok(InodeChild::new(inode, Box::new(())))
        } else {
            todo!("Moving across file systems is not supported yet");
        }
    }

    async fn do_unlink(self: Arc<Self>, target: &InodeChild) -> SyscallResult {
        if target.inode.metadata().mode == InodeMode::IFDIR {
            Ext4Dir::rmdir(&target.inode.metadata().path).map_err(|e| e.try_into().unwrap())?;
        } else {
            Ext4Dir::rmfile(&target.inode.metadata().path).map_err(|e| e.try_into().unwrap())?;
        }
        Ok(())
    }

    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        Ext4Dir::readlink(&self.metadata.path).map_err(|e| e.try_into().unwrap())
    }
}

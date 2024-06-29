use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::time::Duration;
use async_trait::async_trait;
use crate::fs::ext4::Ext4FileSystem;
use crate::fs::ext4::wrapper::map_errno;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeChild, InodeInternal, InodeMeta, InodeMetaInner};
use crate::fs::page_cache::PageCache;
use crate::result::{Errno, SyscallResult};

pub struct Ext4Inode {
    metadata: InodeMeta,
    fs: Weak<Ext4FileSystem>,
}

impl Ext4Inode {
    pub fn root(fs: &Arc<Ext4FileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let ctx = fs.ext4.get_inode_ref(2);
        Arc::new(Self {
            metadata: InodeMeta::new(
                2,
                fs.device.metadata().dev_id,
                InodeMode::IFDIR,
                "/".to_string(),
                "/".to_string(),
                parent,
                None,
                Duration::from_nanos(ctx.inode.atime as u64).into(),
                Duration::from_nanos(ctx.inode.mtime as u64).into(),
                Duration::from_nanos(ctx.inode.ctime as u64).into(),
                ctx.inode.size as isize,
            ),
            fs: Arc::downgrade(fs),
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
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        fs.ext4
            .read_at(self.metadata.ino as u32, offset as usize, buf)
            .map(|n| n as isize)
            .map_err(map_errno)
    }

    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        fs.ext4
            .write_at(self.metadata.ino as u32, offset as usize, buf)
            .map(|n| n as isize)
            .map_err(map_errno)
    }

    async fn truncate_direct(&self, size: isize) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        let mut ctx = fs.ext4.get_inode_ref(self.metadata.ino as u32);
        fs.ext4.truncate_inode(&mut ctx, size as u64).map_err(map_errno)?;
        self.metadata.inner.lock().size = size;
        Ok(())
    }

    async fn load_children(self: Arc<Self>, inner: &mut InodeMetaInner) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        for entry in fs.ext4.dir_get_entries(self.metadata.ino as u32) {
            let ctx = fs.ext4.get_inode_ref(entry.inode);
            let mode = InodeMode::try_from((ctx.inode.mode as u32) << 16).unwrap();
            let page_cache = match mode {
                InodeMode::IFREG => Some(PageCache::new()),
                _ => None,
            };
            let inode = Arc::new(Self {
                metadata: InodeMeta::new(
                    entry.inode as usize,
                    fs.device.metadata().dev_id,
                    mode,
                    entry.get_name(),
                    format!("{}/{}", self.metadata.path, entry.get_name()),
                    Some(self.clone()),
                    page_cache,
                    Duration::from_nanos(ctx.inode.atime as u64).into(),
                    Duration::from_nanos(ctx.inode.mtime as u64).into(),
                    Duration::from_nanos(ctx.inode.ctime as u64).into(),
                    ctx.inode.size as isize,
                ),
                fs: self.fs.clone(),
            });
            let child = InodeChild::new(inode, Box::new(()));
            inner.children.insert(entry.get_name(), child);
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
        let ctx = fs.ext4
            .create(self.metadata.ino as u32, name, ((mode as u32) >> 16) as u16)
            .map_err(map_errno)?;
        let page_cache = match mode {
            InodeMode::IFREG => Some(PageCache::new()),
            _ => None,
        };
        let inode = Arc::new(Self {
            metadata: InodeMeta::new(
                ctx.inode_num as usize,
                fs.device.metadata().dev_id,
                mode,
                name.to_string(),
                format!("{}/{}", self.metadata.path, name),
                Some(self.clone()),
                page_cache,
                Duration::from_nanos(ctx.inode.atime as u64).into(),
                Duration::from_nanos(ctx.inode.mtime as u64).into(),
                Duration::from_nanos(ctx.inode.ctime as u64).into(),
                ctx.inode.size as isize,
            ),
            fs: self.fs.clone(),
        });
        Ok(InodeChild::new(inode, Box::new(())))
    }

    async fn do_movein(
        self: Arc<Self>,
        inner: &mut InodeMetaInner,
        name: &str,
        inode: Arc<dyn Inode>,
    ) -> SyscallResult<InodeChild> {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        if let Ok(inode) = inode.downcast_arc::<Ext4Inode>() {
            let mut parent_ctx = fs.ext4.get_inode_ref(self.metadata.ino as u32);
            let child_ctx = fs.ext4.get_inode_ref(inode.metadata.ino as u32);
            fs.ext4.dir_remove_entry(&mut parent_ctx, name).map_err(map_errno)?;
            fs.ext4.dir_add_entry(&mut parent_ctx, &child_ctx, name).map_err(map_errno)?;
            let inode = Arc::new(Self {
                metadata: InodeMeta::movein(
                    inode.as_ref(),
                    name.to_string(),
                    format!("{}/{}", self.metadata.path, name),
                    self.clone(),
                ),
                fs: self.fs.clone(),
            });
            Ok(InodeChild::new(inode, Box::new(())))
        } else {
            todo!("Moving across file systems is not supported yet");
        }
    }

    async fn do_unlink(self: Arc<Self>, inner: &mut InodeMetaInner, name: &str) -> SyscallResult {
        let fs = self.fs.upgrade().ok_or(Errno::EIO)?;
        fs.ext4.dir_remove(self.metadata.ino as u32, name).map_err(map_errno)?;
        Ok(())
    }
}

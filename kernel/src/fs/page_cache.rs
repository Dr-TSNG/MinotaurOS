use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use crate::arch::{PAGE_SIZE, PhysPageNum};
use crate::fs::inode::{DummyInode, Inode};
use crate::mm::allocator::{alloc_user_frames, UserFrameTracker};
use crate::result::SyscallResult;
use crate::sched::schedule;
use crate::sync::mutex::ReMutex;

pub struct PageCache(ReMutex<PageCacheInner>);

struct PageCacheInner {
    inode: Weak<dyn Inode>,
    file_size: usize,
    deleted: bool,
    pages: BTreeMap<usize, Page>,
}

struct Page {
    frame: UserFrameTracker,
    dirty: bool,
}

impl Page {
    fn new(frame: UserFrameTracker) -> Self {
        Self { frame, dirty: false }
    }
}

impl PageCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(ReMutex::new(PageCacheInner {
            inode: Weak::<DummyInode>::new(),
            file_size: 0,
            deleted: false,
            pages: BTreeMap::new(),
        })))
    }

    pub fn ppn_of(&self, page_num: usize) -> Option<PhysPageNum> {
        self.0.lock().pages.get(&page_num).map(|page| page.frame.ppn)
    }

    pub fn set_inode(&self, inode: Arc<dyn Inode>) {
        let mut inner = self.0.lock();
        inner.inode = Arc::downgrade(&inode);
        inner.file_size = inode.metadata().inner.lock().size as usize;
    }

    pub fn set_deleted(&self) {
        self.0.lock().deleted = true;
    }

    pub async fn load(&self, page_num: usize) -> SyscallResult {
        let mut inner = self.0.lock();
        if inner.pages.get(&page_num).is_none() {
            let frame = alloc_user_frames(1)?;
            let page_buf = frame.ppn.byte_array();
            if !inner.deleted && let Some(inode) = inner.inode.upgrade() {
                inode.read_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
            }
            inner.pages.insert(page_num, Page::new(frame));
        }
        Ok(())
    }

    pub async fn read(&self, mut buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let mut offset = offset as usize;
        let file_size = self.0.lock().file_size;
        if offset >= file_size {
            return Ok(0);
        }
        if offset + buf.len() > file_size {
            buf = &mut buf[..file_size - offset];
        }
        let page_start = offset / PAGE_SIZE;
        let page_end = (offset + buf.len()).div_ceil(PAGE_SIZE);

        let mut cur = 0;
        offset = offset % PAGE_SIZE;
        for page_num in page_start..page_end {
            schedule().await;
            let mut inner = self.0.lock();
            let page = match inner.pages.get(&page_num) {
                Some(frame) => frame,
                None => {
                    let frame = alloc_user_frames(1)?;
                    let page_buf = frame.ppn.byte_array();
                    if !inner.deleted && let Some(inode) = inner.inode.upgrade() {
                        inode.read_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
                    }
                    inner.pages.entry(page_num).or_insert(Page::new(frame))
                }
            };
            let page_buf = page.frame.ppn.byte_array();
            drop(inner);
            let len = min(buf.len() - cur, PAGE_SIZE - offset);
            buf[cur..cur + len].copy_from_slice(&page_buf[offset..offset + len]);
            cur += len;
            offset = 0;
        }
        Ok(cur as isize)
    }

    pub async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let mut offset = offset as usize;
        let file_size = self.0.lock().file_size;
        if offset + buf.len() > file_size {
            self.truncate((offset + buf.len()) as isize).await?;
        }
        let page_start = offset / PAGE_SIZE;
        let page_end = (offset + buf.len()).div_ceil(PAGE_SIZE);

        let mut cur = 0;
        offset %= PAGE_SIZE;
        for page_num in page_start..page_end {
            schedule().await;
            let mut inner = self.0.lock();
            let page = match inner.pages.get_mut(&page_num) {
                Some(page) => page,
                None => {
                    let frame = alloc_user_frames(1)?;
                    inner.pages.entry(page_num).or_insert(Page::new(frame))
                }
            };
            let page_buf = page.frame.ppn.byte_array();
            page.dirty = true;
            drop(inner);
            let len = min(buf.len() - cur, PAGE_SIZE - offset);
            page_buf[offset..offset + len].copy_from_slice(&buf[cur..cur + len]);
            cur += len;
            offset = 0;
        }
        Ok(cur as isize)
    }

    pub async fn truncate(&self, size: isize) -> SyscallResult {
        let mut inner = self.0.lock();
        inner.file_size = size as usize;
        if inner.deleted {
            if let Some(inode) = inner.inode.upgrade() {
                inode.metadata().inner.lock().size = size;
            }
        } else {
            if let Some(inode) = inner.inode.upgrade() {
                inode.truncate_direct(size).await?;
            }
        }

        let page_num = size as usize / PAGE_SIZE;
        inner.pages.retain(|&k, _| k <= page_num);
        if let Some(page) = inner.pages.get_mut(&page_num) {
            let page_buf = page.frame.ppn.byte_array();
            page_buf[size as usize % PAGE_SIZE..].fill(0);
            page.dirty = true;
        }
        Ok(())
    }

    pub async fn sync(&self, offset: usize, len: usize) -> SyscallResult {
        let mut inner = self.0.lock();
        let inode = match inner.inode.upgrade() {
            Some(inode) => inode,
            None => return Ok(()),
        };
        if inner.deleted {
            return Ok(());
        }

        let file_size = inode.metadata().inner.lock().size as usize;
        let page_start = offset / PAGE_SIZE;
        let page_end = min(file_size, offset + len).div_ceil(PAGE_SIZE);
        for (page_num, page) in inner.pages.range_mut(page_start..page_end) {
            if page.dirty {
                let mut page_buf = page.frame.ppn.byte_array();
                if *page_num == file_size / PAGE_SIZE {
                    page_buf = &mut page_buf[..file_size % PAGE_SIZE];
                }
                inode.write_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
                page.dirty = false;
            }
        }
        Ok(())
    }

    pub async fn sync_all(&self) -> SyscallResult {
        self.sync(0, usize::MAX).await
    }
}

impl Drop for PageCacheInner {
    fn drop(&mut self) {
        if self.inode.strong_count() != 0 {
            for page in self.pages.values() {
                if page.dirty {
                    panic!("Dirty page dropped");
                }
            }
        }
    }
}

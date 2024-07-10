use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::{PAGE_SIZE, PhysPageNum};
use crate::fs::inode::Inode;
use crate::mm::allocator::{alloc_user_frames, UserFrameTracker};
use crate::result::SyscallResult;
use crate::sync::mutex::ReMutex;

static HOLDERS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

pub struct PageCache(ReMutex<PageCacheInner>);

struct PageCacheInner {
    deleted: bool,
    pages: BTreeMap<usize, Page>,
}

struct Page {
    frame: UserFrameTracker,
    dirty: bool,
    refs: usize,
}

impl Page {
    fn new(frame: UserFrameTracker) -> Self {
        ALLOCATED.fetch_add(1, Ordering::Relaxed);
        Self { frame, dirty: false, refs: 0 }
    }
}

impl PageCache {
    pub fn holders() -> usize {
        HOLDERS.load(Ordering::Relaxed)
    }

    pub fn allocated() -> usize {
        ALLOCATED.load(Ordering::Relaxed)
    }

    pub fn new() -> Arc<Self> {
        HOLDERS.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self(ReMutex::new(PageCacheInner {
            deleted: false,
            pages: BTreeMap::new(),
        })))
    }

    pub fn ppn_of(&self, page_num: usize) -> Option<PhysPageNum> {
        self.0.lock().pages.get(&page_num).map(|page| page.frame.ppn)
    }

    pub fn set_deleted(&self) {
        self.0.lock().deleted = true;
    }

    pub async fn load(&self, inode: &dyn Inode, page_num: usize) -> SyscallResult {
        let mut inner = self.0.lock();
        if inner.pages.get(&page_num).is_none() {
            let frame = alloc_user_frames(1)?;
            let page_buf = frame.ppn.byte_array();
            if !inner.deleted {
                inode.read_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
            }
            inner.pages.insert(page_num, Page::new(frame));
        }
        inner.pages.get_mut(&page_num).unwrap().refs += 1;
        Ok(())
    }

    pub async fn read(&self, inode: &dyn Inode, mut buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let mut offset = offset as usize;
        let file_size = inode.metadata().inner.lock().size as usize;
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
        let mut inner = self.0.lock();
        for page_num in page_start..page_end {
            let page = match inner.pages.get(&page_num) {
                Some(frame) => frame,
                None => {
                    let frame = alloc_user_frames(1)?;
                    let page_buf = frame.ppn.byte_array();
                    if !inner.deleted {
                        inode.read_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
                    }
                    inner.pages.insert(page_num, Page::new(frame));
                    inner.pages.get(&page_num).unwrap()
                }
            };
            let page_buf = page.frame.ppn.byte_array();
            let len = min(buf.len() - cur, PAGE_SIZE - offset);
            buf[cur..cur + len].copy_from_slice(&page_buf[offset..offset + len]);
            cur += len;
            offset = 0;
        }
        Ok(cur as isize)
    }

    pub async fn write(&self, inode: &dyn Inode, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let mut offset = offset as usize;
        let file_size = inode.metadata().inner.lock().size as usize;
        if offset + buf.len() > file_size {
            self.truncate(inode, (offset + buf.len()) as isize).await?;
        }
        let page_start = offset / PAGE_SIZE;
        let page_end = (offset + buf.len()).div_ceil(PAGE_SIZE);

        let mut cur = 0;
        offset %= PAGE_SIZE;
        let mut inner = self.0.lock();
        for page_num in page_start..page_end {
            let page = match inner.pages.get_mut(&page_num) {
                Some(page) => page,
                None => {
                    let frame = alloc_user_frames(1)?;
                    inner.pages.insert(page_num, Page::new(frame));
                    inner.pages.get_mut(&page_num).unwrap()
                }
            };
            let page_buf = page.frame.ppn.byte_array();
            let len = min(buf.len() - cur, PAGE_SIZE - offset);
            page_buf[offset..offset + len].copy_from_slice(&buf[cur..cur + len]);
            page.dirty = true;
            cur += len;
            offset = 0;
        }
        Ok(cur as isize)
    }

    pub async fn truncate(&self, inode: &dyn Inode, size: isize) -> SyscallResult {
        let mut inner = self.0.lock();
        if inner.deleted {
            inode.metadata().inner.lock().size = size;
        } else {
            inode.truncate_direct(size).await?;
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

    pub async fn sync(&self, inode: &dyn Inode, offset: usize, len: usize, dec_ref: bool) -> SyscallResult<()> {
        let mut inner = self.0.lock();
        if inner.deleted {
            return Ok(());
        }

        let file_size = inode.metadata().inner.lock().size as usize;
        let page_start = offset / PAGE_SIZE;
        let page_end = min(file_size, offset + len).div_ceil(PAGE_SIZE);
        let mut removable = vec![];
        for (page_num, page) in inner.pages.range_mut(page_start..page_end) {
            if page.dirty {
                let mut page_buf = page.frame.ppn.byte_array();
                if *page_num == file_size / PAGE_SIZE {
                    page_buf = &mut page_buf[..file_size % PAGE_SIZE];
                }
                inode.write_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
                page.dirty = false;
            }
            if dec_ref {
                page.refs -= 1;
            }
            if page.refs == 0 {
                removable.push(*page_num);
            }
        }
        for page_num in removable {
            inner.pages.remove(&page_num);
        }
        Ok(())
    }

    pub async fn sync_all(&self, inode: &dyn Inode, dec_ref: bool) -> SyscallResult {
        self.sync(inode, 0, usize::MAX, dec_ref).await?;
        Ok(())
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        ALLOCATED.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for PageCacheInner {
    fn drop(&mut self) {
        HOLDERS.fetch_sub(1, Ordering::Relaxed);
        if !self.deleted {
            for page in self.pages.values() {
                if page.dirty {
                    panic!("Dirty page dropped");
                }
            }
        }
    }
}

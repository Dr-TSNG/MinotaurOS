use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use crate::arch::{PAGE_SIZE, PhysPageNum};
use crate::fs::inode::Inode;
use crate::mm::allocator::{alloc_user_frames, UserFrameTracker};
use crate::result::SyscallResult;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

pub struct PageCache {
    inode: LateInit<Weak<dyn Inode>>,
    pages: Mutex<BTreeMap<usize, Page>>,
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
        let page_cache = Self {
            inode: LateInit::new(),
            pages: Mutex::new(BTreeMap::new()),
        };
        Arc::new(page_cache)
    }

    pub fn set_inode(&self, inode: Arc<dyn Inode>) {
        self.inode.init(Arc::downgrade(&inode));
    }

    pub fn ppn_of(&self, page_num: usize) -> Option<PhysPageNum> {
        let pages = self.pages.lock();
        pages.get(&page_num).map(|page| page.frame.ppn)
    }

    pub async fn load(&self, page_num: usize) -> SyscallResult {
        let mut pages = self.pages.lock();
        if pages.get(&page_num).is_none() {
            let inode = self.inode.upgrade().unwrap();
            let frame = alloc_user_frames(1)?;
            let page_buf = frame.ppn.byte_array();
            inode.read_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
            pages.insert(page_num, Page::new(frame));
        }
        Ok(())
    }

    pub async fn read(&self, mut buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let mut offset = offset as usize;
        let file_size = self.inode.upgrade().unwrap().metadata().inner.lock().size as usize;
        if offset >= file_size {
            return Ok(0);
        }
        if offset + buf.len() > file_size {
            buf = &mut buf[..file_size - offset];
        }
        let page_start = offset / PAGE_SIZE;
        let page_end = (offset + buf.len()).div_ceil(PAGE_SIZE);
        let mut pages = self.pages.lock();

        let mut cur = 0;
        offset = offset % PAGE_SIZE;
        for page_num in page_start..page_end {
            let page = match pages.get(&page_num) {
                Some(frame) => frame,
                None => {
                    let inode = self.inode.upgrade().unwrap();
                    let frame = alloc_user_frames(1)?;
                    let page_buf = frame.ppn.byte_array();
                    inode.read_direct(page_buf, (page_num * PAGE_SIZE) as isize).await?;
                    pages.insert(page_num, Page::new(frame));
                    pages.get(&page_num).unwrap()
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

    pub async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let mut offset = offset as usize;
        let file_size = self.inode.upgrade().unwrap().metadata().inner.lock().size as usize;
        if offset + buf.len() > file_size {
            self.truncate((offset + buf.len()) as isize).await?;
        }
        let page_start = offset / PAGE_SIZE;
        let page_end = (offset + buf.len()).div_ceil(PAGE_SIZE);
        let mut pages = self.pages.lock();

        let mut cur = 0;
        offset %= PAGE_SIZE;
        for page_num in page_start..page_end {
            let page = match pages.get_mut(&page_num) {
                Some(page) => page,
                None => {
                    let frame = alloc_user_frames(1)?;
                    pages.insert(page_num, Page::new(frame));
                    pages.get_mut(&page_num).unwrap()
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

    pub async fn truncate(&self, size: isize) -> SyscallResult {
        let inode = self.inode.upgrade().unwrap();
        inode.truncate_direct(size).await?;
        let mut pages = self.pages.lock();

        let page_num = size as usize / PAGE_SIZE;
        pages.retain(|&k, _| k < page_num);
        if let Some(page) = pages.get_mut(&page_num) {
            let page_buf = page.frame.ppn.byte_array();
            page_buf[size as usize % PAGE_SIZE..].fill(0);
            page.dirty = true;
        }
        Ok(())
    }

    pub async fn sync(&self, offset: usize, len: usize) -> SyscallResult<()> {
        let file_size = self.inode.upgrade().unwrap().metadata().inner.lock().size as usize;
        let page_start = offset / PAGE_SIZE;
        let page_end = min(file_size, offset + len).div_ceil(PAGE_SIZE);
        let mut pages = self.pages.lock();
        for (page_num, page) in pages.range_mut(page_start..page_end) {
            if page.dirty {
                let inode = self.inode.upgrade().unwrap();
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
        self.sync(0, usize::MAX).await?;
        Ok(())
    }
}

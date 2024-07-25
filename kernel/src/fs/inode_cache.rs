use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::num::NonZeroUsize;
use lru::LruCache;
use crate::fs::inode::Inode;
use crate::sync::mutex::Mutex;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
struct HashKey {
    pub parent_key: usize,
    pub subpath: Cow<'static, str>,
}

impl HashKey {
    fn new(parent_key: usize, subpath: Cow<'static, str>) -> Self {
        Self {
            parent_key,
            subpath,
        }
    }
}

pub struct InodeCache(Mutex<LruCache<HashKey, Weak<dyn Inode>>>);

impl InodeCache {
    pub fn new(size: usize) -> Self {
        Self(Mutex::new(LruCache::new(NonZeroUsize::new(size).unwrap())))
    }

    pub fn insert(
        &self,
        parent: Option<&Arc<dyn Inode>>,
        subpath: String,
        inode: &Arc<dyn Inode>,
    ) {
        let mut cache = self.0.lock();
        let parent_key = parent.map(|p| p.metadata().key).unwrap_or(0);
        let hash_key = HashKey::new(parent_key, Cow::Owned(subpath));
        cache.push(hash_key, Arc::downgrade(inode));
    }

    pub fn get(
        &self,
        parent: Option<&Arc<dyn Inode>>,
        subpath: &str,
    ) -> Option<Arc<dyn Inode>> {
        let mut cache = self.0.lock();
        let parent_key = parent.map(|p| p.metadata().key).unwrap_or(0);
        let subpath: &'static str = unsafe { core::mem::transmute(subpath) };
        let hash_key = HashKey::new(parent_key, Cow::Borrowed(subpath));
        cache.get(&hash_key).and_then(|inode| inode.upgrade())
    }

    pub fn invalidate(&self) {
        let mut cache = self.0.lock();
        cache.clear();
    }
}

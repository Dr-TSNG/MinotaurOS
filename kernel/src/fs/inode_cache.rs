use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use hashbrown::HashMap;
use crate::fs::inode::Inode;
use crate::sync::mutex::Mutex;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
struct HashKey<'a> {
    pub parent_key: usize,
    pub subpath: Cow<'a, str>,
}

impl<'a> HashKey<'a> {
    fn new(parent_key: usize, subpath: Cow<'a, str>) -> Self {
        Self {
            parent_key,
            subpath,
        }
    }
}

pub struct InodeCache(Mutex<HashMap<HashKey<'static>, Weak<dyn Inode>>>);

impl InodeCache {
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
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
        cache.insert(hash_key, Arc::downgrade(inode));
    }

    pub fn get(
        &self,
        parent: Option<&Arc<dyn Inode>>,
        subpath: &str,
    ) -> Option<Arc<dyn Inode>> {
        let cache = self.0.lock();
        let parent_key = parent.map(|p| p.metadata().key).unwrap_or(0);
        let hash_key = HashKey::new(parent_key, Cow::Borrowed(subpath));
        cache.get(&hash_key).and_then(|inode| inode.upgrade())
    }

    pub fn invalidate(&self) {
        let mut cache = self.0.lock();
        cache.clear();
    }
}

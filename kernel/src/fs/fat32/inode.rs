use crate::fs::inode::{Inode, InodeMeta};

struct Fat32Inode {
    metadata: InodeMeta,
}

impl Inode for Fat32Inode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }
}

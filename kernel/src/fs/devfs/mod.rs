use crate::fs::file_system::FileSystemMeta;

pub mod tty;

pub struct DevFileSystem {
    metadata: FileSystemMeta,
}

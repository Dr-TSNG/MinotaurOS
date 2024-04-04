use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use log::{debug, info};
use crate::fs::fd::FdNum;
use crate::fs::ffi::AT_FDCWD;
use crate::fs::inode::Inode;
use crate::process::ProcessInner;
use crate::result::{Errno, SyscallResult};

#[macro_export]
macro_rules! split_path {
    ($path:expr) => {
        $path.split('/').filter(|s| !s.is_empty() && *s != ".")
    };
}

pub async fn resolve_path(proc_inner: &ProcessInner, dirfd: FdNum, path: &str) -> SyscallResult<Arc<dyn Inode>> {
    let path = normalize_path(path);
    let path = path.as_ref();
    debug!("[resolve_path] dirfd: {}, path: {:?}", dirfd, path);
    if is_absolute_path(path) {
        let (fs, path) = proc_inner.mnt_ns.resolve(path)?;
        fs.lookup_from_root(path).await
    } else {
        let inode = match dirfd {
            AT_FDCWD => {
                let (fs, path) = proc_inner.mnt_ns.resolve(&proc_inner.cwd)?;
                fs.lookup_from_root(path).await?
            },
            _ => {
                let fd_impl = proc_inner.fd_table.get(dirfd)?;
                fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?
            }
        };
        inode.lookup_relative(path).await
    }
}

pub fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
}

fn normalize_path(path: &str) -> String {
    let mut result = vec![];
    let mut parents = 0;

    for name in split_path!(path) {
        match name {
            ".." => {
                if result.is_empty() {
                    parents += 1;
                } else {
                    result.pop();
                }
            }
            _ => result.push(name),
        }
    }

    let mut normalized = String::new();
    if path.starts_with('/') {
        normalized.push('/');
    } else {
        for _ in 0..parents {
            normalized.push_str("../");
        }
    }

    normalized.push_str(&result.join("/"));
    if normalized.ends_with("../") {
        normalized.pop();
    }
    if normalized.is_empty() {
        normalized.push('.');
    }
    normalized
}

pub fn path_test() {
    assert_eq!(normalize_path(""), ".");
    assert_eq!(normalize_path("/a/.//."), "/a");
    assert_eq!(normalize_path("/a/b/../c"), "/a/c");
    assert_eq!(normalize_path("/a/b/../.."), "/");
    assert_eq!(normalize_path("/a/b/../../.."), "/");
    assert_eq!(normalize_path("/a/b/../../../c"), "/c");
    assert_eq!(normalize_path("../a"), "../a");
    assert_eq!(normalize_path("../../"), "../..");
    assert_eq!(normalize_path("../../a/.."), "../..");
    info!("Path test passed");
}

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use log::{debug, info};
use crate::fs::fd::FdNum;
use crate::fs::ffi::AT_FDCWD;
use crate::fs::inode::Inode;
use crate::process::thread::Audit;
use crate::processor::current_process;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};

#[macro_export]
macro_rules! split_path {
    ($path:expr) => {
        $path.split('/').filter(|s| !s.is_empty() && *s != ".")
    };
}

/// SAFETY: 调用该函数前必须 drop 所有的 Process.inner
pub async fn resolve_path(
    dirfd: FdNum,
    path: &str,
    follow_link: bool,
    audit: &Audit,
) -> SyscallResult<Arc<dyn Inode>> {
    assert_ne!(current_process().inner.locked_by(), local_hart().id);
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let should_be_dir = path.ends_with('/');
    let proc_inner = current_process().inner.lock();
    let path = normalize_path(path);
    debug!("[resolve_path] dirfd: {}, path: {:?}", dirfd, path);

    let mnt_ns = proc_inner.mnt_ns.clone();
    let inode = if is_absolute_path(&path) {
        drop(proc_inner);
        mnt_ns.lookup_absolute(&path, follow_link, audit).await?
    } else if dirfd == AT_FDCWD {
        let cwd = proc_inner.cwd.clone();
        drop(proc_inner);
        let inode = mnt_ns.lookup_absolute(&cwd, follow_link, audit).await?;
        mnt_ns.lookup_relative(inode, &path, follow_link, audit).await?
    } else {
        let fd_impl = proc_inner.fd_table.get(dirfd)?;
        let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
        drop(proc_inner);
        mnt_ns.lookup_relative(inode, &path, follow_link, audit).await?
    };
    if should_be_dir && !inode.metadata().ifmt.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    Ok(inode)
}

pub fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
}

pub fn split_last_path(path: &str) -> Option<(String, String)> {
    let mut path = normalize_path(path);
    if path == "/" {
        return None;
    }
    match path.rfind('/') {
        Some(pos) => {
            let name = path.split_off(pos + 1);
            Some((path, name))
        }
        None => Some((".".to_string(), path)),
    }
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

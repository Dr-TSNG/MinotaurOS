use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::{format, vec};
use log::{debug, info};
use crate::fs::fd::FdNum;
use crate::fs::ffi::AT_FDCWD;
use crate::fs::inode::Inode;
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
) -> SyscallResult<Arc<dyn Inode>> {
    assert_ne!(current_process().inner.locked_by(), local_hart().id);
    let proc_inner = current_process().inner.lock();

    let mut path = normalize_path(path);
    debug!("[resolve_path] dirfd: {}, path: {:?}", dirfd, path);

    // TODO: Remove the hack
    if path == "/proc/self/exe" {
        path = proc_inner.exe.clone();
    }

    let mnt_ns = proc_inner.mnt_ns.clone();
    if is_absolute_path(&path) {
        drop(proc_inner);
        match mnt_ns.inode_cache.get(None, &path) {
            Some(cached) => Ok(cached),
            None => mnt_ns.lookup_absolute(&path, follow_link).await,
        }
    } else if dirfd == AT_FDCWD {
        let cwd = proc_inner.cwd.clone();
        drop(proc_inner);
        let inode = match mnt_ns.inode_cache.get(None, &cwd) {
            Some(cached) => cached,
            None => mnt_ns.lookup_absolute(&cwd, follow_link).await?,
        };
        match mnt_ns.inode_cache.get(Some(&inode), &path) {
            Some(cached) => Ok(cached),
            None => mnt_ns.lookup_relative(inode, &path, follow_link).await,
        }
    } else {
        let fd_impl = proc_inner.fd_table.get(dirfd)?;
        let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
        drop(proc_inner);
        match mnt_ns.inode_cache.get(Some(&inode), &path) {
            Some(cached) => Ok(cached),
            None => mnt_ns.lookup_relative(inode, &path, follow_link).await,
        }
    }
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

pub fn append_path(base: &str, path: &str) -> String {
    if base.ends_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
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

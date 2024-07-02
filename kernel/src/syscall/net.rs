use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::OpenFlags;
use crate::net::{
    listen_endpoint, make_unix_socket_pair, Socket, SocketAddressV4, SocketType, TCP_MSS,
};
use crate::processor::current_process;
use crate::result::Errno::{ENOSTR, ENOTSOCK};
use crate::result::{Errno, SyscallResult};
use core::net::SocketAddrV4;
use log::{debug, info, error};
use smoltcp::wire::IpListenEndpoint;

/// socket level
const SOL_SOCKET: u32 = 1;
const SOL_TCP: u32 = 6;

/// socket Options
const TCP_NODELAY: u32 = 1;
const TCP_MAXSEG: u32 = 2;
#[allow(unused)]
const TCP_INFO: u32 = 11;
const TCP_CONGESTION: u32 = 13;
const SO_SNDBUF: u32 = 7;
const SO_RCVBUF: u32 = 8;
const SO_KEEPALIVE: u32 = 9;

pub fn sys_socket(domain: u32, socket_type: u32, protocol: u32) -> SyscallResult<usize> {
    let sockfd = <dyn Socket>::alloc(domain, socket_type)?;
    info!("[sys_socket] new sockfd: {}", sockfd);
    Ok(sockfd)
}
pub fn sys_bind(sockfd: u32, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    /*
        检查一下从addr到addr+addrlen是否满足User Readable
    */
    let addr_buf = unsafe { core::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
    let socket = current_process()
        .inner
        .lock()
        .socket_table
        .get_ref(sockfd as i32)
        .cloned();
    if socket.is_none() {
        return Err(ENOTSOCK);
    }
    let socket = socket.unwrap();
    let endpoint = listen_endpoint(addr_buf)?;
    match socket.socket_type() {
        SocketType::SOCK_STREAM => socket.bind(endpoint),
        SocketType::SOCK_DGRAM => {
            let mut proc = current_process().inner.lock();
            let res = proc.socket_table.can_bind(endpoint);
            if res.is_none() {
                info!("[sys_bind] not find port exist");
                socket.bind(endpoint)
            } else {
                let (_, sock) = res.unwrap();
                proc.socket_table.insert(sockfd as FdNum, sock.clone());
                let old = proc.fd_table.take(sockfd as FdNum).unwrap().unwrap();
                proc.fd_table
                    .insert(sockfd as FdNum, FileDescriptor::new(sock, old.flags))
                    .expect("replace fdnum in sys_bind failed");
                Ok(0)
            }
        }
        _ => todo!(),
    }
}
pub fn sys_listen(sockfd: u32, _backlog: u32) -> SyscallResult<usize> {
    let proc = current_process().inner.lock();
    let socket = proc.socket_table.get_ref(sockfd as FdNum).cloned();
    if socket.is_none() {
        return Err(ENOTSOCK);
    }
    let socket = socket.unwrap();
    socket.listen()
}
pub async fn sys_accept(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let proc = current_process().inner.lock();
    let socket = proc.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;
    drop(proc);
    info!("[sys_accept]:sys_accept");
    socket.accept(sockfd, addr, addrlen).await
}

pub async fn sys_connect(sockfd: u32, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    // 需要检查一下addr到addr+addrlen是不是用户可读
    let addr_buf = unsafe { core::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;
    drop(proc_inner);
    info!("[sys_connect]: sys_connect");
    socket.connect(addr_buf).await
}
pub fn sys_getsockname(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;
    socket.addr(addr, addrlen)
}
pub fn sys_getpeername(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;
    socket.peer_addr(addr, addrlen)
}
pub async fn sys_sendto(
    sockfd: u32,
    buf: usize,
    len: usize,
    _flags: u32,
    dest_addr: usize,
    addrlen: u32,
) -> SyscallResult<usize> {
    let proc = current_process().inner.lock();
    let socket_file_t = proc.fd_table.get_ref(sockfd as FdNum);
    let socket_file = socket_file_t.cloned().ok_or(Errno::EBADF)?;
    drop(proc);

    // 在此检查buf开始到len长度的内存是不是用户可读的
    let buf = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
    debug!("[sys_sendto] file filags: {:?}", socket_file.flags);

    let proc_inner = current_process().inner.lock();
    let socket_t = proc_inner.socket_table.get_ref(sockfd as FdNum);
    let socket = socket_t.cloned().ok_or(Errno::ENOTSOCK)?;
    debug!("[sys_sendto] get socket sockfd: {}", sockfd);
    drop(proc_inner);

    let len = match socket.socket_type() {
        SocketType::SOCK_STREAM => socket_file.file.socket_write(buf,socket_file.flags).await?,
        SocketType::SOCK_DGRAM => {
            debug!("[sys_sendto] socket is udp");
            // 在此处检查 dest_addr到addrlen长度是否用户可读
            if socket.local_endpoint().unwrap().port == 0 {
                let addr = SocketAddressV4::new([0; 16].as_slice());
                let endpoint = IpListenEndpoint::from(addr);
                socket.bind(endpoint)?;
            }
            let dest_addr =
                unsafe { core::slice::from_raw_parts(dest_addr as *const u8, addrlen as usize) };
            socket.connect(dest_addr).await?;
            socket_file.file.socket_write(buf,socket_file.flags).await?
        }
        _ => todo!(),
    };
    Ok(len as usize)
}
pub async fn sys_recvfrom(
    sockfd: u32,
    buf: usize,
    len: u32,
    _flags: u32,
    src_addr: usize,
    addrlen: usize,
) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let socket_file = proc_inner.fd_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::EBADF)?;
    drop(proc_inner);
    // 在此检查buf开始到len长度的内存是不是用户可写的
    let buf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };
    debug!("[sys_recvfrom] file filags: {:?}", socket_file.flags);

    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;

    debug!("[sys_recvfrom] get socket sockfd: {}", sockfd);
    drop(proc_inner);
    match socket.socket_type() {
        SocketType::SOCK_STREAM => {
            let len = socket_file.file.read(buf).await?;
            if src_addr != 0 {
                socket.peer_addr(src_addr, addrlen)?;
            }
            Ok(len as usize)
        }
        SocketType::SOCK_DGRAM => {
            let len = socket_file.file.socket_read(buf,socket_file.flags).await?;
            if src_addr != 0 {
                socket.peer_addr(src_addr, addrlen)?;
            }
            Ok(len as usize)
        }
        _ => todo!(),
    }
}
pub fn sys_getsockopt(
    sockfd: u32,
    level: u32,
    optname: u32,
    optval_ptr: usize,
    optlen: usize,
) -> SyscallResult<usize> {
    match (level, optname) {
        (SOL_TCP, TCP_MAXSEG) => {
            let len = core::mem::size_of::<u32>();
            // 在此处检查用户是否有写入optval_ptr和optlen的权限
            unsafe {
                *(optval_ptr as *mut u32) = TCP_MSS;
                *(optlen as *mut u32) = len as u32;
            }
        }
        (SOL_TCP, TCP_CONGESTION) => {
            // 获取 TCP 拥塞控制算法名称
            let congestion = "reno";
            // 在此处检查用户是否有写入optval_ptr和optlen的权限

            let buf =
                unsafe { core::slice::from_raw_parts_mut(optval_ptr as *mut u8, congestion.len()) };
            buf.copy_from_slice(congestion.as_bytes());
            unsafe {
                *(optlen as *mut u32) = congestion.len() as u32;
            }
        }
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => {
            let len = core::mem::size_of::<u32>();
            // 在此处检查用户是否有写入optval_ptr和optlen的权限
            /*
            let socket = current_process()
                .inner_handler(move |proc| proc.socket_table.get_ref(sockfd as FdNum).cloned())
                .ok_or(Errno::ENOTSOCK)?;
             */
            let proc_inner = current_process().inner.lock();
            let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;
            drop(proc_inner);
            match optname {
                SO_SNDBUF => {
                    let size = socket.send_buf_size()?;
                    unsafe {
                        *(optval_ptr as *mut u32) = size as u32;
                        *(optlen as *mut u32) = 4;
                    }
                }
                SO_RCVBUF => {
                    let size = socket.recv_buf_size()?;
                    unsafe {
                        *(optval_ptr as *mut u32) = size as u32;
                        *(optlen as *mut u32) = 4;
                    }
                }
                _ => {}
            }
        }
        _ => {
            log::warn!("[sys_getsockopt] level: {}, optname: {}", level, optname);
        }
    }
    Ok(0)
}
pub fn sys_setsockopt(
    sockfd: u32,
    level: u32,
    optname: u32,
    optval_ptr: usize,
    optlen: u32,
) -> SyscallResult<usize> {
    /*
    let socket = current_process()
        .inner_handler(move |proc| proc.socket_table.get_ref(sockfd as FdNum).cloned())
        .ok_or(Errno::ENOTSOCK)?;
    */
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;

    drop(proc_inner);
    match (level, optname) {
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => {
            // 在此处检查用户是否有读optval_ptr到optlen长度的权限

            let size = unsafe { *(optval_ptr as *mut u32) };
            match optname {
                SO_SNDBUF => {
                    socket.set_send_buf_size(size as usize)?;
                }
                SO_RCVBUF => {
                    socket.set_recv_buf_size(size as usize)?;
                }
                _ => {}
            }
        }
        (SOL_TCP, TCP_NODELAY) => {
            // close Nagle’s Algorithm
            // 在此处检查用户是否有读optval_ptr到optlen长度的权限

            let enabled = unsafe { *(optval_ptr as *const u32) };
            log::debug!("[sys_setsockopt] set TCPNODELY: {}", enabled);
            match enabled {
                0 => socket.set_nagle_enabled(true)?,
                _ => socket.set_nagle_enabled(false)?,
            };
        }
        (SOL_SOCKET, SO_KEEPALIVE) => {
            // 在此处检查用户是否有读optval_ptr到optlen长度的权限

            let enabled = unsafe { *(optval_ptr as *const u32) };
            log::debug!("[sys_setsockopt] set socket KEEPALIVE: {}", enabled);
            match enabled {
                1 => socket.set_keep_alive(true)?,
                _ => socket.set_keep_alive(false)?,
            };
        }
        _ => {
            log::warn!("[sys_setsockopt] level: {}, optname: {}", level, optname);
        }
    }
    Ok(0)
}
pub fn sys_sockshutdown(sockfd: u32, how: u32) -> SyscallResult<usize> {
    log::info!("[sys_shutdown] sockfd {}, how {}", sockfd, how);
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get_ref(sockfd as FdNum).cloned().ok_or(Errno::ENOTSOCK)?;
    drop(proc_inner);
    socket.shutdown(how)?;
    Ok(0)
}
pub fn sys_socketpair(
    domain: u32,
    socket_type: u32,
    protocol: u32,
    sv: usize,
) -> SyscallResult<usize> {
    info!(
        "[sys_socketpair] domain {}, type {}, protocol {}, sv {}",
        domain, socket_type, protocol, sv
    );
    let len = 2 * core::mem::size_of::<u32>();
    // 在此处检查用户是否有写sv到len长度的权限

    let sv = unsafe { core::slice::from_raw_parts_mut(sv as *mut u32, len) };
    let (socket1, socket2) = make_unix_socket_pair();
    /*
    let (fd1, fd2) = current_process().inner_handler(move |proc| {
        let fd1 = proc.fd_table.alloc_fd()?;
        proc.fd_table.put(
            FileDescriptor::new(socket1, OpenFlags::O_RDWR),
            fd1 as FdNum,
        )?;
        let fd2 = proc.fd_table.alloc_fd()?;
        proc.fd_table.put(
            FileDescriptor::new(socket2, OpenFlags::O_RDWR),
            fd2 as FdNum,
        )?;
        Ok((fd1, fd2))
    })?;
     */
    let mut proc_inner = current_process().inner.lock();
    let fd1 = proc_inner.fd_table.alloc_fd()?;
    proc_inner.fd_table.put(FileDescriptor::new(socket1,OpenFlags::O_RDWR),
    fd1 as FdNum,)?;
    let fd2 = proc_inner.fd_table.alloc_fd()?;
    proc_inner.fd_table.put(FileDescriptor::new(socket2,OpenFlags::O_RDWR),
    fd2 as FdNum,)?;
    sv[0] = fd1 as u32;
    sv[1] = fd2 as u32;
    info!("[sys_socketpair] new sv: {:?}", sv);
    Ok(0)
}

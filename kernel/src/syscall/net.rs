use core::mem::size_of;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::net::{
    listen_endpoint, make_unix_socket_pair, Socket, SocketAddressV4, SocketType, TCP_MSS,
};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use log::{debug, info, warn};
use smoltcp::wire::IpListenEndpoint;
use crate::arch::VirtAddr;

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
    info!("[socket] new sockfd: {}", sockfd);
    Ok(sockfd)
}

pub fn sys_bind(sockfd: FdNum, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let addr_buf = proc_inner.addr_space.user_slice_r(VirtAddr(addr), addrlen as usize)?;
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
    let endpoint = listen_endpoint(addr_buf)?;
    info!("[bind] sockfd: {}, ep: {}", sockfd, endpoint);
    match socket.socket_type() {
        SocketType::SOCK_STREAM => socket.bind(endpoint)?,
        SocketType::SOCK_DGRAM => {
            if proc_inner.socket_table.can_bind(endpoint) {
                socket.bind(endpoint)?;
            } else {
                return Err(Errno::EADDRINUSE);
            }
        }
        _ => todo!(),
    }
    Ok(0)
}

pub fn sys_listen(sockfd: FdNum, _backlog: u32) -> SyscallResult<usize> {
    info!("[listen] sockfd: {}", sockfd);
    current_process().inner.lock()
        .socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?
        .listen()?;
    Ok(0)
}

pub async fn sys_accept(sockfd: FdNum, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    info!("[accept] sockfd: {}", sockfd);
    let ret = current_process().inner.lock()
        .socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?
        .accept(addr, addrlen).await;
    info!("here??");
    ret
}

pub async fn sys_connect(sockfd: FdNum, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    // 需要检查一下addr到addr+addrlen是不是用户可读
    let addr_buf = unsafe { core::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
    let socket = current_process().inner.lock()
        .socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
    socket.connect(addr_buf).await?;
    Ok(0)
}

pub fn sys_getsockname(sockfd: FdNum, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
    socket.addr(addr, addrlen)
}

pub fn sys_getpeername(sockfd: FdNum, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
    socket.peer_addr(addr, addrlen)
}

pub async fn sys_sendto(
    sockfd: FdNum,
    buf: usize,
    len: usize,
    _flags: u32,
    dest_addr: usize,
    addrlen: u32,
) -> SyscallResult<usize> {

    let fd_impl = current_process().inner.lock().fd_table.get(sockfd)?;
    // 在此检查buf开始到len长度的内存是不是用户可读的
    let buf = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };

    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
    debug!("[sys_sendto] get socket sockfd: {}", sockfd);
    drop(proc_inner);

    let len = match socket.socket_type() {
        SocketType::SOCK_STREAM => fd_impl.file.write(buf).await?,
        SocketType::SOCK_DGRAM => {
            debug!("[sys_sendto] socket is udp");
            // 在此处检查 dest_addr到addrlen长度是否用户可读
            if socket.local_endpoint().port == 0 {
                let addr = SocketAddressV4::new([0; 16].as_slice());
                let endpoint = IpListenEndpoint::from(addr);
                socket.bind(endpoint)?;
            }
            debug!("[sys_sendto] udp socket's local_endpoint.port {}",socket.local_endpoint().port);
            let dest_addr =
                unsafe { core::slice::from_raw_parts(dest_addr as *const u8, addrlen as usize) };
            socket.connect(dest_addr).await?;
            let ret = fd_impl.file.write(buf).await?;
            info!("[sys_sendto ::write] last write OK");
            ret
        }
        _ => todo!(),
    };
    Ok(len as usize)
}
pub async fn sys_recvfrom(
    sockfd: FdNum,
    buf: usize,
    len: u32,
    _flags: u32,
    src_addr: usize,
    addrlen: usize,
) -> SyscallResult<usize> {
    debug!("[sys_recvfrom] get socket sockfd: {}", sockfd);

    let fd_impl = current_process().inner.lock().fd_table.get(sockfd)?;
    // 在此检查buf开始到len长度的内存是不是用户可写的
    let buf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };

    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
    drop(proc_inner);
    match socket.socket_type() {
        SocketType::SOCK_STREAM => {
            let len = fd_impl.file.read(buf).await?;
            if src_addr != 0 {
                socket.peer_addr(src_addr, addrlen)?;
            }
            Ok(len as usize)
        }
        SocketType::SOCK_DGRAM => {
            debug!("[sys_recvfrom] udp read begin...");
            let len = fd_impl.file.read(buf).await?;
            if src_addr != 0 {
                socket.peer_addr(src_addr, addrlen)?;
            }
            Ok(len as usize)
        }
        _ => todo!(),
    }
}

pub fn sys_getsockopt(
    sockfd: FdNum,
    level: u32,
    optname: u32,
    optval_ptr: usize,
    optlen: usize,
) -> SyscallResult<usize> {
    match (level, optname) {
        (SOL_TCP, TCP_MAXSEG) => {
            let len = size_of::<u32>();
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
            // 在此处检查用户是否有写入optval_ptr和optlen的权限
            /*
            let socket = current_process()
                .inner_handler(move |proc| proc.socket_table.get_ref(sockfd).cloned())
                .ok_or(Errno::ENOTSOCK)?;
             */
            let proc_inner = current_process().inner.lock();
            let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
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
            warn!("[sys_getsockopt] level: {}, optname: {}", level, optname);
        }
    }
    Ok(0)
}

pub fn sys_setsockopt(
    sockfd: FdNum,
    level: u32,
    optname: u32,
    optval_ptr: usize,
    optlen: u32,
) -> SyscallResult<usize> {
    /*
    let socket = current_process()
        .inner_handler(move |proc| proc.socket_table.get_ref(sockfd).cloned())
        .ok_or(Errno::ENOTSOCK)?;
    */
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;

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
            debug!("[sys_setsockopt] set TCPNODELY: {}", enabled);
            match enabled {
                0 => socket.set_nagle_enabled(true)?,
                _ => socket.set_nagle_enabled(false)?,
            };
        }
        (SOL_SOCKET, SO_KEEPALIVE) => {
            // 在此处检查用户是否有读optval_ptr到optlen长度的权限

            let enabled = unsafe { *(optval_ptr as *const u32) };
            debug!("[sys_setsockopt] set socket KEEPALIVE: {}", enabled);
            match enabled {
                1 => socket.set_keep_alive(true)?,
                _ => socket.set_keep_alive(false)?,
            };
        }
        _ => {
            warn!("[sys_setsockopt] level: {}, optname: {}", level, optname);
        }
    }
    Ok(0)
}

pub fn sys_sockshutdown(sockfd: FdNum, how: u32) -> SyscallResult<usize> {
    info!("[sys_shutdown] sockfd {}, how {}", sockfd, how);
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.socket_table.get(sockfd).ok_or(Errno::ENOTSOCK)?;
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
        domain, socket_type, protocol, sv,
    );
    let mut proc_inner = current_process().inner.lock();
    let sv = proc_inner.addr_space.user_slice_w(VirtAddr(sv), size_of::<FdNum>())?;
    let sv = bytemuck::cast_slice_mut(sv);
    let (socket1, socket2) = make_unix_socket_pair();
    let fd1 = proc_inner.fd_table.put(FileDescriptor::new(socket1, false), 0)?;
    let fd2 = proc_inner.fd_table.put(FileDescriptor::new(socket2, false), 0)?;
    sv[0] = fd1;
    sv[1] = fd2;
    info!("[socketpair] new sv: {:?}", sv);
    Ok(0)
}

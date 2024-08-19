use core::mem::size_of;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::net::{copy_back_addr, make_unix_socket_pair, RecvFromFlags, SockAddr, Socket, TCP_MSS};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use log::{debug, info, warn};
use macros::suspend;
use crate::mm::protect::{user_slice_r, user_slice_w, user_transmute_w};

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
    info!(
        "[sys_socket] domain: {}, type: {}, protocol: {}",
        domain, socket_type, protocol
    );
    let sockfd = <dyn Socket>::alloc(domain, socket_type)?;
    info!("[sys_socket] new sockfd: {}", sockfd);
    Ok(sockfd)
}

pub fn sys_bind(sockfd: FdNum, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    info!("[sys_bind] sockfd: {}", sockfd);
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    let addr = user_slice_r(addr, addrlen as usize)?;
    let addr = SockAddr::from_bytes(addr)?;
    socket.bind(addr)?;
    Ok(0)
}

pub fn sys_listen(sockfd: FdNum, _backlog: u32) -> SyscallResult<usize> {
    info!("[sys_listen] sockfd: {}", sockfd);
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    socket.listen()?;
    Ok(0)
}

#[suspend]
pub async fn sys_accept(sockfd: FdNum, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    info!("[sys_accept] sockfd: {}", sockfd);
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    let new_sock = if let Some(addrlen) = user_transmute_w::<u32>(addrlen)? {
        // LTP says EINVAL, although it should be EFAULT
        let addr = user_slice_w(addr, *addrlen as usize).map_err(|_| Errno::EINVAL)?;
        let mut addr_buf = SockAddr::Uninit;
        let new_sock = socket.accept(Some(&mut addr_buf)).await?;
        *addrlen = copy_back_addr(addr, &addr_buf) as u32;
        new_sock
    } else {
        socket.accept(None).await?
    };
    let new_fd = current_process().inner.lock()
        .fd_table.put(FileDescriptor::new(new_sock, false), 0)?;
    info!("[sys_accept] new sockfd: {}", new_fd);
    Ok(new_fd as usize)
}

#[suspend]
pub async fn sys_connect(sockfd: FdNum, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    info!("[sys_connect] sockfd: {}",sockfd);
    let addr = user_slice_r(addr, addrlen as usize)?;
    let addr = SockAddr::from_bytes(addr)?;
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    socket.connect(addr).await?;
    Ok(0)
}

pub fn sys_getsockname(sockfd: FdNum, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    let addrlen = user_transmute_w::<u32>(addrlen)?.ok_or(Errno::EFAULT)?;
    let addr = user_slice_w(addr, *addrlen as usize)?;
    let addr_buf = socket.sock_name();
    copy_back_addr(addr, &addr_buf);
    Ok(0)
}

pub fn sys_getpeername(sockfd: FdNum, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    let addrlen = user_transmute_w::<u32>(addrlen)?.ok_or(Errno::EFAULT)?;
    let addr = user_slice_w(addr, *addrlen as usize)?;
    let addr_buf = socket.peer_name()?;
    copy_back_addr(addr, &addr_buf);
    Ok(0)
}

#[suspend]
pub async fn sys_sendto(
    sockfd: FdNum,
    buf: usize,
    len: usize,
    flags: u32,
    dest_addr: usize,
    addrlen: u32,
) -> SyscallResult<usize> {
    info!("[sys_sendto] get socket sockfd: {}", sockfd);
    let flags = RecvFromFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let buf = user_slice_r(buf, len)?;
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    let ret = if dest_addr != 0 {
        let dest = user_slice_r(dest_addr, addrlen as usize)?;
        let dest = SockAddr::from_bytes(dest)?;
        socket.send(buf, flags, Some(dest)).await?
    } else {
        socket.send(buf, flags, None).await?
    };
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_recvfrom(
    sockfd: FdNum,
    buf: usize,
    len: usize,
    flags: u32,
    src_addr: usize,
    addrlen: usize,
) -> SyscallResult<usize> {
    info!("[sys_recvfrom] get socket sockfd: {}", sockfd);
    let flags = RecvFromFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let buf = user_slice_w(buf, len)?;
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;
    let ret = if let Some(addrlen) = user_transmute_w::<u32>(addrlen)? {
        let src = user_slice_w(src_addr, *addrlen as usize)?;
        let mut src_buf = SockAddr::Uninit;
        let ret = socket.recv(buf, flags, Some(&mut src_buf)).await?;
        *addrlen = copy_back_addr(src, &src_buf) as u32;
        ret
    } else {
        socket.recv(buf, flags, None).await?
    };
    Ok(ret as usize)
}

pub fn sys_getsockopt(
    sockfd: FdNum,
    level: u32,
    optname: u32,
    optval: usize,
    optlen: usize,
) -> SyscallResult<usize> {
    info!("[sys_getsockopt] sockfd: {}",sockfd);
    match (level, optname) {
        (SOL_TCP, TCP_MAXSEG) => {
            *user_transmute_w::<u32>(optval)?.ok_or(Errno::EINVAL)? = TCP_MSS;
            *user_transmute_w::<u32>(optlen)?.ok_or(Errno::EINVAL)? = size_of::<u32>() as u32;
        }
        (SOL_TCP, TCP_CONGESTION) => {
            // 获取 TCP 拥塞控制算法名称
            static CONGESTION: &str = "reno";
            user_slice_w(optval, CONGESTION.len())?.copy_from_slice(CONGESTION.as_bytes());
            *user_transmute_w::<u32>(optlen)?.ok_or(Errno::EINVAL)? = CONGESTION.len() as u32;
        }
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => {
            let socket = current_process().inner.lock()
                .fd_table.get(sockfd)?.file.as_socket()?;
            let size = match optname {
                SO_SNDBUF => socket.send_buf_size()?,
                SO_RCVBUF => socket.recv_buf_size()?,
                _ => unreachable!(),
            };
            *user_transmute_w::<u32>(optval)?.ok_or(Errno::EINVAL)? = size as u32;
            *user_transmute_w::<u32>(optlen)?.ok_or(Errno::EINVAL)? = size_of::<usize>() as u32;
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
    optval: usize,
    optlen: u32,
) -> SyscallResult<usize> {
    if optlen == 0 {
        return Err(Errno::EINVAL);
    }
    let optval = user_slice_r(optval, optlen as usize)?;
    info!("[sys_setsockopt] socketfd: {}", sockfd);
    let socket = current_process().inner.lock()
        .fd_table.get(sockfd)?.file.as_socket()?;

    match (level, optname) {
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => {
            let size: u32 = zerocopy::FromBytes::read_from_prefix(optval).ok_or(Errno::EINVAL)?;
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
            let enabled: u8 = zerocopy::FromBytes::read_from_prefix(optval).ok_or(Errno::EINVAL)?;
            debug!("[sys_setsockopt] set TCPNODELY: {}", enabled);
            match enabled {
                0 => socket.set_nagle_enabled(true)?,
                _ => socket.set_nagle_enabled(false)?,
            };
        }
        (SOL_SOCKET, SO_KEEPALIVE) => {
            let enabled: u8 = zerocopy::FromBytes::read_from_prefix(optval).ok_or(Errno::EINVAL)?;
            debug!("[sys_setsockopt] set socket KEEPALIVE: {}", enabled);
            match enabled {
                1 => socket.set_keep_alive(true)?,
                _ => socket.set_keep_alive(false)?,
            };
        }
        _ => {
            warn!("[sys_setsockopt] level: {}, optname: {}", level, optname);
            // return Err(Errno::ENOPROTOOPT);
        }
    }
    Ok(0)
}

pub fn sys_sockshutdown(sockfd: FdNum, how: u32) -> SyscallResult<usize> {
    info!("[sys_shutdown] sockfd {}, how {}", sockfd, how);
    let proc_inner = current_process().inner.lock();
    let socket = proc_inner.fd_table.get(sockfd)?.file.as_socket()?;
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
    let sv = user_slice_w(sv, 2 * size_of::<FdNum>())?;
    let sv = bytemuck::cast_slice_mut(sv);
    let (socket1, socket2) = make_unix_socket_pair();
    let mut proc_inner = current_process().inner.lock();
    let fd1 = proc_inner.fd_table.put(FileDescriptor::new(socket1, false), 0)?;
    let fd2 = proc_inner.fd_table.put(FileDescriptor::new(socket2, false), 0)?;
    sv[0] = fd1;
    sv[1] = fd2;
    info!("[socketpair] new sv: {:?}", sv);
    Ok(0)
}

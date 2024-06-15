use log::info;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::net::{listen_endpoint, Socket, SocketType};
use crate::processor::current_process;
use crate::result::Errno::{ENOSTR, ENOTSOCK};
use crate::result::{Errno, SyscallResult};

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

pub fn sys_socket(domain: u32,socket_type: u32,protocol: u32) -> SyscallResult<usize>{
    let sockfd = <dyn Socket>::alloc(domain,socket_type).unwrap();
    info!("[sys_socket] new sockfd: {}", sockfd);
    Ok(sockfd)
}
pub fn sys_bind(sockfd: u32,addr: usize,addrlen: u32) -> SyscallResult<usize>{
    /*
        检查一下从addr到addr+addrlen是否满足User Readable
    */
    let addr_buf = unsafe{core::slice::from_raw_parts(addr as *const u8,addrlen as usize)};
    let socket = current_process().inner.lock().socket_table.get_ref(sockfd as i32).cloned();
    if socket.is_none(){
        return Err(ENOTSOCK);
    }
    let socket = socket.unwrap();
    let endpoint = listen_endpoint(addr_buf)?;
    match socket.socket_type() {
        SocketType::SOCK_STREAM => {
            socket.bind(endpoint)
        },
        SocketType::SOCK_DGRAM => {
            let mut proc = current_process().inner.lock();
            let res = proc.socket_table.can_bind(endpoint);
            if res.is_none(){
                info!("[sys_bind] not find port exist");
                socket.bind(endpoint)
            } else {
                let (_,sock) = res.unwrap();
                proc.socket_table.insert(sockfd as FdNum,sock.clone());
                let old = proc.fd_table.take(sockfd as FdNum).unwrap().unwrap();
                proc.fd_table.insert(sockfd as FdNum, FileDescriptor::new(sock, old.flags)).expect("replace fdnum in sys_bind failed");
                Ok(0)
            }
        },
        _ => todo!(),
    }
}
pub fn sys_listen(sockfd: u32, _backlog: u32) -> SyscallResult<usize>{
    let proc = current_process().inner.lock();
    let socket = proc.socket_table.get_ref(sockfd as FdNum).cloned();
    if socket.is_none(){
        return Err(ENOTSOCK);
    }
    let socket = socket.unwrap();
    socket.listen()
}
pub async fn sys_accept(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    let socket = current_process().inner_handler(|proc|{
        proc.socket_table.get_ref(sockfd as FdNum).cloned()
            .ok_or(Err(ENOTSOCK))?
    });
    socket.accept(sockfd,addr,addrlen).await
}
pub async fn sys_connect(sockfd: u32, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    // 需要检查一下addr到addr+addrlen是不是用户可读
    let addr_buf = unsafe { core::slice::from_raw_parts(addr as *const u8, addrlen as usize) };
    let socket = current_process()
        .inner_handler(|proc| proc.socket_table.get_ref(sockfd as FdNum).cloned())
        .ok_or(Errno::ENOTSOCK)?;
    socket.connect(addr_buf).await
}
pub fn sys_getsockname(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize>{
    let socket = current_process()
        .inner_handler(|proc| proc.socket_table.get_ref(sockfd as FdNum).cloned())
        .ok_or(Errno::ENOTSOCK)?;
    socket.addr(addr, addrlen)
}
pub fn sys_getpeername(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize>{
    let socket = current_process()
        .inner_handler(|proc| proc.socket_table.get_ref(sockfd as FdNum).cloned())
        .ok_or(Errno::ENOTSOCK)?;
    socket.peer_addr(addr, addrlen)
}
pub async fn sys_sendto(
    sockfd: u32,
    buf: usize,
    len: usize,
    _flags: u32,
    dest_addr: usize,
    addrlen: u32,
) -> SyscallResult<usize>{
    todo!()
}
pub async fn sys_recvfrom(
    sockfd: u32,
    buf: usize,
    len: u32,
    _flags: u32,
    src_addr: usize,
    addrlen: usize,
) -> SyscallResult<usize>{
    todo!()
}
pub fn sys_getsockopt(
    sockfd: u32,
    level: u32,
    optname: u32,
    optval_ptr: usize,
    optlen: usize,
) -> SyscallResult<usize>{
    todo!()
}
pub fn sys_setsockopt(
    sockfd: u32,
    level: u32,
    optname: u32,
    optval_ptr: usize,
    optlen: u32,
) -> SyscallResult<()>{
    todo!()
}
pub fn sys_shutdown(sockfd: u32, how: u32) -> SyscallResult<usize>{
    log::info!("[sys_shutdown] sockfd {}, how {}", sockfd, how);
    current_process().inner_handler(|proc| {
        let socket = proc
            .socket_table
            .get_ref(sockfd as FdNum)
            .ok_or(Errno::EBADF)?
            .clone();
        socket.shutdown(how)?;
        Ok(0)
    })
}
pub fn sys_socketpair(domain: u32, socket_type: u32, protocol: u32, sv: usize) -> SyscallResult<usize>{
    todo!()
}

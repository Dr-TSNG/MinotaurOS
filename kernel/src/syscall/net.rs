use crate::net::Socket;
use crate::processor::current_process;
use crate::result::SyscallResult;

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
    todo!()
}
pub fn sys_bind(sockfd: u32,addr: usize,addrlen: u32) -> SyscallResult<usize>{
    todo!()
}
pub fn sys_listen(sockfd: u32, _backlog: u32) -> SyscallResult<usize>{
    todo!()
}
pub async fn sys_accept(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
    todo!()
}
pub async fn sys_connect(sockfd: u32, addr: usize, addrlen: u32) -> SyscallResult<usize> {
    todo!()
}
pub fn sys_getsockname(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize>{
    todo!()
}
pub fn sys_getpeername(sockfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize>{
    todo!()
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
    todo!()
}
pub fn sys_socketpair(domain: u32, socket_type: u32, protocol: u32, sv: usize) -> SyscallResult<usize>{
    todo!()
}

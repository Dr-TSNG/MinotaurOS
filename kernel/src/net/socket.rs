use crate::fs::fd::FdNum;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use bitflags::bitflags;
use smoltcp::wire::IpListenEndpoint;

use crate::fs::file::File;
use crate::net::netaddress::IpAddr;
use crate::result::SyscallResult;

/// 32KiB , both send and recv
pub const BUFFER_SIZE: usize = 1 << 15;

pub enum ShutDownType {
    ShutdownRead(u32),
    ShutdownWrite(u32),
    ShutdownRw(u32),
}

bitflags! {
    /// socket type, use when you alloc a socket , didn't impl yet
    pub struct SocketType: u32 {
        const SOCK_STREAM = 1 << 0;
        const SOCK_DGRAM = 1 << 1;
        const SOCK_CLOEXEC = 1 << 19;
    }
}

/// used when you want trans a socket_address to IpEndPoint or IpListenEndPoint
pub enum SocketAddress {
    V4(SocketAddressV4),
    V6(SocketAddressV6),
}

pub struct SocketAddressV4 {
    port: [u8; 2],
    addr_v4: IpAddr::Ipv4(),
}

pub struct SocketAddressV6 {
    port: [u8; 2],
    flowinfo: u32,
    addr_v6: IpAddr::Ipv6(),
}

pub struct SocketTable(BTreeMap<FdNum, Arc<dyn Socket>>);

/// for syscall on net part , return SyscallResult
pub trait Socket: File {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult;
    fn connect(&self, addr: &[u8]) -> SyscallResult;
    fn listen(&self) -> SyscallResult;
    fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult;
    fn set_send_buf_size(&self, size: usize) -> SyscallResult;
    fn set_recv_buf_size(&self, size: usize) -> SyscallResult;
    fn set_keep_live(&self, enabled: bool) -> SyscallResult;
    fn dis_connect(&self, enabled: bool) -> SyscallResult;
}

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use bitflags::bitflags;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};

use crate::fs::fd::FdNum;
use crate::fs::file::File;
use crate::net::netaddress::IpAddr;
use crate::net::port::PORT_ALLOCATOR;
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

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[repr(C)]
pub struct SocketAddressV4 {
    port: [u8; 2],
    addr_v4: IpAddr::Ipv4(),
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[repr(C)]
pub struct SocketAddressV6 {
    port: [u8; 2],
    flowinfo: [u8; 4],
    addr_v6: IpAddr::Ipv6(),
}

impl From<IpEndpoint> for SocketAddressV4 {
    fn from(value: IpEndpoint) -> Self {
        Self {
            port: value.port.to_be_bytes(),
            addr_v4: value
                .addr
                .as_bytes()
                .try_into()
                .expect("ipv4 address length error!"),
        }
    }
}
impl From<SocketAddressV4> for IpEndpoint {
    fn from(value: SocketAddressV4) -> Self {
        let port = u16::from_be_bytes(value.port);
        Self::new(IpAddress::Ipv4(Ipv4Address(value.addr_v4)), port)
    }
}

impl From<SocketAddressV4> for IpListenEndpoint {
    fn from(value: SocketAddressV4) -> Self {
        let port = u16::from_be_bytes(value.port);
        let addr = Ipv4Address(value.addr_v4);
        if addr.is_unspecified() {
            if port != 0 {
                IpListenEndpoint { addr: None, port }
            } else {
                IpListenEndpoint {
                    addr: None,
                    port: unsafe { PORT_ALLOCATOR.take().unwrap() as u16 },
                }
            }
        } else {
            IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(addr)),
                port,
            }
        }
    }
}

impl From<IpEndpoint> for SocketAddressV6 {
    fn from(value: IpEndpoint) -> Self {
        Self {
            port: value.port.to_be_bytes(),
            flowinfo: [0 as u8; 4],
            addr_v6: value
                .addr
                .as_bytes()
                .try_into()
                .expect("ipv6 addr length error!"),
        }
    }
}
impl From<SocketAddressV6> for IpEndpoint {
    fn from(value: SocketAddressV6) -> Self {
        let port = u16::from_be_bytes(value.port);
        Self::new(IpAddress::Ipv6(Ipv6Address(value.addr_v6)), port)
    }
}
impl From<SocketAddressV6> for IpListenEndpoint {
    fn from(value: SocketAddressV6) -> Self {
        let port = u16::from_be_bytes(value.port);
        let addr = Ipv6Address(value.addr_v6);
        if addr.is_unspecified() {
            if port != 0 {
                IpListenEndpoint { addr: None, port }
            } else {
                IpListenEndpoint {
                    addr: None,
                    port: unsafe { PORT_ALLOCATOR.take().unwrap() as u16 },
                }
            }
        } else {
            IpListenEndpoint {
                addr: Some(IpAddress::Ipv6(addr)),
                port,
            }
        }
    }
}

pub struct SocketTable(BTreeMap<FdNum, Arc<dyn Socket>>);

/// for syscall on net part , return SyscallResult
pub trait Socket: File {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult;
    fn connect<'a>(&'a self, addr: &'a [u8]) -> SyscallResult;
    fn listen(&self) -> SyscallResult;
    fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult;
    fn set_send_buf_size(&self, size: usize) -> SyscallResult;
    fn set_recv_buf_size(&self, size: usize) -> SyscallResult;
    fn set_keep_live(&self, enabled: bool) -> SyscallResult;
    fn dis_connect(&self, enabled: bool) -> SyscallResult;
    fn socket_type(&self) -> SocketType;
}

pub fn endpoint(addr_buf: &[u8]) -> IpEndpoint {
    todo!()
}

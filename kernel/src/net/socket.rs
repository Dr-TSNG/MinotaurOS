use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::mem::size_of;
use core::slice;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::file::File;
use crate::net::port::random_port;
use crate::net::tcp::TcpSocket;
use crate::net::udp::UdpSocket;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use bitflags::bitflags;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};

/// domain
pub const AF_UNIX: u16 = 0x0001;
pub const AF_INET: u16 = 0x0002;
pub const AF_INET6: u16 = 0x000a;

/// 32KiB , both send and recv
pub const BUFFER_SIZE: usize = 1 << 15;

/// 这是fd描述符与Socket相关的映射表，
/// 实现file trait后，用于使用fd查找socket
#[derive(Clone, Default)]
pub struct SocketTable(BTreeMap<FdNum, Arc<dyn Socket>>);

impl SocketTable {
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, key: FdNum, value: Arc<dyn Socket>) {
        self.0.insert(key, value);
    }

    pub fn get(&self, fd: FdNum) -> Option<Arc<dyn Socket>> {
        self.0.get(&fd).cloned()
    }

    pub fn take(&mut self, fd: FdNum) -> Option<Arc<dyn Socket>> {
        self.0.remove(&fd)
    }

    pub fn can_bind(&self, endpoint: IpListenEndpoint) -> bool {
        self.0.values().all(|socket| socket.local_endpoint() != endpoint)
    }
}

/// shutdown
#[allow(unused)]
pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
#[allow(unused)]
pub const SHUT_RDWR: u32 = 2;

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
    addr_v4: [u8; 4],
}

impl SocketAddressV4 {
    pub fn new(buf: &[u8]) -> Self {
        let addr = Self {
            port: buf[2..4].try_into().expect("ipv4 port len err"),
            addr_v4: buf[4..8].try_into().expect("ipv4 addr len err"),
        };
        addr
    }
    pub fn fill(&self, addr_buf: &mut [u8], addrlen: usize) {
        addr_buf.fill(0);
        addr_buf[0..2].copy_from_slice(u16::to_ne_bytes(AF_INET).as_slice());
        addr_buf[2..4].copy_from_slice(self.port.as_slice());
        addr_buf[4..8].copy_from_slice(self.addr_v4.as_slice());
        unsafe {
            *(addrlen as *mut u32) = 8;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[repr(C)]
pub struct SocketAddressV6 {
    port: [u8; 2],
    flowinfo: [u8; 4],
    addr_v6: [u8; 16],
}

impl SocketAddressV6 {
    pub fn new(buf: &[u8]) -> Self {
        let addr = Self {
            port: buf[2..4].try_into().expect("ipv6 port len err"),
            flowinfo: buf[4..8].try_into().expect("ipv6 flowinfo len err"),
            addr_v6: buf[8..24].try_into().expect("ipv6 addr len err"),
        };
        addr
    }
    pub fn fill(&self, addr_buf: &mut [u8], addrlen: usize) {
        addr_buf.fill(0);
        addr_buf[0..2].copy_from_slice(u16::to_ne_bytes(AF_INET6).as_slice());
        addr_buf[2..4].copy_from_slice(self.port.as_slice());
        addr_buf[4..8].copy_from_slice(self.flowinfo.as_slice());
        addr_buf[8..24].copy_from_slice(self.addr_v6.as_slice());
        unsafe {
            *(addrlen as *mut u32) = 24;
        }
    }
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
                    port: random_port(),
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
            flowinfo: [0u8; 4],
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
                    port: random_port(),
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

/// for syscall on net part , return SyscallResult
#[allow(unused)]
#[async_trait]
pub trait Socket: File {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    fn listen(&self) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    async fn accept(&self, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult;

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult;

    fn set_keep_live(&self, enabled: bool) -> SyscallResult;

    fn dis_connect(&self, how: u32) -> SyscallResult;

    fn socket_type(&self) -> SocketType;

    fn local_endpoint(&self) -> IpListenEndpoint;

    fn remote_endpoint(&self) -> Option<IpEndpoint>;

    fn shutdown(&self, how: u32) -> SyscallResult;

    fn recv_buf_size(&self) -> SyscallResult<usize>;

    fn send_buf_size(&self) -> SyscallResult<usize>;

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }
}
pub fn to_endpoint(listen_endpoint: IpListenEndpoint) -> IpEndpoint {
    let addr = if listen_endpoint.addr.is_none() {
        IpAddress::v4(127, 0, 0, 1)
    } else {
        listen_endpoint.addr.unwrap()
    };
    IpEndpoint::new(addr, listen_endpoint.port)
}
pub fn listen_endpoint(addr_buf: &[u8]) -> SyscallResult<IpListenEndpoint> {
    let family = u16::from_ne_bytes(addr_buf[0..2].try_into().expect("family size wrong"));
    match family {
        AF_INET => {
            let ipv4 = SocketAddressV4::new(addr_buf);
            Ok(IpListenEndpoint::from(ipv4))
        }
        AF_INET6 => {
            let ipv6 = SocketAddressV6::new(addr_buf);
            Ok(IpListenEndpoint::from(ipv6))
        }
        _ => {
            return Err(Errno::EINVAL);
        }
    }
}
pub fn endpoint(addr_buf: &[u8]) -> SyscallResult<IpEndpoint> {
    let listen_endpoint = listen_endpoint(addr_buf)?;
    let addr = if listen_endpoint.addr.is_none() {
        IpAddress::v4(127, 0, 0, 1)
    } else {
        listen_endpoint.addr.unwrap()
    };
    Ok(IpEndpoint::new(addr, listen_endpoint.port))
}
pub fn fill_with_endpoint(
    endpoint: IpEndpoint,
    addr: usize,
    addrlen: usize,
) -> SyscallResult<usize> {
    match endpoint.addr {
        IpAddress::Ipv4(_) => {
            let len = size_of::<u16>() + size_of::<SocketAddressV4>();
            // tos在此处使用UserCheck检查了addr开始处的len长度内存是否支持写入。
            let addr_buf = unsafe { slice::from_raw_parts_mut(addr as *mut u8, len) };
            SocketAddressV4::from(endpoint).fill(addr_buf, addrlen);
        }
        IpAddress::Ipv6(_) => {
            let len = size_of::<u16>() + size_of::<SocketAddressV6>();
            let addr_buf = unsafe { slice::from_raw_parts_mut(addr as *mut u8, len) };
            SocketAddressV6::from(endpoint).fill(addr_buf, addrlen);
        }
    }
    Ok(0)
}

impl dyn Socket {
    pub fn alloc(domain: u32, socket_type: u32) -> SyscallResult<usize> {
        match domain as u16 {
            AF_INET | AF_INET6 => {
                let socket_type = SocketType::from_bits(socket_type).ok_or(Errno::EINVAL)?;
                let cloexec = socket_type.contains(SocketType::SOCK_CLOEXEC);
                // 创建 inode， 赋值给生成的 udp socket， inode 的类型为 IFSOCK
                if socket_type.contains(SocketType::SOCK_DGRAM) {
                    let socket = Arc::new(UdpSocket::new());
                    let mut proc_inner = current_process().inner.lock();
                    let fd = proc_inner.fd_table.put(FileDescriptor::new(socket.clone(), cloexec), 0)?;
                    proc_inner.socket_table.insert(fd, socket);
                    Ok(fd as usize)
                } else if socket_type.contains(SocketType::SOCK_STREAM) {
                    let socket = Arc::new(TcpSocket::new());
                    let mut proc_inner = current_process().inner.lock();
                    let fd = proc_inner.fd_table.put(FileDescriptor::new(socket.clone(), cloexec), 0)?;
                    proc_inner.socket_table.insert(fd, socket);
                    Ok(fd as usize)
                } else {
                    Err(Errno::EINVAL)
                }
            }
            AF_UNIX => {
                Ok(4)
                // todo!()
            }
            _ => Err(Errno::EINVAL),
        }
    }
    pub fn addr(self: &Arc<Self>, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        let local_endpoint = self.local_endpoint();
        let local_endpoint = to_endpoint(local_endpoint);
        fill_with_endpoint(local_endpoint, addr, addrlen)
    }

    pub fn peer_addr(self: &Arc<Self>, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        match self.remote_endpoint() {
            Some(remote_endpoint) => fill_with_endpoint(remote_endpoint, addr, addrlen),
            None => Err(Errno::ENOTCONN),
        }
    }
}
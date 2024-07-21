use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use bitflags::bitflags;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use crate::fs::fd::FileDescriptor;
use crate::fs::file::File;
use crate::net::netaddress::{fill_with_endpoint, to_endpoint};
use crate::net::tcp::TcpSocket;
use crate::net::udp::UdpSocket;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

/// domain
pub const AF_UNIX: u16 = 0x0001;
pub const AF_INET: u16 = 0x0002;
pub const AF_INET6: u16 = 0x000a;


pub const BUFFER_SIZE: usize = 1 << 17;

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

    /// recv_from flags
    pub struct RecvFromFlags: u32 {
        /// peek
        const MSG_PEEK = 1 << 1;
        /// noblock
        const MSG_DONTWAIT = 1 << 6;
        /// nothing to do
        const MSG_NOTHING = 1 << 0;
    }
}

impl Default for RecvFromFlags {
    fn default() -> Self {
        Self {
            bits: RecvFromFlags::MSG_NOTHING.bits,
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

    async fn recv(&self, buf: &mut [u8],flags: RecvFromFlags) -> SyscallResult<isize>{Err(Errno::EOPNOTSUPP)}

    async fn send(&self,buf: &[u8],flags: RecvFromFlags) -> SyscallResult<isize>{Err(Errno::EOPNOTSUPP)}
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
                    Ok(fd as usize)
                } else if socket_type.contains(SocketType::SOCK_STREAM) {
                    let socket = Arc::new(TcpSocket::new());
                    let mut proc_inner = current_process().inner.lock();
                    let fd = proc_inner.fd_table.put(FileDescriptor::new(socket.clone(), cloexec), 0)?;
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


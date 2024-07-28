use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use bitflags::bitflags;
use crate::fs::fd::FileDescriptor;
use crate::fs::file::File;
use crate::net::netaddress::SockAddr;
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
    fn bind(&self, addr: SockAddr) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    async fn connect(&self, addr: SockAddr) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    fn listen(&self) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    async fn accept(&self, addr: Option<&mut SockAddr>) -> SyscallResult<Arc<dyn Socket>> {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult;

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult;

    fn dis_connect(&self, how: u32) -> SyscallResult;

    fn socket_type(&self) -> SocketType;

    fn sock_name(&self) -> SockAddr;

    fn peer_name(&self) -> Option<SockAddr>;

    fn shutdown(&self, how: u32) -> SyscallResult;

    fn recv_buf_size(&self) -> SyscallResult<usize>;

    fn send_buf_size(&self) -> SyscallResult<usize>;

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    async fn recv(
        &self,
        buf: &mut [u8],
        flags: RecvFromFlags,
        src: Option<&mut SockAddr>,
    ) -> SyscallResult<isize> {
        Err(Errno::EOPNOTSUPP)
    }

    async fn send(
        &self,
        buf: &[u8],
        flags: RecvFromFlags,
        dest: Option<SockAddr>,
    ) -> SyscallResult<isize> {
        Err(Errno::EOPNOTSUPP)
    }
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
}


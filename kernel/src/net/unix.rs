use super::{Socket, SocketType};
use crate::fs::file::{File, FileMeta};
use crate::fs::pipe::Pipe;
use crate::result::{Errno, SyscallResult};
use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use log::info;
use crate::fs::ffi::OpenFlags;
use crate::net::netaddress::SockAddr;

pub struct UnixSocket {
    metadata: FileMeta,
    read_end: Arc<Pipe>,
    write_end: Arc<Pipe>,
}

#[async_trait]
impl File for UnixSocket {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    fn as_socket(self: Arc<Self>) -> SyscallResult<Arc<dyn Socket>> {
        Ok(self)
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        self.read_end.read(buf).await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        self.write_end.write(buf).await
    }
}

#[allow(unused)]
#[async_trait]
impl Socket for UnixSocket {
    fn set_send_buf_size(&self, size: usize) -> SyscallResult<()> {
        todo!()
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult<()> {
        todo!()
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        todo!()
    }

    fn socket_type(&self) -> SocketType {
        todo!()
    }

    fn sock_name(&self) -> SockAddr {
        todo!()
    }

    fn peer_name(&self) -> SyscallResult<SockAddr> {
        Err(Errno::EINVAL)
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        info!("[UnixSocket::shutdown] how {}", how);
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        todo!()
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        todo!()
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult {
        todo!()
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }
}

impl UnixSocket {
    pub fn new(read_end: Arc<Pipe>, write_end: Arc<Pipe>) -> Self {
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
            // buf: Mutex::new(VecDeque::new()),
            read_end,
            write_end,
        }
    }
}

pub fn make_unix_socket_pair() -> (Arc<UnixSocket>, Arc<UnixSocket>) {
    let (read1, write1) = Pipe::new();
    let (read2, write2) = Pipe::new();
    let socket1 = Arc::new(UnixSocket::new(read1, write2));
    let socket2 = Arc::new(UnixSocket::new(read2, write1));
    (socket1, socket2)
}

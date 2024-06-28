use super::{Socket, SocketType};
use crate::fs::devfs::unix_socket::UnixSockNode;
use crate::fs::ffi::InodeMode;
use crate::fs::file::{File, FileMeta};
use crate::fs::pipe::Pipe;
use crate::result::{Errno, SyscallResult};
use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use smoltcp::wire::IpEndpoint;

pub struct UnixSocket {
    file_meta: FileMeta,
    read_end: Arc<Pipe>,
    write_end: Arc<Pipe>,
}

#[async_trait]
impl File for UnixSocket {
    fn metadata(&self) -> &FileMeta {
        &self.file_meta
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        self.read_end.read(buf).await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        self.write_end.write(buf).await
    }
}
#[async_trait]
impl Socket for UnixSocket {
    fn bind(&self, addr: smoltcp::wire::IpListenEndpoint) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn listen(&self) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    async fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult<()> {
        todo!()
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult<()> {
        todo!()
    }

    fn set_keep_live(&self, enabled: bool) -> SyscallResult {
        todo!()
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        todo!()
    }

    fn socket_type(&self) -> SocketType {
        todo!()
    }

    fn local_endpoint(&self) -> SyscallResult<smoltcp::wire::IpListenEndpoint> {
        todo!()
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        None
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        log::info!("[UnixSocket::shutdown] how {}", how);
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        todo!()
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        todo!()
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }
}

impl UnixSocket {
    pub fn new(read_end: Arc<Pipe>, write_end: Arc<Pipe>) -> Self {
        let unix_node = UnixSockNode::new();
        Self {
            file_meta: FileMeta::new(Some(unix_node)),
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

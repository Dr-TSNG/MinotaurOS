use smoltcp::phy::Medium;
use smoltcp::wire::IpEndpoint;
use smoltcp::{iface::SocketHandle, wire::IpListenEndpoint};

use crate::fs::file::{File, FileMeta};
use crate::net::socket::Socket;
use crate::result::{MosResult, SyscallResult};
use crate::sync::mutex::Mutex;

pub struct TcpSocket {
    inner: Mutex<TcpInner>,
    socket_handle: SocketHandle,
    file_data: FileMeta,
}

struct TcpInner {
    local_endpoint: IpListenEndpoint,
    remote_endpoint: IpListenEndpoint,
    last_state: smoltcp::socket::tcp::State,
    recv_buf_size: usize,
    send_buf_size: usize,
}

impl TcpSocket {
    /// put this socket into INTERFACE's Sockets_Set and return a SocketHandle
    pub fn new() -> SocketHandle {
        todo!()
    }

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> MosResult<()> {
        todo!()
    }

    /// tcp_socket wait for a connection to it , if connected , return remote IpEndpoint
    fn tcp_accept(&self) -> MosResult<IpEndpoint> {
        todo!()
    }
}

impl File for TcpSocket {
    fn metadata(&self) -> &FileMeta {
        todo!()
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        todo!()
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        todo!()
    }
}

impl Socket for TcpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        todo!()
    }

    fn connect(&self, addr: &[u8]) -> SyscallResult {
        todo!()
    }

    fn listen(&self) -> SyscallResult {
        todo!()
    }

    fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult {
        todo!()
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult {
        let t = self.inner.lock();
        t.send_buf_size = size;
        Ok(())
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult {
        let t = self.inner.lock();
        t.recv_buf_size = size;
        Ok(())
    }

    fn set_keep_live(&self, enabled: bool) -> SyscallResult {
        todo!()
    }

    fn dis_connect(&self, enabled: bool) -> SyscallResult {
        todo!()
    }
}

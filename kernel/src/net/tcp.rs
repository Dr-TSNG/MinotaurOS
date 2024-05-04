use crate::fs::ffi::InodeMode::{FileFIFO, IFSOCK};
use alloc::vec;
use log::info;
use smoltcp::phy::Medium;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use smoltcp::{iface::SocketHandle, wire::IpListenEndpoint};

use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::port::{PortAllocator, PORT_ALLOCATOR};
use crate::net::socket::{Socket, SocketType, BUFFER_SIZE};
use crate::result::SyscallResult;
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
    pub fn new() -> Self {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        // 将socket加入interface，返回handler
        let handler = NET_INTERFACE.add_tcpsocket(socket);
        info!("[TcpSocket::new] new{}", handler);
        NET_INTERFACE.poll();
        // 没有处理分配完port，不能再多分配，返回None的情况。。。
        let port = PORT_ALLOCATOR.take().unwrap();
        info!("[TcpSocket handle{} : port is {}]", handler, port);
        Self {
            socket_handle: handler,
            inner: Mutex::new(TcpInner {
                local_endpoint: IpListenEndpoint { addr: None, port },
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
            file_data: FileMeta::new(Some(IFSOCK)),
        }
    }

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        todo!()
    }

    /// tcp_socket wait for a connection to it , if connected , return remote IpEndpoint
    fn tcp_accept(&self) -> SyscallResult<IpEndpoint> {
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

    fn socket_type(&self) -> SocketType {
        todo!()
    }
}

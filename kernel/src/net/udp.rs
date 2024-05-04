use alloc::boxed::Box;
use alloc::vec;

use smoltcp::iface::SocketHandle;
use smoltcp::socket;
use smoltcp::socket::udp::PacketMetadata;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::socket::SocketAddress;
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::socket::Socket;
use crate::net::socket::{SocketType, BUFFER_SIZE};
use crate::result::Errno::{EINVAL, EOPNOTSUPP};
use crate::result::SyscallResult;
use crate::sync::mutex::Mutex;

pub struct UdpSocket {
    inner: Mutex<UdpSocketInner>,
    socket_handler: SocketHandle,
    file_data: FileMeta,
}

struct UdpSocketInner {
    remote_endpoint: Option<IpEndpoint>,
    recvbuf_size: usize,
    sendbuf_size: usize,
}

impl UdpSocket {
    pub fn new() -> Self {
        let recv = smoltcp::socket::udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0 as u8; BUFFER_SIZE],
        );
        let send = smoltcp::socket::udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0 as u8; BUFFER_SIZE],
        );
        let socket = socket::udp::Socket::new(recv, send);
        let socket_handle = NET_INTERFACE.add_socket(socket);
        NET_INTERFACE.poll();
        Self {
            inner: Mutex::new(UdpSocketInner {
                remote_endpoint: None,
                recvbuf_size: BUFFER_SIZE,
                sendbuf_size: BUFFER_SIZE,
            }),
            socket_handler: socket_handle,
            file_data: FileMeta {
                inode: None,
                prw_lock: Default::default(),
                inner: Default::default(),
            },
        }
    }
}

impl File for UdpSocket {
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

impl Socket for UdpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| {
            socket.bind(addr).ok().ok_or(SyscallResult::Err(EINVAL))
        })?;
        NET_INTERFACE.poll();
        Ok(())
    }

    fn connect<'a>(&'a self, addr: &'a [u8]) -> SyscallResult {
        Box::pin(async move {
            let remote_endpoint;
        });
    }

    fn listen(&self) -> SyscallResult {
        SyscallResult::Err(EOPNOTSUPP)
    }

    fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult {
        todo!()
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().sendbuf_size = size;
        Ok(())
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().recvbuf_size = size;
        Ok(())
    }

    fn set_keep_live(&self, enabled: bool) -> SyscallResult {
        SyscallResult::Err(EOPNOTSUPP)
    }

    fn dis_connect(&self, enabled: bool) -> SyscallResult {
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        1 << 1.into()
    }
}

/*
impl Socket for UdpSocket{

}

 */

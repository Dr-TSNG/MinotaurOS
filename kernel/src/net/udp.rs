use alloc::boxed::Box;
use alloc::vec;
use async_trait::async_trait;
use log::info;

use smoltcp::iface::SocketHandle;
use smoltcp::socket;
use smoltcp::socket::udp::PacketMetadata;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::socket::Socket;
use crate::net::socket::{endpoint, SocketAddressV4, SocketType, BUFFER_SIZE};
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
        log::info!("[UdpSocket::new] new {}", socket_handle);
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

#[async_trait]
impl Socket for UdpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        NET_INTERFACE.poll();
        let ret = NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| socket.bind(addr));
        if ret.is_err() == true {
            return Err(EINVAL);
        }
        NET_INTERFACE.poll();
        Ok(())
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        // let fut = Box::pin(async move {

        let remote_endpoint = endpoint(addr)?;
        let mut inner = self.inner.lock();
        inner.remote_endpoint = Some(remote_endpoint);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| {
            let local = socket.endpoint();
            if local.port == 0 {
                let addr = SocketAddressV4::new([0; 16].as_slice());
                let endpoint = IpListenEndpoint::from(addr);
                let ret = socket.bind(endpoint);
                if ret.is_err() {
                    return match ret.err().unwrap() {
                        socket::udp::BindError::Unaddressable => {
                            info!("[Udp::bind] unaddr");
                            Err(EINVAL)
                        }
                        socket::udp::BindError::InvalidState => {
                            info!("[Udp::bind] invaild state");
                            Err(EINVAL)
                        }
                    };
                }
                log::info!("[Udp::bind] bind to {:?}", endpoint);
                Ok(())
            } else {
                // log::info!("[Udp::bind] bind to {:?}", remote_endpoint);
                Ok(())
            }
        })?;
        NET_INTERFACE.poll();
        return SyscallResult::Ok(());
        //});
        //fut.await
    }

    async fn listen(&self) -> SyscallResult {
        SyscallResult::Err(EOPNOTSUPP)
    }

    async fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult {
        SyscallResult::Err(EOPNOTSUPP)
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

    fn dis_connect(&self, how: u32) -> SyscallResult {
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_DGRAM
    }

    fn local_endpoint(&self) -> SyscallResult<IpListenEndpoint> {
        todo!()
    }
}

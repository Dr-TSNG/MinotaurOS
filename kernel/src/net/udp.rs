#![allow(unused)]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use log::{debug, info, log};
use managed::{Managed, ManagedSlice};

use crate::fs::devfs::net::NetInode;
use crate::fs::fd::FileDescriptor;
use crate::fs::ffi::{InodeMode, OpenFlags};
use smoltcp::iface::SocketHandle;
use smoltcp::phy::PacketMeta;
use smoltcp::socket;
use smoltcp::socket::udp::{PacketMetadata, SendError, UdpMetadata};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use xmas_elf::program::Flags;

use crate::fs::file::{File, FileMeta, Seek};
use crate::fs::inode::Inode;
use crate::net::iface::NET_INTERFACE;
use crate::net::MAX_BUFFER_SIZE;
use crate::net::socket::Socket;
use crate::net::socket::{endpoint, SocketAddressV4, SocketType, BUFFER_SIZE};
use crate::process::thread::event_bus::Event;
use crate::processor::current_thread;
use crate::result::Errno::{EAGAIN, EINVAL, ENOBUFS, ENOTCONN, EOPNOTSUPP};
use crate::result::{Errno, SyscallResult};
use crate::sched::{sleep_for, yield_now};
use crate::sync::mutex::Mutex;

pub struct UdpSocket {
    inner: Mutex<UdpSocketInner>,
    socket_handler: SocketHandle,
    pub file_data: FileMeta,
}
struct UdpSocketInner {
    remote_endpoint: Option<IpEndpoint>,
    recvbuf_size: usize,
    sendbuf_size: usize,
}
impl UdpSocket {
    pub fn new() -> Self {
        let recv = socket::udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; BUFFER_SIZE],
        );
        let send = socket::udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; BUFFER_SIZE],
        );
        let socket = socket::udp::Socket::new(recv, send);
        let socket_handle = NET_INTERFACE.add_socket(socket);
        info!("[UdpSocket::new] new {}", socket_handle);
        NET_INTERFACE.poll();
        let mut file_data = FileMeta::new(None);
        let net_inode = NetInode::new();
        file_data.inode = Option::from(net_inode as Arc<dyn Inode>);
        Self {
            inner: Mutex::new(UdpSocketInner {
                remote_endpoint: None,
                recvbuf_size: BUFFER_SIZE,
                sendbuf_size: BUFFER_SIZE,
            }),
            socket_handler: socket_handle,
            file_data,
        }
    }
}
#[async_trait]
impl File for UdpSocket {
    fn metadata(&self) -> &FileMeta {
        &self.file_data
    }
    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        Err(EINVAL)
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        Err(EINVAL)
    }
    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        debug!("[Udp::pollin] {} enter", self.socket_handler);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| {
            if socket.can_recv() {
                log::info!("[Udp::pollin] {} recv buf have item", self.socket_handler);
                Ok(true)
            } else {
                if let Some(waker) = waker {
                    socket.register_recv_waker(&waker);
                }
                Ok(false)
            }
        })
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        debug!("[Udp::pollout] {} enter", self.socket_handler);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| {
            if socket.can_send() {
                log::info!("[Udp::pollout] {} tx buf have slots", self.socket_handler);
                Ok(true)
            } else {
                if let Some(waker) = waker {
                    socket.register_send_waker(&waker);
                }
                Ok(false)
            }
        })
    }

    async fn socket_read(&self, buf: &mut [u8], flags: OpenFlags) -> SyscallResult<isize> {
        log::info!("[Ucp::read] {} enter", self.socket_handler);

        let future = current_thread().event_bus.suspend_with(
            Event::KILL_THREAD,
            UdpRecvFuture::new(self,buf,flags),
        );
        match future.await {
            Ok(len) => {
                if len> MAX_BUFFER_SIZE/2{
                    // need to be slow
                    sleep_for(Duration::from_millis(2)).await;
                }else{
                    // for one heart
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => {Err(e)}
        }
    }

    async fn socket_write(&self, buf: &[u8], flags: OpenFlags) -> SyscallResult<isize> {
        log::info!("[Udp::write] {} enter", self.socket_handler);
        let future = current_thread().event_bus.suspend_with(
            Event::KILL_THREAD,
            UdpSendFuture::new(self,buf,flags),
        );
        match future.await {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    // need to be slow
                    sleep_for(Duration::from_millis(2)).await;
                } else {
                    // for one heart
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => {
                Err(e)
            }
        }
    }
}
#[async_trait]
impl Socket for UdpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult<usize> {
        NET_INTERFACE.poll();
        let ret = NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| socket.bind(addr));
        if ret.is_err() == true {
            return Err(EINVAL);
        }
        NET_INTERFACE.poll();
        Ok(0)
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult<usize> {
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
                info!("[Udp::bind] bind to {:?}", endpoint);
                Ok(())
            } else {
                // log::info!("[Udp::bind] bind to {:?}", remote_endpoint);
                Ok(())
            }
        })?;
        NET_INTERFACE.poll();
        return Ok(0);
        //});
        //fut.await
    }

    fn listen(&self) -> SyscallResult<usize> {
        Err(EOPNOTSUPP)
    }

    async fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        Err(EOPNOTSUPP)
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
        Err(EOPNOTSUPP)
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_DGRAM
    }

    fn local_endpoint(&self) -> SyscallResult<IpListenEndpoint> {
        NET_INTERFACE.poll();
        let local =
            NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| socket.endpoint());
        NET_INTERFACE.poll();
        Ok(local)
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        self.inner.lock().remote_endpoint
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        log::info!("[UdpSocket::shutdown] how {}", how);
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recvbuf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().sendbuf_size)
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        Err(Errno::EOPNOTSUPP)
    }
}
impl Drop for UdpSocket {
    fn drop(&mut self) {
        info!(
            "[UdpSocket::drop] drop socket {}, remote endpoint {:?}",
            self.socket_handler,
            self.inner.lock().remote_endpoint
        );
        NET_INTERFACE.handle_udp_socket(self.socket_handler, |socket| {
            if socket.is_open() {
                socket.close();
            }
        });
        NET_INTERFACE.remove(self.socket_handler);
        NET_INTERFACE.poll();
    }
}

struct UdpRecvFuture<'a> {
    socket: &'a UdpSocket,
    buf: ManagedSlice<'a, u8>,
    flags: OpenFlags,
}
impl<'a> UdpRecvFuture<'a> {
    fn new<S>(socket: &'a UdpSocket, buf: S, flags: OpenFlags) -> Self
    where
        S: Into<ManagedSlice<'a, u8>>,
    {
        Self {
            socket,
            buf: buf.into(),
            flags,
        }
    }
}
impl<'a> Future for UdpRecvFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        NET_INTERFACE.poll();
        let ret = NET_INTERFACE.handle_udp_socket(self.socket.socket_handler, |socket| {
            if !socket.can_recv() {
                info!("[UdpRecvFuture::poll] cannot recv yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
                    info!("[UdpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(EAGAIN));
                }
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpRecvFuture::poll] start to recv...");
            let this = self.get_mut();
            Poll::Ready({
                let (ret, meta) = socket.recv_slice(&mut this.buf).ok().ok_or(ENOTCONN)?;
                let remote = Some(meta.endpoint);
                info!(
                    "[UdpRecvFuture::poll] {:?} <- {:?}",
                    socket.endpoint(),
                    remote
                );
                this.socket.inner.lock().remote_endpoint = remote;
                debug!("[UdpRecvFuture::poll] recv {} bytes", ret);
                Ok(ret)
            })
        });
        NET_INTERFACE.poll();
        ret
    }
}
struct UdpSendFuture<'a> {
    socket: &'a UdpSocket,
    buf: &'a [u8],
    flags: OpenFlags,
}
impl<'a> UdpSendFuture<'a> {
    fn new(socket: &'a UdpSocket, buf: &'a [u8], flags: OpenFlags) -> Self {
        Self { socket, buf, flags }
    }
}
impl<'a> Future for UdpSendFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        NET_INTERFACE.poll();
        let ret = NET_INTERFACE.handle_udp_socket(self.socket.socket_handler, |socket| {
            if !socket.can_send() {
                info!("[UdpSendFuture::poll] cannot send yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
                    info!("[UdpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(EAGAIN));
                }
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpSendFuture::poll] start to send...");
            let remote = self.socket.inner.lock().remote_endpoint;
            let this = self.get_mut();
            let meta = UdpMetadata {
                endpoint: remote.unwrap(),
                meta: PacketMeta::default(),
            };
            let len = this.buf.len();
            info!(
                "[UdpSendFuture::poll] {:?} -> {:?}",
                socket.endpoint(),
                remote
            );
            let ret = socket.send_slice(&this.buf, meta);
            Poll::Ready(if let Some(err) = ret.err() {
                if err == SendError::Unaddressable {
                    Err(ENOTCONN)
                } else {
                    Err(ENOBUFS)
                }
            } else {
                debug!("[UdpSendFuture::poll] send {} bytes", len);
                Ok(len)
            })
        });
        NET_INTERFACE.poll();
        ret
    }
}

use alloc::boxed::Box;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use log::{debug, info, warn};
use managed::ManagedSlice;
use crate::fs::ffi::OpenFlags;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::PacketMeta;
use smoltcp::socket::udp;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::MAX_BUFFER_SIZE;
use crate::net::socket::Socket;
use crate::net::socket::{endpoint, SocketAddressV4, SocketType, BUFFER_SIZE};
use crate::result::{Errno, SyscallResult};
use crate::sched::{sleep_for, yield_now};
use crate::sync::mutex::Mutex;

pub struct UdpSocket {
    metadata: FileMeta,
    inner: Mutex<UdpSocketInner>,
}

struct UdpSocketInner {
    handle: SocketHandle,
    remote_endpoint: Option<IpEndpoint>,
    recvbuf_size: usize,
    sendbuf_size: usize,
}

impl UdpSocket {
    pub fn new() -> Self {
        let recv = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
            vec![0u8; BUFFER_SIZE],
        );
        let send = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
            vec![0u8; BUFFER_SIZE],
        );
        let socket = udp::Socket::new(recv, send);
        let handle = NET_INTERFACE.add_socket(socket);
        info!("[udp] New socket handle {}", handle);
        NET_INTERFACE.poll();
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
            inner: Mutex::new(UdpSocketInner {
                handle,
                remote_endpoint: None,
                recvbuf_size: BUFFER_SIZE,
                sendbuf_size: BUFFER_SIZE,
            }),
        }
    }
}
#[async_trait]
impl File for UdpSocket {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        debug!("[udp] Read on {}", self.inner.lock().handle);
        let flags = self.metadata.flags.lock();
        match UdpRecvFuture::new(self, buf, *flags).await {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    sleep_for(Duration::from_millis(2)).await?;
                } else {
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => Err(e),
        }
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        debug!("[udp] Write on {}", self.inner.lock().handle);
        let flags = self.metadata().flags.lock();
        match UdpSendFuture::new(self, buf, *flags).await {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    sleep_for(Duration::from_millis(2)).await?;
                } else {
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => Err(e),
        }
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let handle = self.inner.lock().handle;
        debug!("[udp] Pollin for {}", handle);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(handle, |socket| {
            if socket.can_recv() {
                debug!("[udp] Pollin {} recv buf have item", handle);
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
        let handle = self.inner.lock().handle;
        debug!("[udp] Pollout for {}", handle);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(handle, |socket| {
            if socket.can_send() {
                debug!("[udp] Pollout {} tx buf have slots", handle);
                Ok(true)
            } else {
                if let Some(waker) = waker {
                    socket.register_send_waker(&waker);
                }
                Ok(false)
            }
        })
    }
}

#[async_trait]
impl Socket for UdpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        let handle = self.inner.lock().handle;
        NET_INTERFACE.poll();
        if let Err(e) = NET_INTERFACE.handle_udp_socket(handle, |socket| socket.bind(addr)) {
            warn!("[udp] Bind failed for {}: {:?}", handle, e);
            return Err(Errno::EINVAL);
        }
        NET_INTERFACE.poll();
        Ok(())
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        let remote_endpoint = endpoint(addr)?;
        let mut inner = self.inner.lock();
        inner.remote_endpoint = Some(remote_endpoint);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_udp_socket(inner.handle, |socket| {
            let local = socket.endpoint();
            if local.port == 0 {
                let addr = SocketAddressV4::new([0; 16].as_slice());
                let endpoint = IpListenEndpoint::from(addr);
                if let Err(e) = socket.bind(endpoint) {
                    warn!("[udp] Bind failed for {}: {:?}", inner.handle, e);
                    return Err(Errno::EINVAL);
                }
                info!("[udp] Bound {} to {:?}", inner.handle, endpoint);
                Ok(())
            } else {
                // log::info!("[Udp::bind] bind to {:?}", remote_endpoint);
                Ok(())
            }
        })?;
        NET_INTERFACE.poll();
        Ok(())
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().sendbuf_size = size;
        Ok(())
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().recvbuf_size = size;
        Ok(())
    }

    fn set_keep_live(&self, _enabled: bool) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }

    fn dis_connect(&self, _how: u32) -> SyscallResult {
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_DGRAM
    }

    fn local_endpoint(&self) -> IpListenEndpoint {
        let handle = self.inner.lock().handle;
        NET_INTERFACE.poll();
        let local =
            NET_INTERFACE.handle_udp_socket(handle, |socket| socket.endpoint());
        NET_INTERFACE.poll();
        local
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        self.inner.lock().remote_endpoint
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        info!("[UdpSocket::shutdown] how {}", how);
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recvbuf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().sendbuf_size)
    }
}
impl Drop for UdpSocket {
    fn drop(&mut self) {
        let handle = self.inner.lock().handle;
        info!(
            "[UdpSocket::drop] drop socket {}, remote endpoint {:?}",
            handle,
            self.inner.lock().remote_endpoint
        );
        NET_INTERFACE.handle_udp_socket(handle, |socket| {
            if socket.is_open() {
                socket.close();
            }
        });
        NET_INTERFACE.remove(handle);
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
        let handle = self.socket.inner.lock().handle;
        let ret = NET_INTERFACE.handle_udp_socket(handle, |socket| {
            if !socket.can_recv() {
                info!("[UdpRecvFuture::poll] cannot recv yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
                    info!("[UdpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpRecvFuture::poll] start to recv...");
            let this = self.get_mut();
            Poll::Ready({
                let (ret, meta) = socket.recv_slice(&mut this.buf).ok().ok_or(Errno::ENOTCONN)?;
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
        let handle = self.socket.inner.lock().handle;
        let ret = NET_INTERFACE.handle_udp_socket(handle, |socket| {
            if !socket.can_send() {
                info!("[UdpSendFuture::poll] cannot send yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
                    info!("[UdpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpSendFuture::poll] start to send...");
            let remote = self.socket.inner.lock().remote_endpoint;
            let this = self.get_mut();
            let meta = udp::UdpMetadata {
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
                if err == udp::SendError::Unaddressable {
                    Err(Errno::ENOTCONN)
                } else {
                    Err(Errno::ENOBUFS)
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

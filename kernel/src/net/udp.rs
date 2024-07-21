use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use futures::future::{Either, select};
use log::{debug, info};
use crate::fs::ffi::OpenFlags;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::PacketMeta;
use smoltcp::socket::udp;
use smoltcp::socket::udp::{PacketMetadata, SendError, UdpMetadata};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::{MAX_BUFFER_SIZE, RecvFromFlags};
use crate::net::netaddress::{endpoint, is_local, SocketAddressV4};
use crate::net::socket::{Socket};
use crate::net::socket::{SocketType, BUFFER_SIZE};
use crate::result::{Errno, SyscallResult};
use crate::result::Errno::EOPNOTSUPP;
use crate::sched::{sleep_for, yield_now};
use crate::sync::mutex::Mutex;

pub struct UdpSocket {
    metadata: FileMeta,
    inner: Mutex<UdpSocketInner>,
}

struct UdpSocketInner {
    handle_loop: SocketHandle,
    handle_dev: SocketHandle,
    local_endpoint: IpListenEndpoint,
    remote_endpoint: Option<IpEndpoint>,
    recvbuf_size: usize,
    sendbuf_size: usize,
}

impl UdpSocket {
    pub fn new() -> Self {
        let tx_buf = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; MAX_BUFFER_SIZE],
        );
        let rx_buf = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; MAX_BUFFER_SIZE],
        );
        let socket_loop = udp::Socket::new(rx_buf, tx_buf);

        let tx_buf = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; MAX_BUFFER_SIZE],
        );
        let rx_buf = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; MAX_BUFFER_SIZE],
        );
        let socket_dev = udp::Socket::new(rx_buf, tx_buf);
        let (handle_loop, handle_dev) = NET_INTERFACE.lock().add_socket(socket_loop, socket_dev);
        info!("[UdpSocket::new] new (handler_loop {}, handler_dev {})", handle_loop, handle_dev);
        Self {
            metadata: FileMeta::new(None, OpenFlags::O_RDWR),
            inner: Mutex::new(UdpSocketInner {
                handle_dev,
                handle_loop,
                remote_endpoint: None,
                local_endpoint: IpListenEndpoint::default(),
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

    fn as_socket(self: Arc<Self>) -> SyscallResult<Arc<dyn Socket>> {
        Ok(self)
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        drop(inner);
        info!("[Ucp::read] ({}, {}) enter", handle_loop, handle_dev);
        let flags = self.metadata().flags.lock();
        let mut flags_recv = RecvFromFlags::default();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_recv = RecvFromFlags::MSG_DONTWAIT;
        }
        self.recv(buf, flags_recv).await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        drop(inner);
        info!("[Ucp::read] ({}, {}) enter", handle_loop, handle_dev);
        let flags = self.metadata().flags.lock();
        let mut flags_recv = RecvFromFlags::default();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_recv = RecvFromFlags::MSG_DONTWAIT;
        }
        self.send(buf, flags_recv).await
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        info!(
            "[Udp::pollin] (handle_loop {}, handle_dev {}) enter",
            inner.handle_loop, inner.handle_dev
        );
        let poll_func = |socket: &mut udp::Socket<'_>| {
            if socket.can_recv() {
                info!(
                    "[Udp::pollin] (handle_loop {}, handle_dev {}) recv buf have item",
                    inner.handle_loop,
                    inner.handle_dev,
                );
                true
            } else {
                if let Some(waker) = waker.clone() {
                    socket.register_recv_waker(&waker);
                }
                false
            }
        };
        let mut net = NET_INTERFACE.lock();
        net.poll_all();
        Ok(poll_func(net.sockets_loop.get_mut(inner.handle_loop))
            || poll_func(net.sockets_dev.get_mut(inner.handle_dev)))
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        info!(
            "[Udp::pollout] (handle_loop {}, handle_dev {}) enter",
            inner.handle_loop, inner.handle_dev
        );
        let is_local = is_local(self.remote_endpoint().unwrap());
        let poll_func = |socket: &mut udp::Socket<'_>| {
            if socket.can_send() {
                info!(
                    "[Udp::pollout] (handle_loop {}, handle_dev {}) tx buf have slots",
                    inner.handle_loop,
                    inner.handle_dev,
                );
                true
            } else {
                if let Some(waker) = waker {
                    socket.register_send_waker(&waker);
                }
                false
            }
        };
        let mut net = NET_INTERFACE.lock();
        net.poll(is_local);
        if is_local {
            Ok(poll_func(net.sockets_loop.get_mut(inner.handle_loop)))
        } else {
            Ok(poll_func(net.sockets_dev.get_mut(inner.handle_dev)))
        }
    }
}

#[async_trait]
impl Socket for UdpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        let mut inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        info!("[Udp::bind] bind to {:?}", addr);
        let socket = net.sockets_loop.get_mut::<udp::Socket>(inner.handle_loop);
        socket.bind(addr).ok().ok_or(Errno::EINVAL)?;
        let socket = net.sockets_dev.get_mut::<udp::Socket>(inner.handle_dev);
        socket.bind(addr).ok().ok_or(Errno::EINVAL)?;
        inner.local_endpoint = addr;
        Ok(())
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        let remote_endpoint = endpoint(addr)?;
        let mut inner = self.inner.lock();
        inner.remote_endpoint = Some(remote_endpoint);
        let is_local = is_local(remote_endpoint);

        let poll_func = |socket: &mut udp::Socket<'_>| {
            let local = socket.endpoint();
            info!("[Udp::connect] local: {:?}", local);
            if local.port == 0 {
                info!("[Udp::connect] don't have local");
                let addr = SocketAddressV4::new([0; 16].as_slice());
                let endpoint = IpListenEndpoint::from(addr);
                let ret = socket.bind(endpoint);
                if ret.is_err() {
                    return match ret.err().unwrap() {
                        udp::BindError::Unaddressable => {
                            info!("[Udp::bind] unaddr");
                            Err(Errno::EINVAL)
                        }
                        udp::BindError::InvalidState => {
                            info!("[Udp::bind] invaild state");
                            Err(Errno::EINVAL)
                        }
                    };
                }
                info!("[Udp::bind] bind to {:?}", endpoint);
                Ok(())
            } else {
                Ok(())
            }
        };
        info!("udp connect");
        info!("is_local: {}",is_local);
        info!("udp connect to : {} ... ", remote_endpoint);
        let mut net = NET_INTERFACE.lock();
        if is_local {
            poll_func(net.sockets_loop.get_mut(inner.handle_loop))?;
        } else {
            poll_func(net.sockets_dev.get_mut(inner.handle_dev))?;
        }
        info!("OK");
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
        Err(EOPNOTSUPP)
    }

    fn dis_connect(&self, _how: u32) -> SyscallResult {
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_DGRAM
    }

    fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner.lock().local_endpoint
        /*
        let handle = self.inner.lock().handle_loop;
        NET_INTERFACE.poll();
        let local =
            NET_INTERFACE.handle_udp_socket(handle, |socket| socket.endpoint());
        NET_INTERFACE.poll();
        local
         */
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

    async fn recv(&self, buf: &mut [u8], flags: RecvFromFlags) -> SyscallResult<isize> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        drop(inner);
        info!("[Ucp::recv] ({}, {}) enter", handle_loop, handle_dev);
        let buf_start = buf.as_ptr() as usize;
        // back loop dev
        let future1 = UdpRecvFuture::new(self, buf_start, buf.len(), flags, true);
        // os virt-net dev
        let future2 = UdpRecvFuture::new(self, buf_start, buf.len(), flags, false);
        match select(future1, future2).await {
            Either::Left((len, _)) => match len {
                Ok(len) => {
                    if len > MAX_BUFFER_SIZE / 2 {
                        // need to be slow
                        sleep_for(Duration::from_millis(1)).await?;
                    } else {
                        yield_now().await;
                    }
                    Ok(len as isize)
                }
                Err(e) => {
                    Err(e)
                }
            }
            Either::Right((len, _)) => match len {
                Ok(len) => {
                    if len > MAX_BUFFER_SIZE / 2 {
                        // need to be slow
                        sleep_for(Duration::from_millis(1)).await?;
                    } else {
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

    async fn send(&self, buf: &[u8], flags: RecvFromFlags) -> SyscallResult<isize> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        drop(inner);
        info!("[Ucp::recv] ({}, {}) enter",handle_loop,handle_dev);
        let future = UdpSendFuture::new(self, buf, flags);
        let ret = future.await;
        match ret {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    // need to be slow
                    sleep_for(Duration::from_millis(1)).await?;
                } else {
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => { Err(e) }
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        /*
        info!(
            "[UdpSocket::drop] drop socket (handle_loop {}, handle_dev {}), remoteep {:?}",
            self.inner.lock().handle_loop,
            self.inner.lock().handle_dev,
            self.inner.lock().remote_endpoint
        );
         */
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets_loop.get_mut::<udp::Socket>(inner.handle_loop);
        if socket.is_open() {
            socket.close();
        }
        let socket = net.sockets_dev.get_mut::<udp::Socket>(inner.handle_dev);
        if socket.is_open() {
            socket.close();
        }
        net.remove(inner.handle_loop, inner.handle_dev);
        info!("[udp::drop] ok");
        net.poll_all();
    }
}

struct UdpRecvFuture<'a> {
    socket: &'a UdpSocket,
    // buf: ManagedSlice<'a, u8>,
    buf_start: usize,
    buf_len: usize,
    flags: RecvFromFlags,
    for_loop: bool,
}
impl<'a> UdpRecvFuture<'a> {
    fn new(
        socket: &'a UdpSocket,
        buf_start: usize,
        buf_len: usize,
        flags: RecvFromFlags,
        for_loop: bool,
    ) -> Self {
        Self {
            socket,
            buf_start,
            buf_len,
            flags,
            for_loop,
        }
    }
}
impl<'a> Future for UdpRecvFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        info!("[sys_recvfrom] poll_all failed in ref NET_DEVICE because it is None");
        let mut inner = self.socket.inner.lock();
        let mut net = NET_INTERFACE.lock();
        net.poll_all();
        if self.for_loop {
            // 本地网络
            let socket = net.sockets_loop.get_mut::<udp::Socket>(inner.handle_loop);
            let this = self.get_mut();
            if !socket.can_recv() {
                info!("[UdpRecvFuture::poll] cannot recv yet");
                if this.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[UdpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpRecvFuture::poll] start to recv...");
            let (ret, remote) = if this.flags.bits() & RecvFromFlags::MSG_PEEK.bits() > 0 {
                info!("[UdpRecvFuture::poll] get flags MSG_PEEK");
                let (ret, meta) = socket
                    .peek_slice(unsafe {
                        &mut core::slice::from_raw_parts_mut(
                            this.buf_start as *mut u8,
                            this.buf_len,
                        )
                    })
                    .ok()
                    .ok_or(Errno::ENOTCONN)?;
                let endpoint = meta.endpoint;
                (ret, endpoint)
            } else {
                let (ret, meta) = socket
                    .recv_slice(unsafe {
                        &mut core::slice::from_raw_parts_mut(
                            this.buf_start as *mut u8,
                            this.buf_len,
                        )
                    }).ok().ok_or(Errno::ENOTCONN)?;
                let endpoint = meta.endpoint;
                (ret, endpoint)
            };
            info!("[UdpRecvFuture::poll] {:?} <- {:?}", socket.endpoint(), remote);
            inner.remote_endpoint = Some(remote);
            info!("[UdpRecvFuture::poll] recv {} bytes", ret);
            Poll::Ready(Ok(ret))
        } else {
            let socket = net.sockets_dev.get_mut::<udp::Socket>(inner.handle_dev);
            let this = self.get_mut();
            if !socket.can_recv() {
                info!("[UdpRecvFuture::poll] cannot recv yet");
                if this.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[UdpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpRecvFuture::poll] start to recv...");
            let (ret, remote) = if this.flags.bits() & RecvFromFlags::MSG_PEEK.bits() > 0 {
                info!("[UdpRecvFuture::poll] get flags MSG_PEEK");
                let (ret, meta) = socket
                    .peek_slice(unsafe {
                        &mut core::slice::from_raw_parts_mut(
                            this.buf_start as *mut u8,
                            this.buf_len,
                        )
                    })
                    .ok()
                    .ok_or(Errno::ENOTCONN)?;
                let endpoint = meta.endpoint;
                (ret, endpoint)
            } else {
                let (ret, meta) = socket
                    .recv_slice(unsafe {
                        &mut core::slice::from_raw_parts_mut(
                            this.buf_start as *mut u8,
                            this.buf_len,
                        )
                    })
                    .ok()
                    .ok_or(Errno::ENOTCONN)?;
                let endpoint = meta.endpoint;
                (ret, endpoint)
            };
            info!("[UdpRecvFuture::poll] {:?} <- {:?}", socket.endpoint(), remote);
            inner.remote_endpoint = Some(remote);
            info!("[UdpRecvFuture::poll] recv {} bytes", ret);
            Poll::Ready(Ok(ret))
        }
    }
}

struct UdpSendFuture<'a> {
    socket: &'a UdpSocket,
    buf: &'a [u8],
    flags: RecvFromFlags,
}

impl<'a> UdpSendFuture<'a> {
    fn new(socket: &'a UdpSocket, buf: &'a [u8], flags: RecvFromFlags) -> Self {
        Self { socket, buf, flags }
    }
}

impl<'a> Future for UdpSendFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let is_local = is_local(self.socket.remote_endpoint().unwrap());
        let inner = self.socket.inner.lock();
        let mut net = NET_INTERFACE.lock();
        net.poll(is_local);
        let ret = if is_local {
            let socket = net.sockets_loop.get_mut::<udp::Socket>(inner.handle_loop);
            if !socket.can_send() {
                info!("[UdpSendFuture::poll] cannot send yet");
                if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[UdpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpSendFuture::poll] start to send...");
            let this = self.get_mut();
            let meta = UdpMetadata {
                endpoint: inner.remote_endpoint.unwrap(),
                meta: PacketMeta::default(),
            };
            let len = this.buf.len();
            info!(
                    "[UdpSendFuture::poll] {:?} -> {:?}",
                    socket.endpoint(),
                    inner.remote_endpoint
                );
            let ret = socket.send_slice(&this.buf, meta);
            Poll::Ready(if let Some(err) = ret.err() {
                if err == SendError::Unaddressable {
                    Err(Errno::ENOTCONN)
                } else {
                    Err(Errno::ENOBUFS)
                }
            } else {
                debug!("[UdpSendFuture::poll] send {} bytes", len);
                Ok(len)
            })
        } else {
            let socket = net.sockets_dev.get_mut::<udp::Socket>(inner.handle_dev);
            if !socket.can_send() {
                info!("[UdpSendFuture::poll] cannot send yet");
                if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[UdpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[UdpSendFuture::poll] start to send...");
            let this = self.get_mut();
            let meta = UdpMetadata {
                endpoint: inner.remote_endpoint.unwrap(),
                meta: PacketMeta::default(),
            };
            let len = this.buf.len();
            info!(
                    "[UdpSendFuture::poll] {:?} -> {:?}",
                    socket.endpoint(),
                    inner.remote_endpoint
                );
            let ret = socket.send_slice(&this.buf, meta);
            Poll::Ready(if let Some(err) = ret.err() {
                if err == SendError::Unaddressable {
                    Err(Errno::ENOTCONN)
                } else {
                    Err(Errno::ENOBUFS)
                }
            } else {
                debug!("[UdpSendFuture::poll] send {} bytes", len);
                Ok(len)
            })
        };
        net.poll(is_local);
        ret
    }
}

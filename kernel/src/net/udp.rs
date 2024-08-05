use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::ops::DerefMut;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use log::{error, info, warn};
use crate::fs::ffi::OpenFlags;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::PacketMeta;
use smoltcp::socket::udp;
use smoltcp::socket::udp::{PacketMetadata, RecvError, SendError, UdpMetadata};
use smoltcp::wire::IpEndpoint;
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::RecvFromFlags;
use crate::net::netaddress::{SockAddr, SockAddrIn4, specify_ipep, unspecified_ipep};
use crate::net::socket::{Socket};
use crate::net::socket::{SocketType, BUFFER_SIZE};
use crate::result::{Errno, SyscallResult};
use crate::result::Errno::EOPNOTSUPP;
use crate::sync::mutex::Mutex;

pub struct UdpSocket {
    metadata: FileMeta,
    handle: SocketHandle,
    inner: Mutex<UdpInner>,
}

struct UdpInner {
    local_endpoint: Option<IpEndpoint>,
    remote_endpoint: Option<IpEndpoint>,
    recvbuf_size: usize,
    sendbuf_size: usize,
}

impl UdpSocket {
    pub fn new() -> Self {
        let tx_buf = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; BUFFER_SIZE],
        );
        let rx_buf = udp::PacketBuffer::new(
            vec![PacketMetadata::EMPTY, PacketMetadata::EMPTY],
            vec![0u8; BUFFER_SIZE],
        );
        let socket = udp::Socket::new(rx_buf, tx_buf);
        let mut net = NET_INTERFACE.lock();
        let handle = net.sockets.add(socket);
        info!("[udp] Create new socket: handle {}", handle);
        Self {
            metadata: FileMeta::new(None, OpenFlags::O_RDWR),
            handle,
            inner: Mutex::new(UdpInner {
                local_endpoint: None,
                remote_endpoint: None,
                recvbuf_size: BUFFER_SIZE,
                sendbuf_size: BUFFER_SIZE,
            }),
        }
    }

    fn do_bind(&self, mut ep: IpEndpoint) -> SyscallResult {
        let mut inner = self.inner.lock();
        if inner.local_endpoint.is_some() {
            return Err(Errno::EINVAL);
        }
        let mut net = NET_INTERFACE.lock();
        specify_ipep(&mut net, &mut ep);
        let socket = net.sockets.get_mut::<udp::Socket>(self.handle);
        socket.bind(ep).unwrap();
        inner.local_endpoint = Some(ep);
        info!("[udp] (handle {}) bind to {}", self.handle, ep);
        Ok(())
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
        let flags = self.metadata().flags.lock();
        let mut flags_recv = RecvFromFlags::default();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_recv = RecvFromFlags::MSG_DONTWAIT;
        }
        self.recv(buf, flags_recv, None).await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let flags = self.metadata().flags.lock();
        let mut flags_recv = RecvFromFlags::default();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_recv = RecvFromFlags::MSG_DONTWAIT;
        }
        self.send(buf, flags_recv, None).await
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        info!("[udp] (handle {}) pollin", self.handle);
        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<udp::Socket>(self.handle);
        if socket.can_recv() {
            info!("[udp] (handle {}) pollin: rx buf have data", self.handle);
            Ok(true)
        } else {
            info!("[udp] (handle {}) pollin: rx buf empty, register waker", self.handle);
            if let Some(waker) = waker.clone() {
                socket.register_recv_waker(&waker);
            }
            Ok(false)
        }
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        info!("[udp] (handle {}) pollout", self.handle);
        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<udp::Socket>(self.handle);
        if socket.can_send() {
            info!("[udp] (handle {}) pollout: tx buf have space", self.handle);
            Ok(true)
        } else {
            info!("[udp] (handle {}) pollout: tx buf full, register waker", self.handle);
            if let Some(waker) = waker.clone() {
                socket.register_send_waker(&waker);
            }
            Ok(false)
        }
    }
}

#[async_trait]
impl Socket for UdpSocket {
    fn bind(&self, addr: SockAddr) -> SyscallResult {
        let mut ep = IpEndpoint::try_from(addr)?;
        specify_ipep(NET_INTERFACE.lock().deref_mut(), &mut ep);
        self.do_bind(ep)
    }

    async fn connect(&self, addr: SockAddr) -> SyscallResult {
        let ep = IpEndpoint::try_from(addr)?;
        info!("[udp] (handle {}) connect to {}", self.handle, ep);
        self.inner.lock().remote_endpoint = Some(ep);
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

    fn dis_connect(&self, _how: u32) -> SyscallResult {
        info!("[udp] (handle {}) disconnect", self.handle);
        self.inner.lock().remote_endpoint = None;
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_DGRAM
    }

    fn sock_name(&self) -> SockAddr {
        self.inner.lock().local_endpoint.map(Into::into)
            .unwrap_or_else(|| SockAddr::In4(SockAddrIn4::default()))
    }

    fn peer_name(&self) -> SyscallResult<SockAddr> {
        let res = self.inner.lock().remote_endpoint.map(Into::into);
        match res {
            Some(sockaddr) => Ok(sockaddr),
            _ => Err(Errno::ENOTCONN),
        }
    }


    fn shutdown(&self, how: u32) -> SyscallResult {
        warn!("[udp] (handle {}) shutdown: how {}", self.handle, how);
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recvbuf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().sendbuf_size)
    }

    fn set_keep_alive(&self, _enabled: bool) -> SyscallResult {
        Err(EOPNOTSUPP)
    }

    async fn recv(
        &self,
        buf: &mut [u8],
        flags: RecvFromFlags,
        src: Option<&mut SockAddr>,
    ) -> SyscallResult<isize> {
        info!("[udp] (handle {}) recv", self.handle);
        if self.inner.lock().local_endpoint.is_none() {
            self.do_bind(unspecified_ipep())?;
        }
        let len = UdpRecvFuture::new(self.handle, flags, buf, src).await?;
        Ok(len as isize)
    }

    async fn send(
        &self,
        buf: &[u8],
        flags: RecvFromFlags,
        dest: Option<SockAddr>,
    ) -> SyscallResult<isize> {
        if self.inner.lock().local_endpoint.is_none() {
            self.do_bind(unspecified_ipep())?;
        }
        let dest = match dest {
            Some(dest) => IpEndpoint::try_from(dest)?,
            None => self.inner.lock().remote_endpoint.ok_or(Errno::ENOTCONN)?,
        };
        let len = UdpSendFuture::new(self.handle, flags, buf, dest).await?;
        Ok(len as isize)
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        info!("[udp] (handle {}) drop socket", self.handle);
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<udp::Socket>(self.handle);
        if socket.is_open() {
            socket.close();
        }
        net.sockets.remove(self.handle);
        net.poll();
    }
}

struct UdpRecvFuture<'a> {
    handle: SocketHandle,
    flags: RecvFromFlags,
    buf: &'a mut [u8],
    src: Option<&'a mut SockAddr>,
}

impl<'a> UdpRecvFuture<'a> {
    fn new(
        handle: SocketHandle,
        flags: RecvFromFlags,
        buf: &'a mut [u8],
        src: Option<&'a mut SockAddr>,
    ) -> Self {
        Self { handle, flags, buf, src }
    }
}

impl<'a> Future for UdpRecvFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<udp::Socket>(this.handle);

        if !socket.can_recv() {
            info!("[udp] (handle {}) recv: cannot recv yet", this.handle);
            if this.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            socket.register_recv_waker(cx.waker());
            return Poll::Pending;
        }

        info!("[udp] (handle {}) recv: start", this.handle);
        let (nbytes, remote) = if this.flags.contains(RecvFromFlags::MSG_PEEK) {
            let recv = match socket.peek_slice(this.buf) {
                Ok(recv) => recv,
                Err(e) => {
                    warn!("[udp] (handle {}) recv: peek error {}", this.handle, e);
                    return Poll::Ready(Err(Errno::ENOTCONN));
                }
            };
            (recv.0, recv.1.endpoint)
        } else {
            let recv = match socket.recv_slice(this.buf) {
                Ok(recv) => recv,
                Err(e) => {
                    warn!("[udp] (handle {}) recv: recv error {}", this.handle, e);
                    return match e {
                        RecvError::Exhausted => Poll::Ready(Err(Errno::ENOTCONN)),
                        RecvError::Truncated => Poll::Ready(Err(Errno::EMSGSIZE)),
                    }
                }
            };
            (recv.0, recv.1.endpoint)
        };

        info!("[udp] (handle {}) recv: {} <- {}", this.handle, socket.endpoint(), remote);
        if let Some(src) = this.src.as_mut() {
            **src = SockAddr::from(remote);
        }
        info!("[udp] (handle {}) recv: got {} bytes", this.handle, nbytes);
        net.poll();
        Poll::Ready(Ok(nbytes))
    }
}

struct UdpSendFuture<'a> {
    handle: SocketHandle,
    flags: RecvFromFlags,
    buf: &'a [u8],
    dest: IpEndpoint,
}

impl<'a> UdpSendFuture<'a> {
    fn new(
        handle: SocketHandle,
        flags: RecvFromFlags,
        buf: &'a [u8],
        dest: IpEndpoint,
    ) -> Self {
        Self { handle, flags, buf, dest }
    }
}

impl<'a> Future for UdpSendFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<udp::Socket>(self.handle);

        if !socket.can_send() {
            info!("[udp] (handle {}) send: cannot send yet", self.handle);
            if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            socket.register_send_waker(cx.waker());
            return Poll::Pending;
        }

        info!("[udp] (handle {}) send: start", self.handle);
        let meta = UdpMetadata {
            endpoint: self.dest,
            meta: PacketMeta::default(),
        };
        info!("[udp] (handle {}) send: {} -> {}", self.handle, socket.endpoint(), self.dest);
        let nbytes = self.buf.len();
        let ret = match socket.send_slice(self.buf, meta) {
            Ok(()) => {
                info!("[udp] (handle {}) send: sent {} bytes", self.handle, nbytes);
                Poll::Ready(Ok(nbytes))
            }
            Err(e) => {
                error!("[udp] (handle {}) send: error {}", self.handle, e);
                match e {
                    SendError::Unaddressable => Poll::Ready(Err(Errno::ENOTCONN)),
                    SendError::BufferFull => Poll::Ready(Err(Errno::ENOBUFS)),
                }
            }
        };
        net.poll();
        ret
    }
}

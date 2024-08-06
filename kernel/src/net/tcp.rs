use crate::fs::ffi::OpenFlags;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::ops::DerefMut;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use log::{error, info, warn};
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use smoltcp::iface::SocketHandle;
use core::time::Duration;
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::socket::{Socket, SocketType, BUFFER_SIZE};
use crate::net::netaddress::{SockAddr, SockAddrIn4, specify_ipep, unspecified_ipep};
use crate::net::socket::{SHUT_WR};
use crate::net::RecvFromFlags;
use crate::result::{Errno, SyscallResult};
use crate::sched::yield_now;
use crate::sync::mutex::Mutex;

pub const TCP_MSS_DEFAULT: u32 = 1 << 15;
pub const TCP_MSS: u32 = if TCP_MSS_DEFAULT > BUFFER_SIZE as u32 {
    BUFFER_SIZE as u32
} else {
    TCP_MSS_DEFAULT
};

pub struct TcpSocket {
    metadata: FileMeta,
    inner: Mutex<TcpInner>,
}

struct TcpInner {
    handle: SocketHandle,
    local_endpoint: Option<IpEndpoint>,
    remote_endpoint: Option<IpEndpoint>,
    last_state: tcp::State,
    recv_buf_size: usize,
    send_buf_size: usize,
}

impl TcpSocket {
    pub fn new() -> Self {
        let tx_buf = tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]);
        let rx_buf = tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        let mut net = NET_INTERFACE.lock();
        let handle = net.sockets.add(socket);
        info!("[tcp] Create new socket: handle {}", handle);
        Self {
            metadata: FileMeta::new(None, OpenFlags::O_RDWR),
            inner: Mutex::new(TcpInner {
                handle,
                local_endpoint: None,
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
        }
    }
}

impl TcpInner {
    fn do_bind(&mut self, mut ep: IpEndpoint) -> SyscallResult {
        if self.local_endpoint.is_some() {
            return Err(Errno::EINVAL);
        }
        let mut net = NET_INTERFACE.lock();
        specify_ipep(&mut net, &mut ep);
        self.local_endpoint = Some(ep);
        info!("[tcp] (handle {}) bind to: {}", self.handle, ep);
        Ok(())
    }
}

#[async_trait]
impl File for TcpSocket {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    fn as_socket(self: Arc<Self>) -> SyscallResult<Arc<dyn Socket>> {
        Ok(self)
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let flags = self.metadata.flags.lock();
        let mut flags_recv = RecvFromFlags::default();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_recv = RecvFromFlags::MSG_DONTWAIT;
        }
        self.recv(buf, flags_recv, None).await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let mut flags_send = RecvFromFlags::default();
        let flags = self.metadata().flags.lock();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_send = RecvFromFlags::MSG_DONTWAIT;
        }
        self.send(buf, flags_send, None).await
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        info!("[tcp] (handle {}) pollin: state {}", inner.handle, socket.state());

        if socket.can_recv() {
            info!("[tcp] (handle {}) pollin: recv buf have item", inner.handle);
            Ok(true)
        } else if socket.state() == tcp::State::CloseWait
            || socket.state() == tcp::State::FinWait2
            || socket.state() == tcp::State::TimeWait
            || (inner.last_state == tcp::State::Listen
            && socket.state() == tcp::State::Established)
            || socket.state() == tcp::State::SynReceived
        {
            info!("[tcp] (handle {}) state changed from {}", inner.handle, inner.last_state);
            Ok(true)
        } else {
            info!("[tcp] (handle {}) pollin: nothing to read", inner.handle);
            if let Some(waker) = &waker {
                socket.register_recv_waker(waker);
            }
            Ok(false)
        }
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        info!("[tcp] (handle {}) pollout: state {}", inner.handle, socket.state());

        if socket.can_send() {
            info!("[tcp] (handle {}) pollout: tx buf have slots", inner.handle);
            Ok(true)
        } else {
            info!("[tcp] (handle {}) pollout: tx buf full", inner.handle);
            if let Some(waker) = waker {
                socket.register_send_waker(&waker);
            }
            Ok(false)
        }
    }
}

#[async_trait]
impl Socket for TcpSocket {
    fn bind(&self, addr: SockAddr) -> SyscallResult {
        let mut ep = IpEndpoint::try_from(addr)?;
        specify_ipep(NET_INTERFACE.lock().deref_mut(), &mut ep);
        self.inner.lock().do_bind(ep.into())
    }

    async fn connect(&self, addr: SockAddr) -> SyscallResult {
        let remote_endpoint = IpEndpoint::try_from(addr)?;
        let mut inner = self.inner.lock();
        if inner.local_endpoint.is_none() {
            inner.do_bind(unspecified_ipep())?;
        }
        if inner.remote_endpoint.is_some() {
            return Err(Errno::EISCONN);
        }
        // 若不是多核心启动，需要在这里 yield ,防止单核心 Debug 没有 Yeild，这里直接Yield
        // yield_now().await;
        info!(
            "[tcp] (handle {}) connect: {} -> {}",
            inner.handle, inner.local_endpoint.unwrap(), remote_endpoint,
        );
        loop {
            let mut net = NET_INTERFACE.lock();
            let net_ref = net.deref_mut();
            net_ref.poll();
            let socket = net_ref.sockets.get_mut::<tcp::Socket>(inner.handle);

            match socket.state() {
                tcp::State::Closed => {
                    let ret = socket
                        .connect(net_ref.iface.context(), remote_endpoint, inner.local_endpoint.unwrap());
                    if let Err(e) = ret {
                        info!("[tcp] (handle {}) Connect error: {}", inner.handle, e);
                        return Err(Errno::EINVAL);
                    }
                    info!("[tcp] (handle {}) Connect start", inner.handle);
                    drop(net);
                    yield_now().await;
                }
                tcp::State::SynSent => {
                    info!("[tcp] (handle {}) Connecting, state {}", inner.handle, socket.state());
                    drop(net);
                    yield_now().await;
                }
                tcp::State::Established => {
                    info!("[tcp] (handle {}) Connected, state {}", inner.handle, socket.state());
                    inner.remote_endpoint = Some(remote_endpoint);
                    return Ok(());
                }
                _ => {
                    warn!(
                        "[tcp] (handle {}) Connect: unexpected state {}",
                        inner.handle, socket.state(),
                    );
                    socket.close();
                }
            }
        }
    }

    fn listen(&self) -> SyscallResult {
        let mut inner = self.inner.lock();
        if inner.local_endpoint.is_none() {
            inner.do_bind(unspecified_ipep())?;
        }
        let local_ep = inner.local_endpoint.unwrap();

        info!("[tcp] (handle {}) listening: {}", inner.handle, local_ep);
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        let ret = socket.listen(local_ep).map_err(|e| {
            error!("[tcp] (handle {}) Listen failed with {}", inner.handle, e);
            Errno::EINVAL
        });
        inner.last_state = socket.state();
        ret
    }

    async fn accept(&self, addr: Option<&mut SockAddr>) -> SyscallResult<Arc<dyn Socket>> {
        let flags = *self.metadata.flags.lock();
        let peer_addr = TcpAcceptFuture::new(self, flags).await?;
        if let Some(addr) = addr {
            *addr = peer_addr.into();
        }
        info!("[tcp] accept: peer address: {}", peer_addr);

        let local_ep = self.inner.lock().local_endpoint.unwrap();
        info!("[tcp] accept: new socket try bind to {}", local_ep);
        let new_socket = Arc::new(TcpSocket::new());
        new_socket.inner.lock().do_bind(local_ep)?;
        info!("[tcp] Listen on new socket");
        new_socket.listen()?;
        core::mem::swap(self.inner.lock().deref_mut(), new_socket.inner.lock().deref_mut());
        Ok(new_socket)
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().send_buf_size = size;
        Ok(())
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().recv_buf_size = size;
        Ok(())
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        let inner = self.inner.lock();
        if inner.remote_endpoint.is_none() {
            return Err(Errno::ENOTCONN);
        }
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        }
        net.poll();
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_STREAM
    }

    fn sock_name(&self) -> SockAddr {
        self.inner.lock().local_endpoint.map(Into::into)
            .unwrap_or_else(|| SockAddr::In4(SockAddrIn4::default()))
    }

    fn peer_name(&self) -> SyscallResult<SockAddr> {
        self.inner.lock().remote_endpoint.map(Into::into).ok_or(Errno::ENOTCONN)
    }

    fn shutdown(&self, how: u32) -> SyscallResult {
        let inner = self.inner.lock();
        info!("[tcp] (handle {}) shutdown: how {}", inner.handle, how);
        if inner.remote_endpoint.is_none() {
            return Err(Errno::ENOTCONN);
        }
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        }
        net.poll();
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recv_buf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().send_buf_size)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        socket.set_keep_alive(enabled.then_some(Duration::from_secs(1).into()));
        Ok(())
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        socket.set_nagle_enabled(enabled);
        Ok(())
    }

    async fn recv(
        &self,
        buf: &mut [u8],
        flags: RecvFromFlags,
        dest: Option<&mut SockAddr>,
    ) -> SyscallResult<isize> {
        let len = TcpRecvFuture::new(self, buf, flags).await?;
        if let Some(dest) = dest {
            *dest = self.peer_name().unwrap();
        }
        Ok(len as isize)
    }

    async fn send(
        &self,
        buf: &[u8],
        flags: RecvFromFlags,
        _: Option<SockAddr>,
    ) -> SyscallResult<isize> {
        let len = TcpSendFuture::new(self, buf, flags).await?;
        Ok(len as isize)
    }
}

impl Drop for TcpSocket {
    // 在 TcpSocket 被清除时，我们将它的端口号放回分配器中
    fn drop(&mut self) {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        info!("[tcp] (handle {}) drop: before state {}", inner.handle, socket.state());
        if socket.is_open() {
            socket.close();
        }
        info!("[tcp] (handle {}) drop: after state {}", inner.handle, socket.state());
        net.poll();
        net.sockets.remove(inner.handle);
        net.poll();
    }
}

struct TcpAcceptFuture<'a> {
    socket: &'a TcpSocket,
    flags: OpenFlags,
}

impl<'a> TcpAcceptFuture<'a> {
    fn new(socket: &'a TcpSocket, flags: OpenFlags) -> Self {
        Self { socket, flags }
    }
}

impl<'a> Future for TcpAcceptFuture<'a> {
    type Output = SyscallResult<IpEndpoint>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.socket.inner.lock();
        if inner.local_endpoint.is_none() {
            return Poll::Ready(Err(Errno::ENOTCONN));
        }

        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        info!("[tcp] (handle {}) accept: state {}", inner.handle, socket.state());

        if !socket.is_open() {
            warn!("[tcp] (handle {}) accept: socket is not open", inner.handle);
            return Poll::Ready(Err(Errno::EINVAL));
        }
        if matches!(socket.state(), tcp::State::SynReceived | tcp::State::Established) {
            inner.last_state = socket.state();
            inner.remote_endpoint = socket.remote_endpoint();
            return Poll::Ready(Ok(socket.remote_endpoint().unwrap()));
        }
        if self.flags.contains(OpenFlags::O_NONBLOCK) {
            return Poll::Ready(Err(Errno::EAGAIN));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

struct TcpRecvFuture<'a> {
    socket: &'a TcpSocket,
    buf: &'a mut [u8],
    flags: RecvFromFlags,
}

impl<'a> TcpRecvFuture<'a> {
    fn new(socket: &'a TcpSocket, buf: &'a mut [u8], flags: RecvFromFlags) -> Self {
        Self { socket, buf, flags }
    }
}

impl<'a> Future for TcpRecvFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.socket.inner.lock();
        if inner.local_endpoint.is_none() {
            return Poll::Ready(Err(Errno::ENOTCONN));
        }

        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        info!("[tcp] (handle {}) recv: state {}", inner.handle, socket.state());

        if matches!(socket.state(), tcp::State::CloseWait | tcp::State::TimeWait) {
            return Poll::Ready(Ok(0));
        }
        if !socket.may_recv() {
            warn!("[tcp] (handle {}) recv: may_recv false", inner.handle);
            return Poll::Ready(Err(Errno::ENOTCONN));
        }
        if !socket.can_recv() {
            info!("[tcp] (handle {}) recv: cannot recv yet", inner.handle);
            if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            socket.register_recv_waker(cx.waker());
            return Poll::Pending;
        }

        info!("[tcp] (handle {}) recv: start", inner.handle);
        let this = self.get_mut();
        info!(
            "[tcp] (handle {}) Recv: {} <- {}",
            inner.handle, inner.local_endpoint.unwrap(), inner.remote_endpoint.unwrap(),
        );
        let recv = if this.flags.contains(RecvFromFlags::MSG_PEEK) {
            socket.peek_slice(&mut this.buf)
        } else {
            socket.recv_slice(&mut this.buf)
        };
        let ret = match recv {
            Ok(nbytes) => {
                info!("[tcp] (handle {}) recv: got {} bytes", inner.handle, nbytes);
                Poll::Ready(Ok(nbytes))
            }
            Err(e) => {
                error!("[tcp] (handle {}) recv: error {}", inner.handle, e);
                Poll::Ready(Err(Errno::ENOTCONN))
            }
        };
        ret
    }
}

struct TcpSendFuture<'a> {
    socket: &'a TcpSocket,
    buf: &'a [u8],
    flags: RecvFromFlags,
}

impl<'a> TcpSendFuture<'a> {
    fn new(socket: &'a TcpSocket, buf: &'a [u8], flags: RecvFromFlags) -> Self {
        Self { socket, buf, flags }
    }
}

impl<'a> Future for TcpSendFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.socket.inner.lock();
        if inner.local_endpoint.is_none() {
            return Poll::Ready(Err(Errno::ENOTCONN));
        }

        let mut net = NET_INTERFACE.lock();
        net.poll();
        let socket = net.sockets.get_mut::<tcp::Socket>(inner.handle);
        info!("[tcp] (handle {}) send: state {}", inner.handle, socket.state());

        if !socket.may_send() {
            warn!("[tcp] (handle {}) send: may_send false", inner.handle);
            return Poll::Ready(Err(Errno::ENOTCONN));
        }
        if !socket.can_send() {
            info!("[tcp] (handle {}) send: cannot send yet", inner.handle);
            if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            socket.register_send_waker(cx.waker());
            return Poll::Pending;
        }

        info!("[tcp] (handle {}) send: start", inner.handle);
        let this = self.get_mut();
        info!(
            "[tcp] (handle {}) send: {} -> {}",
            inner.handle, socket.local_endpoint().unwrap(), socket.remote_endpoint().unwrap(),
        );
        let ret = match socket.send_slice(&mut this.buf) {
            Ok(nbytes) => {
                info!("[tcp] (handle {}) send: sent {} bytes", inner.handle, nbytes);
                Poll::Ready(Ok(nbytes))
            }
            Err(e) => {
                error!("[tcp] (handle {}) send: error {}", inner.handle, e);
                Poll::Ready(Err(Errno::ENOTCONN))
            }
        };
        net.poll();
        ret
    }
}

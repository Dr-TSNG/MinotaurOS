use crate::fs::fd::FileDescriptor;
use crate::fs::ffi::OpenFlags;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::ops::DerefMut;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use log::{debug, info};
use managed::ManagedSlice;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use smoltcp::{iface::SocketHandle, wire::IpListenEndpoint};
use core::time::Duration;
use tap::{Pipe, Tap};
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::port::random_port;
use crate::net::socket::{Socket, SocketType, BUFFER_SIZE};
use crate::net::netaddress::fill_with_endpoint;
use crate::net::socket::{SHUT_WR};
use crate::net::{MAX_BUFFER_SIZE, RecvFromFlags};
use crate::net::netaddress::{endpoint, is_local};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use crate::sched::{sleep_for, yield_now};
use crate::sync::mutex::Mutex;

pub const TCP_MSS_DEFAULT: u32 = 1 << 15;
pub const TCP_MSS: u32 = if TCP_MSS_DEFAULT > MAX_BUFFER_SIZE as u32 {
    MAX_BUFFER_SIZE as u32
} else {
    TCP_MSS_DEFAULT
};

pub struct TcpSocket {
    metadata: FileMeta,
    inner: Mutex<TcpInner>,
}

struct TcpInner {
    handle_loop: SocketHandle,
    handle_dev: SocketHandle,
    local_endpoint: IpListenEndpoint,
    remote_endpoint: Option<IpEndpoint>,
    last_state_loop: tcp::State,
    last_state_dev: tcp::State,
    recv_buf_size: usize,
    send_buf_size: usize,
}

impl TcpSocket {
    pub fn new() -> Self {
        let tx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let rx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let socket_loop = tcp::Socket::new(rx_buf, tx_buf);

        let tx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let rx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let socket_dev = tcp::Socket::new(rx_buf, tx_buf);
        // 将 socket 加入 interface，返回 handle
        let (handle_loop, handle_dev) = NET_INTERFACE.lock().add_socket(socket_loop, socket_dev);
        // info!("[TcpSocket::new] new ({}, {})", handler_loop, handler_loop);
        let port = random_port();
        info!("[tcp] New socket handle_loop {} handle_dev {} at port {}", handle_loop,handle_dev, port);
        Self {
            metadata: FileMeta::new(None, OpenFlags::O_RDWR),
            inner: Mutex::new(TcpInner {
                handle_dev,
                handle_loop,
                local_endpoint: IpListenEndpoint { addr: None, port },
                remote_endpoint: None,
                last_state_dev: tcp::State::Closed,
                last_state_loop: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
        }
    }

    pub fn new_with(iple: IpListenEndpoint) -> Self {
        let tx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let rx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let socket_loop = tcp::Socket::new(rx_buf, tx_buf);

        let tx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let rx_buf = tcp::SocketBuffer::new(vec![0; MAX_BUFFER_SIZE]);
        let socket_dev = tcp::Socket::new(rx_buf, tx_buf);
        // 将 socket 加入 interface，返回 handle
        let (handle_loop, handle_dev) = NET_INTERFACE.lock().add_socket(socket_loop, socket_dev);
        let port = random_port();
        info!("[tcp] New socket handle_loop {} handle_dev {} at port {}", handle_loop,handle_dev, port);
        Self {
            metadata: FileMeta::new(None, OpenFlags::O_RDWR),
            inner: Mutex::new(TcpInner {
                handle_loop,
                handle_dev,
                local_endpoint: iple,
                remote_endpoint: None,
                last_state_loop: tcp::State::Closed,
                last_state_dev: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
        }
    }

    /// tcp_socket wait for a connection to it , if connected , return remote IpEndpoint
    async fn tcp_accept(&self, flags: OpenFlags) -> SyscallResult<IpEndpoint> {
        TcpAcceptFuture::new(self, flags).await
    }
}

impl TcpInner {
    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&mut self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        let is_local = is_local(remote_endpoint);
        info!(
            "[Tcp::connect] local: {:?}, remote: {:?}",
            self.local_endpoint, remote_endpoint,
        );
        let ret = if is_local {
            let net = &mut *NET_INTERFACE.lock();
            net.sockets_loop
                .get_mut::<tcp::Socket>(self.handle_loop)
                .connect(net.loopback.iface.context(), remote_endpoint, self.local_endpoint)
        } else {
            let net = &mut *NET_INTERFACE.lock();
            net.sockets_dev
                .get_mut::<tcp::Socket>(self.handle_dev)
                .connect(net.device.iface.context(), remote_endpoint, self.local_endpoint)
        };
        match ret {
            Ok(_) => {
                self.remote_endpoint = Some(remote_endpoint);
                Ok(())
            }
            Err(e) => {
                info!(
                    "[Tcp::connect] (handle_loop {}, handle_dev {}) connect error occur",
                    self.handle_loop,
                    self.handle_dev,
                );
                self.remote_endpoint = None;
                match e {
                    tcp::ConnectError::Unaddressable => Err(Errno::EINVAL),
                    tcp::ConnectError::InvalidState => Err(Errno::EISCONN),
                }
            }
        }
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
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        drop(inner);
        info!(
            "[Tcp::read] (handle_loop {}, handle_dev {}) enter",
            handle_loop,
            handle_dev,
        );
        let flags = self.metadata.flags.lock();
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
        info!(
            "[Tcp::write] (handle_loop {}, handle_dev {}) enter",
            handle_loop,
            handle_dev
        );
        let mut flags_recv = RecvFromFlags::default();
        let flags = self.metadata().flags.lock();
        if flags.contains(OpenFlags::O_NONBLOCK) {
            flags_recv = RecvFromFlags::MSG_DONTWAIT;
        }
        self.send(buf, flags_recv).await
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        info!(
            "[Tcp::pollin] (handle_loop {}, handle_dev {}) enter",
            inner.handle_loop,
            inner.handle_dev
        );
        let poll_func = |socket: &mut tcp::Socket<'_>, last_state| {
            if socket.can_recv() {
                info!(
                    "[Tcp::pollin] (handle_loop {}, handle_dev {}) recv buf have item",
                    inner.handle_loop,
                    inner.handle_dev
                );
                true
            } else if socket.state() == tcp::State::CloseWait
                || socket.state() == tcp::State::FinWait2
                || socket.state() == tcp::State::TimeWait
                || (last_state == tcp::State::Listen && socket.state() == tcp::State::Established)
                || socket.state() == tcp::State::SynReceived
            // || (last_state==tcp::State::Closed && socket.state()==tcp::State::Established)
            {
                info!("[Tcp::pollin] state become {:?}", socket.state());
                true
            } else {
                info!("[Tcp::pollin] last_state is {:?}" , last_state);
                info!("[Tcp::pollin] nothing to read, state {:?}", socket.state());
                if let Some(waker) = &waker {
                    socket.register_recv_waker(waker);
                }
                false
            }
        };
        info!("[Tcp::pollin] poll all...");
        let mut net = NET_INTERFACE.lock();
        net.poll_all();
        let loop_ret = poll_func(net.sockets_loop.get_mut(inner.handle_loop), inner.last_state_loop);
        let dev_ret = poll_func(net.sockets_dev.get_mut(inner.handle_dev), inner.last_state_dev);
        if loop_ret || dev_ret {
            info!("[Tcp::pollin] ret Ok(true)...");
            return Ok(true);
        }
        info!("[Tcp::pollin] ret Ok(false)...");
        return Ok(false);
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        info!(
            "[Tcp::pollout] (handle_loop {}, handle_dev {}) enter",
            handle_loop, handle_dev
        );
        let is_local = is_local(self.remote_endpoint().unwrap());
        let poll_func = |socket: &mut tcp::Socket<'_>| {
            if socket.can_send() {
                info!(
                    "[Tcp::pollout] (handle_loop {}, handle_dev {}) tx buf have slots",
                    handle_loop, handle_dev
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
            Ok(poll_func(net.sockets_loop.get_mut(handle_loop)))
        } else {
            Ok(poll_func(net.sockets_dev.get_mut(handle_dev)))
        }
    }
}

#[async_trait]
impl Socket for TcpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        info!("[Tcp::bind] bind to: {:?}", addr);
        self.inner.lock().local_endpoint = addr;
        Ok(())
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        let remote_endpoint = endpoint(addr)?;
        let mut inner = self.inner.lock();
        let is_local = is_local(remote_endpoint);
        // 若不是多核心启动，需要在这里 yield ,防止单核心 Debug 没有 Yeild，这里直接Yield
        // yield_now().await;
        inner.tcp_connect(remote_endpoint)?;
        loop {
            let state = NET_INTERFACE.lock().pipe_ref_mut(|net| {
                net.poll(is_local);
                if is_local {
                    net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop).state()
                } else {
                    net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev).state()
                }
            });
            let handle = if is_local {
                inner.handle_loop
            } else {
                inner.handle_dev
            };
            match state {
                tcp::State::Closed => {
                    // close but not already connect, retry
                    info!("[Tcp::connect] {} already closed, try again", handle);
                    inner.tcp_connect(remote_endpoint)?;
                    yield_now().await;
                }
                tcp::State::Established => {
                    info!("[Tcp::connect] {} connected, state {:?}", handle, state);
                    return Ok(());
                }
                _ => {
                    info!("[Tcp::connect] {} not connect yet, state {:?}", handle, state);
                    yield_now().await;
                }
            }
        }
    }

    fn listen(&self) -> SyscallResult {
        let mut inner = self.inner.lock();
        info!(
            "[Tcp::listen] (handle_loop {}, handle_dev {}) listening: {:?}",
            inner.handle_loop, inner.handle_dev, inner.local_endpoint,
        );
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
        socket.listen(inner.local_endpoint).map_err(|_| Errno::EADDRINUSE).tap_mut(|_| {
            inner.last_state_loop = socket.state();
        })?;
        let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
        socket.listen(inner.local_endpoint).map_err(|_| Errno::EADDRINUSE).tap_mut(|_| {
            inner.last_state_dev = socket.state();
        })?;
        Ok(())
    }

    async fn accept(&self, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        let inner = self.inner.lock();
        info!("[tcp] Accept on handle_loop {} handle_dev {}", inner.handle_loop, inner.handle_dev);
        drop(inner);
        let peer_addr = self.tcp_accept(*self.metadata.flags.lock()).await?;
        debug!("[tcp] Peer address: {:?}", peer_addr);
        let local = self.local_endpoint();
        debug!("[tcp] New socket try bind to {:?}", local);
        let local_ep: IpListenEndpoint = local.try_into().expect("cannot convert to ListenEndpoint");
        let new_socket = Arc::new(TcpSocket::new_with(local_ep));
        debug!("[tcp] Listen on new socket");
        new_socket.listen()?;
        fill_with_endpoint(peer_addr, addr, addrlen)?;

        let mut proc_inner = current_process().inner.lock();
        let new_fd = proc_inner.fd_table.put(FileDescriptor::new(new_socket.clone(), false), 0)?;
        core::mem::swap(self.inner.lock().deref_mut(), new_socket.inner.lock().deref_mut());
        Ok(new_fd as usize)
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().send_buf_size = size;
        Ok(())
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult {
        self.inner.lock().recv_buf_size = size;
        Ok(())
    }

    fn set_keep_live(&self, enabled: bool) -> SyscallResult {
        let inner = self.inner.lock();
        if enabled {
            let mut net = NET_INTERFACE.lock();
            let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
            socket.set_keep_alive(Some(Duration::from_secs(1).into()));
            let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
            socket.set_keep_alive(Some(Duration::from_secs(1).into()));
        }
        Ok(())
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
        match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        }
        let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
        match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        }
        net.poll_all();
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_STREAM
    }

    fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner.lock().local_endpoint.clone()
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        let inner = self.inner.lock();
        let net = NET_INTERFACE.lock();
        let loop_remote = net
            .sockets_loop
            .get::<tcp::Socket>(inner.handle_loop)
            .remote_endpoint();
        let dev_remote = net
            .sockets_dev
            .get::<tcp::Socket>(inner.handle_dev)
            .remote_endpoint();
        match loop_remote {
            None => match dev_remote {
                Some(_) => dev_remote,
                None => None,
            },
            Some(_) => loop_remote,
        }
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        info!("[TcpSocket::shutdown] how {}", how);
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
        match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        }
        let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
        match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        }
        net.poll_all();
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recv_buf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().send_buf_size)
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult<usize> {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
        socket.set_nagle_enabled(enabled);
        let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
        socket.set_nagle_enabled(enabled);
        Ok(0)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        let inner = self.inner.lock();
        let mut net = NET_INTERFACE.lock();
        if enabled {
            let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
            socket.set_keep_alive(Some(Duration::from_secs(1).into()));
            let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
            socket.set_keep_alive(Some(Duration::from_secs(1).into()));
        } else {
            let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
            socket.set_keep_alive(None);
            let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
            socket.set_keep_alive(None);
        }
        Ok(0)
    }

    async fn recv(&self, buf: &mut [u8], flags: RecvFromFlags) -> SyscallResult<isize> {
        let future = TcpRecvFuture::new(self, buf, flags);
        let ret = future.await;
        match ret {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    // need to be slow
                    sleep_for(Duration::from_millis(2)).await.expect("TODO: panic message");
                } else {
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => Err(e)
        }
    }

    async fn send(&self, buf: &[u8], flags: RecvFromFlags) -> SyscallResult<isize> {
        let future = TcpSendFuture::new(self, buf, flags);
        let ret = future.await;
        match ret {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    // need to be slow
                    sleep_for(Duration::from_millis(2)).await.expect("TODO: panic message");
                } else {
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => Err(e)
        }
    }
}

impl Drop for TcpSocket {
    // 在 TcpSocket 被清除时，我们将它的端口号放回分配器中
    fn drop(&mut self) {
        let inner = self.inner.lock();
        info!(
            "[TcpSocket::Drop] dropping handle_loop {} handle_dev {}",
            inner.handle_loop, inner.handle_dev,
        );
        let mut net = NET_INTERFACE.lock();
        let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
        info!("[TcpSocket::drop] before state is {:?}", socket.state());
        if socket.is_open() {
            socket.close();
        }
        info!("[TcpSocket::drop] after state is {:?}", socket.state());
        let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
        info!("[TcpSocket::drop] before state is {:?}", socket.state());
        if socket.is_open() {
            socket.close();
        }
        info!("[TcpSocket::drop] after state is {:?}", socket.state());
        net.poll_all();
        net.remove(inner.handle_loop, inner.handle_dev);
        net.poll_all();
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
        let inner = &mut *self.socket.inner.lock();
        let mut poll_func = |socket: &mut tcp::Socket<'_>| {
            if !socket.is_open() {
                info!("[TcpAcceptFuture::poll] this socket is not open");
                return Poll::Ready(Err(Errno::EINVAL));
            }
            if socket.state() == tcp::State::SynReceived
                || socket.state() == tcp::State::Established
            {
                if is_local(socket.remote_endpoint().unwrap()) {
                    inner.last_state_loop = socket.state();
                } else {
                    inner.last_state_dev = socket.state();
                }
                inner.remote_endpoint = socket.remote_endpoint();
                info!("[TcpAcceptFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(socket.remote_endpoint().unwrap()));
            }
            if self.flags.contains(OpenFlags::O_NONBLOCK) {
                info!("[TcpAcceptFuture::poll] flags set nonblock");
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            Poll::Pending
        };

        let mut net = NET_INTERFACE.lock();
        net.poll_all();
        let socket = net.sockets_loop.get_mut(inner.handle_loop);
        let ret1 = poll_func(socket);
        if ret1.is_ready() {
            return ret1;
        }
        socket.register_recv_waker(cx.waker());
        let socket = net.sockets_dev.get_mut(inner.handle_dev);
        let ret2 = poll_func(socket);
        if ret2.is_ready() {
            return ret2;
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

struct TcpRecvFuture<'a> {
    socket: &'a TcpSocket,
    buf: ManagedSlice<'a, u8>,
    flags: RecvFromFlags,
}

impl<'a> TcpRecvFuture<'a> {
    fn new<S>(socket: &'a TcpSocket, buf: S, flags: RecvFromFlags) -> Self
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
impl<'a> Future for TcpRecvFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let remote = self.socket.remote_endpoint().ok_or(Errno::ENOTCONN)?;
        let is_local = is_local(remote);
        let inner = self.socket.inner.lock();
        let mut net = NET_INTERFACE.lock();
        net.poll(is_local);
        let ret = if is_local {
            let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
            if socket.state() == tcp::State::CloseWait || socket.state() == tcp::State::TimeWait {
                info!("[TcpRecvFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(0));
            }
            if !socket.may_recv() {
                info!("[TcpRecvFuture::poll] err when recv, state {:?}", socket.state());
                return Poll::Ready(Err(Errno::ENOTCONN));
            }
            info!("[TcpRecvFuture::poll] state {:?}", socket.state());
            if !socket.can_recv() {
                info!("[TcpRecvFuture::poll] cannot recv yet");
                if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[TcpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[TcpRecvFuture::poll] start to recv...");
            let this = self.get_mut();
            info!(
                "[TcpRecvFuture::poll] {:?} <- {:?}",
                socket.local_endpoint(),
                remote,
            );
            Poll::Ready(
                match if this.flags.contains(RecvFromFlags::MSG_PEEK) {
                    info!("[TcpRecvFuture::poll] get flags MSG_PEEK");
                    socket.peek_slice(&mut this.buf)
                } else {
                    socket.recv_slice(&mut this.buf)
                } {
                    Ok(nbytes) => {
                        info!(
                            "[TcpRecvFuture::poll] recv {} bytes, buf[0] {}",
                            nbytes, this.buf[0] as char,
                        );
                        Ok(nbytes)
                    }
                    Err(_) => Err(Errno::ENOTCONN)
                },
            )
        } else {
            let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
            if socket.state() == tcp::State::CloseWait || socket.state() == tcp::State::TimeWait {
                info!("[TcpRecvFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(0));
            }
            if !socket.may_recv() {
                info!("[TcpRecvFuture::poll] err when recv, state {:?}", socket.state());
                return Poll::Ready(Err(Errno::ENOTCONN));
            }
            info!("[TcpRecvFuture::poll] state {:?}", socket.state());
            if !socket.can_recv() {
                info!("[TcpRecvFuture::poll] cannot recv yet");
                if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[TcpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[TcpRecvFuture::poll] start to recv...");
            let this = self.get_mut();
            info!(
                    "[TcpRecvFuture::poll] {:?} <- {:?}",
                    socket.local_endpoint(),
                    remote,
                );
            Poll::Ready(
                match if this.flags.contains(RecvFromFlags::MSG_PEEK) {
                    info!("flags: {:?}", this.flags);
                    info!("[TcpRecvFuture::poll] get flags MSG_PEEK");
                    socket.peek_slice(&mut this.buf)
                } else {
                    socket.recv_slice(&mut this.buf)
                } {
                    Ok(nbytes) => {
                        info!("[TcpRecvFuture::poll] recv {} bytes, buf[0] {}", nbytes, this.buf[0] as char);
                        Ok(nbytes)
                    }
                    Err(_) => Err(Errno::ENOTCONN),
                },
            )
        };
        net.poll(is_local);
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
        let is_local = is_local(self.socket.remote_endpoint().unwrap());
        let inner = self.socket.inner.lock();
        let mut net = NET_INTERFACE.lock();
        net.poll(is_local);
        let ret = if is_local {
            let socket = net.sockets_loop.get_mut::<tcp::Socket>(inner.handle_loop);
            if !socket.may_send() {
                info!("[TcpSendFuture::poll] err when send");
                return Poll::Ready(Err(Errno::ENOTCONN));
            }
            if !socket.can_send() {
                info!("[TcpSendFuture::poll] cannot send yet");
                if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[TcpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[TcpSendFuture::poll] start to send...");
            let this = self.get_mut();
            info!(
                    "[TcpSendFuture::poll] {:?} -> {:?}",
                    socket.local_endpoint(),
                    socket.remote_endpoint()
                );
            Poll::Ready(match socket.send_slice(&mut this.buf) {
                Ok(nbytes) => {
                    info!("[TcpSendFuture::poll] send {} bytes", nbytes);
                    Ok(nbytes)
                }
                Err(_) => Err(Errno::ENOTCONN),
            })
        } else {
            let socket = net.sockets_dev.get_mut::<tcp::Socket>(inner.handle_dev);
            if !socket.may_send() {
                info!("[TcpSendFuture::poll] err when send");
                return Poll::Ready(Err(Errno::ENOTCONN));
            }
            if !socket.can_send() {
                info!("[TcpSendFuture::poll] cannot send yet");
                if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                    info!("[TcpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(Errno::EAGAIN));
                }
                socket.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            info!("[TcpSendFuture::poll] start to send...");
            let this = self.get_mut();
            info!(
                    "[TcpSendFuture::poll] {:?} -> {:?}",
                    socket.local_endpoint(),
                    socket.remote_endpoint()
                );
            Poll::Ready(match socket.send_slice(&mut this.buf) {
                Ok(nbytes) => {
                    info!("[TcpSendFuture::poll] send {} bytes", nbytes);
                    Ok(nbytes)
                }
                Err(_) => Err(Errno::ENOTCONN),
            })
        };
        net.poll(is_local);
        ret
    }
}

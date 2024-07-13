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
use tap::Pipe;
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::port::PORTS;
use crate::net::socket::{endpoint, fill_with_endpoint, Socket, SocketType, BUFFER_SIZE};
use crate::net::socket::{SHUT_WR};
use crate::net::MAX_BUFFER_SIZE;
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
    handle: SocketHandle,
    local_endpoint: IpListenEndpoint,
    remote_endpoint: Option<IpEndpoint>,
    last_state: tcp::State,
    recv_buf_size: usize,
    send_buf_size: usize,
}

impl TcpSocket {
    pub fn new() -> Self {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        // 将 socket 加入 interface，返回 handle
        let handle = NET_INTERFACE.add_socket(socket);
        NET_INTERFACE.poll();
        let port = unsafe { PORTS.positive_u32() as u16 };
        info!("[tcp] New socket handle {} at port {}", handle, port);
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
            inner: Mutex::new(TcpInner {
                handle,
                local_endpoint: IpListenEndpoint { addr: None, port },
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
        }
    }

    pub fn new_with(iple: IpListenEndpoint) -> Self {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        // 将 socket 加入 interface，返回 handle
        let handle = NET_INTERFACE.add_socket(socket);
        NET_INTERFACE.poll();
        let port = unsafe { PORTS.positive_u32() as u16 };
        info!("[tcp] New socket handle {} at port {}", handle, port);
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
            inner: Mutex::new(TcpInner {
                handle,
                local_endpoint: iple,
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
        }
    }

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        let (local, handle) = self.inner.lock().pipe_ref_mut(|inner| {
            info!("[tcp] Connect: {:?} -> {:?}", inner.local_endpoint, remote_endpoint);
            inner.remote_endpoint = Some(remote_endpoint);
            (inner.local_endpoint, inner.handle)
        });
        NET_INTERFACE.inner_handler(|inner| {
            let socket = inner.sockets_set.get_mut::<tcp::Socket>(handle);
            if let Err(e) = socket.connect(inner.i_face.context(), remote_endpoint, local) {
                info!("[tcp] Connect failed on {}", handle);
                return match e {
                    tcp::ConnectError::Unaddressable => Err(Errno::EINVAL),
                    tcp::ConnectError::InvalidState => Err(Errno::EISCONN),
                };
            }
            info!("[tcp] Before poll socket state: {}", socket.state());
            Ok(())
        })?;
        Ok(())
    }

    /// tcp_socket wait for a connection to it , if connected , return remote IpEndpoint
    async fn tcp_accept(&self, flags: OpenFlags) -> SyscallResult<IpEndpoint> {
        TcpAcceptFuture::new(self, flags).await
    }
}
#[async_trait]
impl File for TcpSocket {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        debug!("[tcp] Read on {}", self.inner.lock().handle);
        let flags = self.metadata.flags.lock();
        match TcpRecvFuture::new(self, buf, *flags).await {
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
        debug!("[tcp] Write on {}", self.inner.lock().handle);
        let flags = self.metadata().flags.lock();
        match TcpSendFuture::new(self, buf, *flags).await {
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
        info!("[tcp] Pollin for {}", handle);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            if socket.can_recv() {
                debug!("[tcp] Pollin {} recv buf have item", handle);
                Ok(true)
            } else if socket.state() == tcp::State::CloseWait
                || socket.state() == tcp::State::FinWait2
                || socket.state() == tcp::State::TimeWait
                || (self.inner.lock().last_state == tcp::State::Listen
                && socket.state() == tcp::State::Established)
                || socket.state() == tcp::State::SynReceived
            {
                debug!("[Tcp] Pollin state become {:?}", socket.state());
                Ok(true)
            } else {
                debug!("[Tcp] Pollin nothing to read, state {:?}", socket.state());
                if let Some(waker) = waker {
                    socket.register_recv_waker(&waker);
                }
                Ok(false)
            }
        })
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let handle = self.inner.lock().handle;
        info!("[tcp] Pollout for {}", handle);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            if socket.can_send() {
                debug!("[Tcp] Pollout {} tx buf have slots", handle);
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
impl Socket for TcpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        self.inner.lock().local_endpoint = addr;
        Ok(())
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        let handle = self.inner.lock().handle;
        let remote_endpoint = endpoint(addr)?;
        // 若不是多核心启动，需要在这里 yield ,防止单核心 Debug 没有 Yeild，这里直接Yield
        // yield_now().await;
        self.tcp_connect(remote_endpoint)?;
        loop {
            NET_INTERFACE.poll();
            let state = NET_INTERFACE.handle_tcp_socket(
                handle,
                |socket| socket.state(),
            );
            match state {
                tcp::State::Closed => {
                    debug!("[tcp] Connect: {} is already closed, try again", handle);
                    self.tcp_connect(remote_endpoint)?;
                    yield_now().await;
                }
                tcp::State::Established => {
                    debug!("[tcp] Connect: {} connected, state {:?}", handle, state);
                    yield_now().await;
                    return Ok(());
                }
                _ => {
                    debug!("[tcp] Connect: {} is not connect yet, state {:?}", handle, state);
                    yield_now().await;
                }
            }
        }
    }

    fn listen(&self) -> SyscallResult {
        let (local, handle) = self.inner.lock().pipe_ref_mut(|it| {
            (it.local_endpoint, it.handle)
        });
        info!("[tcp] Start listening {} at {:?}", handle, local);
        NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            let ret = socket.listen(local).map_err(|_| Errno::EADDRINUSE);
            self.inner.lock().last_state = socket.state();
            ret
        })
    }

    async fn accept(&self, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        info!("[tcp] Accept on {}", self.inner.lock().handle);
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
        proc_inner.socket_table.insert(new_fd, new_socket.clone());
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
        if enabled {
            let handle = self.inner.lock().handle;
            NET_INTERFACE.handle_tcp_socket(handle, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(())
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        let handle = self.inner.lock().handle;
        NET_INTERFACE.handle_tcp_socket(handle, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.poll();
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_STREAM
    }

    fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner.lock().local_endpoint.clone()
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        let handle = self.inner.lock().handle;
        NET_INTERFACE.poll();
        let ret =
            NET_INTERFACE.handle_tcp_socket(handle, |socket| socket.remote_endpoint());
        NET_INTERFACE.poll();
        ret
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        info!("[TcpSocket::shutdown] how {}", how);
        let handle = self.inner.lock().handle;
        NET_INTERFACE.handle_tcp_socket(handle, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.poll();
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recv_buf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().send_buf_size)
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult<usize> {
        let handle = self.inner.lock().handle;
        NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            socket.set_nagle_enabled(enabled)
        });
        Ok(0)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        if enabled {
            let handle = self.inner.lock().handle;
            NET_INTERFACE.handle_tcp_socket(handle, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(0)
    }
}
impl Drop for TcpSocket {
    // 在 TcpSocket 被清除时，我们将它的端口号放回分配器中
    fn drop(&mut self) {
        let handle = self.inner.lock().handle;
        info!(
            "[TcpSocket::drop] drop socket {}, localep {:?}",
            handle,
            self.inner.lock().local_endpoint
        );
        NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            info!("[TcpSocket::drop] before state is {:?}", socket.state());
            if socket.is_open() {
                socket.close();
            }
            info!("[TcpSocket::drop] after state is {:?}", socket.state());
        });
        NET_INTERFACE.poll();
        NET_INTERFACE.remove(handle);
        NET_INTERFACE.poll();
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
        NET_INTERFACE.poll();
        let handle = self.socket.inner.lock().handle;
        let ret = NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            if !socket.is_open() {
                info!("[TcpAcceptFuture::poll] this socket is not open");
                return Poll::Ready(Err(Errno::EINVAL));
            }
            if socket.state() == tcp::State::SynReceived
                || socket.state() == tcp::State::Established
            {
                self.socket.inner.lock().last_state = socket.state();
                info!("[TcpAcceptFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(socket.remote_endpoint().unwrap()));
            }
            info!(
                "[TcpAcceptFuture::poll] not syn yet, state {:?}",
                socket.state()
            );
            if self.flags.contains(OpenFlags::O_NONBLOCK) {
                info!("[TcpAcceptFuture::poll] flags set nonblock");
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        });
        NET_INTERFACE.poll();
        ret
    }
}
struct TcpRecvFuture<'a> {
    socket: &'a TcpSocket,
    buf: ManagedSlice<'a, u8>,
    flags: OpenFlags,
}
impl<'a> TcpRecvFuture<'a> {
    fn new<S>(socket: &'a TcpSocket, buf: S, flags: OpenFlags) -> Self
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
        NET_INTERFACE.poll();
        let handle = self.socket.inner.lock().handle;
        let ret = NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            if socket.state() == tcp::State::CloseWait || socket.state() == tcp::State::TimeWait {
                info!("[TcpRecvFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(0));
            }
            if !socket.may_recv() {
                info!(
                    "[TcpRecvFuture::poll] err when recv, state {:?}",
                    socket.state()
                );
                return Poll::Ready(Err(Errno::ENOTCONN));
            }
            info!("[TcpRecvFuture::poll] state {:?}", socket.state());
            if !socket.can_recv() {
                info!("[TcpRecvFuture::poll] cannot recv yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
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
                socket.remote_endpoint()
            );
            Poll::Ready(match socket.recv_slice(&mut this.buf) {
                Ok(nbytes) => {
                    info!("[TcpRecvFuture::poll] recv {} bytes", nbytes);
                    Ok(nbytes)
                }
                Err(_) => Err(Errno::ENOTCONN),
            })
        });
        NET_INTERFACE.poll();
        ret
    }
}
struct TcpSendFuture<'a> {
    socket: &'a TcpSocket,
    buf: &'a [u8],
    flags: OpenFlags,
}
impl<'a> TcpSendFuture<'a> {
    fn new(socket: &'a TcpSocket, buf: &'a [u8], flags: OpenFlags) -> Self {
        Self { socket, buf, flags }
    }
}
impl<'a> Future for TcpSendFuture<'a> {
    type Output = SyscallResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        NET_INTERFACE.poll();
        let handle = self.socket.inner.lock().handle;
        let ret = NET_INTERFACE.handle_tcp_socket(handle, |socket| {
            if !socket.may_send() {
                info!("[TcpSendFuture::poll] err when send");
                return Poll::Ready(Err(Errno::ENOTCONN));
            }
            if !socket.can_send() {
                info!("[TcpSendFuture::poll] cannot send yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
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
        });
        NET_INTERFACE.poll();
        ret
    }
}

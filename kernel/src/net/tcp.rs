use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::OpenFlags;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use core::any::Any;
use core::f32::consts::E;
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
use xmas_elf::header::Class;
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
use crate::result::Errno::ENOTCONN;
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
        let tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let socket_loop = smoltcp::socket::tcp::Socket::new(rx_buf, tx_buf);

        let tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let socket_dev = smoltcp::socket::tcp::Socket::new(rx_buf, tx_buf);
        // 将 socket 加入 interface，返回 handle
        let (handle_loop, handle_dev) = NET_INTERFACE.add_socket(socket_loop, socket_dev);
        // info!("[TcpSocket::new] new ({}, {})", handler_loop, handler_loop);
        let port = random_port();
        info!("[tcp] New socket handle_loop {} handle_dev {} at port {}", handle_loop,handle_dev, port);
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
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
        let tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let socket_loop = smoltcp::socket::tcp::Socket::new(rx_buf, tx_buf);

        let tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0 as u8; MAX_BUFFER_SIZE]);
        let socket_dev = smoltcp::socket::tcp::Socket::new(rx_buf, tx_buf);
        // 将 socket 加入 interface，返回 handle
        let (handle_loop, handle_dev) = NET_INTERFACE.add_socket(socket_loop, socket_dev);
        let port = random_port();
        info!("[tcp] New socket handle_loop {} handle_dev {} at port {}", handle_loop,handle_dev, port);
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
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

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        let is_local = is_local(remote_endpoint);
        let local = self.inner.lock().local_endpoint;
        info!(
            "[Tcp::connect] local: {:?}, remote: {:?}",
            local, remote_endpoint
        );
        let ret = if is_local{
            NET_INTERFACE.loopback(|inner|{
                NET_INTERFACE.handle_tcp_socket_loop(self.inner.lock().handle_loop,|socket|{
                    socket.connect(inner.iface.context(),remote_endpoint,local)
                })
            })
        }else{
            NET_INTERFACE.device(|inner| {
                NET_INTERFACE.handle_tcp_socket_dev(self.inner.lock().handle_dev, |socket| {
                    socket.connect(inner.iface.context(), remote_endpoint, local)
                })
            })
        };
        if ret.is_err() {
            let inner = self.inner.lock();
            let handle_loop = inner.handle_loop;
            let handle_dev = inner.handle_dev;
            drop(inner);
            info!(
                "[Tcp::connect] (handle_loop {}, handle_dev {}) connect error occur",
                handle_loop,
                handle_dev,
            );
            match ret.err().unwrap() {
                tcp::ConnectError::Unaddressable => return Err(Errno::EINVAL),
                tcp::ConnectError::InvalidState => return Err(Errno::EISCONN),
            }
        }
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
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        let last_state_loop = inner.last_state_loop;
        let last_state_dev = inner.last_state_dev;
        info!(
            "[Tcp::pollin] (handle_loop {}, handle_dev {}) enter",
            handle_loop,
            handle_dev
        );
        let pool_func = |socket: &mut smoltcp::socket::tcp::Socket<'_>, last_state|{
            if socket.can_recv(){
                info!(
                    "[Tcp::pollin] (handle_loop {}, handle_dev {}) recv buf have item",
                    handle_loop,
                    handle_dev
                );
                Ok(true)
            }else if socket.state() == tcp::State::CloseWait
                || socket.state() == tcp::State::FinWait2
                || socket.state() == tcp::State::TimeWait
                || (last_state == tcp::State::Listen && socket.state() == tcp::State::Established)
                || socket.state() == tcp::State::SynReceived
                // || (last_state==tcp::State::Closed && socket.state()==tcp::State::Established)
            {
                info!("[Tcp::pollin] state become {:?}", socket.state());
                Ok(true)
            }else {
                info!("[Tcp::pollin] last_state is {:?}" , last_state);
                info!("[Tcp::pollin] nothing to read, state {:?}", socket.state());
                Ok(false)
            }
        };
        //loop {
            info!("[Tcp::pollin] poll all...");
            NET_INTERFACE.poll_all();
            let loop_ret = NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
                pool_func(socket, last_state_loop)
            })?;
            let dev_ret = NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
                pool_func(socket, last_state_dev)
            })?;
            if loop_ret || dev_ret {
                info!("[Tcp::pollin] ret Ok(true)...");
                return Ok(true);
            }
        //}
       info!("[Tcp::pollin] ret Ok(false)...");
        return Ok(false);
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        // drop(inner);
        info!(
            "[Tcp::pollout] (handle_loop {}, handle_dev {}) enter",
            handle_loop, handle_dev
        );
        let is_local = is_local(self.remote_endpoint().unwrap());
        let poll_func = |socket: &mut smoltcp::socket::tcp::Socket<'_>| {
            if socket.can_send() {
                info!(
                    "[Tcp::pollout] (handle_loop {}, handle_dev {}) tx buf have slots",
                    handle_loop, handle_dev
                );
                Ok(true)
            } else {
                if let Some(waker) = waker {
                    socket.register_send_waker(&waker);
                }
                Ok(false)
            }
        };
        NET_INTERFACE.poll(is_local);
        if is_local {
            NET_INTERFACE.handle_tcp_socket_loop(handle_loop, poll_func)
        } else {
            NET_INTERFACE.handle_tcp_socket_dev(handle_dev, poll_func)
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
        self.inner.lock().remote_endpoint = Some(remote_endpoint);
        let is_local = is_local(remote_endpoint);
        // 若不是多核心启动，需要在这里 yield ,防止单核心 Debug 没有 Yeild，这里直接Yield
        // yield_now().await;
        self.tcp_connect(remote_endpoint)?;
        loop {
            NET_INTERFACE.poll(is_local);
            let state = if is_local {
                NET_INTERFACE.handle_tcp_socket_loop(self.inner.lock().handle_loop, |socket| socket.state())
            } else {
                NET_INTERFACE.handle_tcp_socket_dev(self.inner.lock().handle_dev, |socket| socket.state())
            };
            let handler = if is_local {
                self.inner.lock().handle_loop
            } else {
                self.inner.lock().handle_dev
            };
            match state {
                tcp::State::Closed => {
                    // close but not already connect, retry
                    info!("[Tcp::connect] {} already closed, try again", handler);
                    self.tcp_connect(remote_endpoint)?;
                    yield_now().await;
                }
                tcp::State::Established => {
                    info!("[Tcp::connect] {} connected, state {:?}", handler, state);
                    yield_now().await;
                    return Ok(());
                }
                _ => {
                    info!(
                            "[Tcp::connect] {} not connect yet, state {:?}",
                            handler, state
                        );
                    yield_now().await;
                }
            }
        }
    }

    fn listen(&self) -> SyscallResult {
        let (local, handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.local_endpoint, it.handle_dev, it.handle_loop)
        });
        info!("[Tcp::listen] (handle_loop {}, handle_dev {}) listening: {:?}", handle_loop, handle_dev, local);
        NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
            let ret = socket.listen(local).map_err(|_| Errno::EADDRINUSE);
            self.inner.lock().last_state_loop = socket.state();
            ret
        })?;
        NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
            let ret = socket.listen(local).ok().ok_or(Errno::EADDRINUSE);
            self.inner.lock().last_state_dev = socket.state();
            ret
        })?;
        Ok(())
    }

    async fn accept(&self, sockfd: FdNum , addr: usize, addrlen: usize) -> SyscallResult<usize> {
        let inner = self.inner.lock();
        let handle_loop = inner.handle_loop;
        let handle_dev = inner.handle_dev;
        drop(inner);
        info!("[tcp] Accept on handle_loop {} handle_dev {}", handle_loop,handle_dev);
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
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        if enabled {
            NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
            NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(())
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.poll_all();
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_STREAM
    }

    fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner.lock().local_endpoint.clone()
    }
    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        let loop_remote =
            NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| socket.remote_endpoint());
        let dev_remote =
            NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| socket.remote_endpoint());
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
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.poll_all();
        Ok(())
    }

    fn recv_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().recv_buf_size)
    }

    fn send_buf_size(&self) -> SyscallResult<usize> {
        Ok(self.inner.lock().send_buf_size)
    }

    fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult<usize> {
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
            socket.set_nagle_enabled(enabled)
        });
        NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| socket.set_nagle_enabled(enabled));
        Ok(0)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        if enabled {
            NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
            NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(0)
    }

    async fn recv(&self, buf: &mut [u8], flags: RecvFromFlags) -> SyscallResult<isize> {
        let future = TcpRecvFuture::new(self,buf,flags);
        let ret =  future.await;
        match ret {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    // need to be slow
                    sleep_for(Duration::from_millis(2)).await.expect("TODO: panic message");
                } else {
                    yield_now().await;
                }
                Ok(len as isize)
            },
            Err(e) => Err(e)
        }
    }

    async fn send(&self, buf: &[u8], flags: RecvFromFlags) -> SyscallResult<isize> {
        let future = TcpSendFuture::new(self,buf,flags);
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
            },
            Err(e) => Err(e)
        }
    }
}
impl Drop for TcpSocket {
    // 在 TcpSocket 被清除时，我们将它的端口号放回分配器中
    fn drop(&mut self) {
        info!("[TcpSocket::Drop] ...");
        /*
        info!(
            "[TcpSocket::drop] drop socket (handle_loop {}, handle_dev {}), localep {:?}",
            self.inner.lock().handle_loop,
            self.inner.lock().handle_dev,
            self.inner.lock().local_endpoint
        );
         */
        let (handle_dev, handle_loop) = self.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
            info!("[TcpSocket::drop] before state is {:?}", socket.state());
            if socket.is_open() {
                socket.close();
            }
            info!("[TcpSocket::drop] after state is {:?}", socket.state());
        });
        NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
            info!("[TcpSocket::drop] before state is {:?}", socket.state());
            if socket.is_open() {
                socket.close();
            }
            info!("[TcpSocket::drop] after state is {:?}", socket.state());
        });
        NET_INTERFACE.poll_all();
        NET_INTERFACE.remove(handle_loop, handle_dev);
        NET_INTERFACE.poll_all();
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
        let poll_func = |socket: &mut smoltcp::socket::tcp::Socket<'_>|{
            if !socket.is_open(){
                info!("[TcpAcceptFuture::poll] this socket is not open");
                return Poll::Ready(Err(Errno::EINVAL));
            }
            if socket.state() == tcp::State::SynReceived
                || socket.state() == tcp::State::Established
            {
                let mut inner = self.socket.inner.lock();
                if is_local(socket.remote_endpoint().unwrap()) {
                    inner.last_state_loop = socket.state();
                } else {
                    inner.last_state_dev = socket.state();
                }
                inner.remote_endpoint = socket.remote_endpoint();
                info!("[TcpAcceptFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(socket.remote_endpoint().unwrap()));
            }
            if self.flags.contains(OpenFlags::O_NONBLOCK){
                info!("[TcpAcceptFuture::poll] flags set nonblock");
                return Poll::Ready(Err(Errno::EAGAIN));
            }
            Poll::Pending
        };
        loop {
            let (handle_dev, handle_loop) = self.socket.inner.lock().pipe_ref_mut(|it| {
                (it.handle_dev, it.handle_loop)
            });
            NET_INTERFACE.poll_all();
            let ret1 = NET_INTERFACE.handle_tcp_socket_loop(handle_loop, poll_func);
            if ret1.is_ready() {
                return ret1;
            }
            let ret2 = NET_INTERFACE.handle_tcp_socket_dev(handle_dev, poll_func);
            if ret2.is_ready() {
                return ret2;
            }
        }
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
        let is_local = is_local(self.socket.remote_endpoint().unwrap());
        NET_INTERFACE.poll(is_local);
        let (handle_dev, handle_loop) = self.socket.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        let ret = if is_local{
            NET_INTERFACE.handle_tcp_socket_loop(handle_loop,|socket|{
                if socket.state() == tcp::State::CloseWait || socket.state() == tcp::State::TimeWait
                {
                    log::info!("[TcpRecvFuture::poll] state become {:?}", socket.state());
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
                    socket.remote_endpoint()
                );
                Poll::Ready(
                    match if this.flags.contains(RecvFromFlags::MSG_PEEK) {
                        info!("[TcpRecvFuture::poll] get flags MSG_PEEK");
                        socket.peek_slice(&mut this.buf)
                    }else{
                        socket.recv_slice(&mut this.buf)
                    } {
                        Ok(nbytes) => {
                            info!(
                                "[TcpRecvFuture::poll] recv {} bytes, buf[0] {}",
                                nbytes, this.buf[0] as char
                            );
                            Ok(nbytes)
                        }
                        Err(_) => Err(ENOTCONN)
                    },
                )
            })
        }else{
            NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
                if socket.state() == tcp::State::CloseWait || socket.state() == tcp::State::TimeWait
                {
                    log::info!("[TcpRecvFuture::poll] state become {:?}", socket.state());
                    return Poll::Ready(Ok(0));
                }
                if !socket.may_recv() {
                    log::info!(
                        "[TcpRecvFuture::poll] err when recv, state {:?}",
                        socket.state()
                    );
                    return Poll::Ready(Err(Errno::ENOTCONN));
                }
                log::info!("[TcpRecvFuture::poll] state {:?}", socket.state());
                if !socket.can_recv() {
                    log::info!("[TcpRecvFuture::poll] cannot recv yet");
                    if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                        log::info!("[TcpRecvFuture::poll] already set nonblock");
                        return Poll::Ready(Err(Errno::EAGAIN));
                    }
                    socket.register_recv_waker(cx.waker());
                    return Poll::Pending;
                }
                log::info!("[TcpRecvFuture::poll] start to recv...");
                let this = self.get_mut();
                info!(
                    "[TcpRecvFuture::poll] {:?} <- {:?}",
                    socket.local_endpoint(),
                    socket.remote_endpoint()
                );
                Poll::Ready(
                    match if this.flags.contains(RecvFromFlags::MSG_PEEK) {
                        info!("flags: {:?}", this.flags);
                        info!("[TcpRecvFuture::poll] get flags MSG_PEEK");
                        socket.peek_slice(&mut this.buf)
                    }else{
                        socket.recv_slice(&mut this.buf)
                    } {
                        Ok(nbytes) => {
                            info!(
                                "[TcpRecvFuture::poll] recv {} bytes, buf[0] {}",
                                nbytes, this.buf[0] as char
                            );
                            Ok(nbytes)
                        }
                        Err(_) => Err(ENOTCONN),
                    },
                )
            })
        };
        NET_INTERFACE.poll(is_local);
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
        NET_INTERFACE.poll(is_local);
        let (handle_dev, handle_loop) = self.socket.inner.lock().pipe_ref_mut(|it| {
            (it.handle_dev, it.handle_loop)
        });
        let ret = if is_local {
            NET_INTERFACE.handle_tcp_socket_loop(handle_loop, |socket| {
                if !socket.may_send() {
                    info!("[TcpSendFuture::poll] err when send");
                    return Poll::Ready(Err(ENOTCONN));
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
                log::info!("[TcpSendFuture::poll] start to send...");
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
            })
        }else{
            NET_INTERFACE.handle_tcp_socket_dev(handle_dev, |socket| {
                if !socket.may_send() {
                    info!("[TcpSendFuture::poll] err when send");
                    return Poll::Ready(Err(Errno::ENOTCONN));
                }
                if !socket.can_send() {
                    log::info!("[TcpSendFuture::poll] cannot send yet");
                    if self.flags.contains(RecvFromFlags::MSG_DONTWAIT) {
                        log::info!("[TcpSendFuture::poll] already set nonblock");
                        return Poll::Ready(Err(Errno::EAGAIN));
                    }
                    socket.register_send_waker(cx.waker());
                    return Poll::Pending;
                }
                log::info!("[TcpSendFuture::poll] start to send...");
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
            })
        };
        NET_INTERFACE.poll(is_local);
        ret
    }
}

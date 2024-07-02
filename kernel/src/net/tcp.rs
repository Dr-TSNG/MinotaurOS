#![allow(unused)]

use crate::arch::VirtAddr;
use crate::fs::devfs::net::NetInode;
use crate::fs::fd::{FdNum, FdTable, FileDescriptor};
use crate::fs::ffi::InodeMode::IFSOCK;
use crate::fs::ffi::{InodeMode, OpenFlags};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use futures::future::err;
use log::info;
use managed::ManagedSlice;
use smoltcp::phy::Medium;
use smoltcp::socket::tcp;
use smoltcp::socket::tcp::State;
use smoltcp::wire::IpEndpoint;
use smoltcp::{iface::SocketHandle, wire::IpListenEndpoint};
use core::time::Duration;
use xmas_elf::program::Flags;

use crate::fs::file::{File, FileMeta, Seek};
use crate::fs::inode::Inode;
use crate::net::iface::NET_INTERFACE;
use crate::net::port::Ports;
use crate::net::socket::{endpoint, fill_with_endpoint, Socket, SocketType, BUFFER_SIZE};
use crate::net::socket::{SHUT_RD, SHUT_RDWR, SHUT_WR};
use crate::net::MAX_BUFFER_SIZE;
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::Errno::{EADDRINUSE, EAGAIN, EINVAL, EISCONN, ENOTCONN};
use crate::result::{Errno, SyscallResult};
use crate::sched::iomultiplex::IOMultiplexFuture;
use crate::sched::time::current_time;
use crate::sched::{sleep_for, yield_now};
use super::Mutex;

pub const TCP_MSS_DEFAULT: u32 = 1 << 15;
pub const TCP_MSS: u32 = if TCP_MSS_DEFAULT > MAX_BUFFER_SIZE as u32 {
    MAX_BUFFER_SIZE as u32
} else {
    TCP_MSS_DEFAULT
};

pub struct TcpSocket {
    inner: Mutex<TcpInner>,
    socket_handle: SocketHandle,
    pub(crate) file_data: FileMeta,
}
struct TcpInner {
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
        // 将socket加入interface，返回handler
        let handler = NET_INTERFACE.add_socket(socket);
        info!("[TcpSocket::new] new{}", handler);
        NET_INTERFACE.poll();
        let port = unsafe { Ports.positive_u32() as u16 };
        info!("[TcpSocket handle{} : port is {}]", handler, port);
        let mut file_data = FileMeta::new(None);
        let net_inode = NetInode::new();
        file_data.inode = Option::from(net_inode as Arc<dyn Inode>);
        Self {
            socket_handle: handler,
            inner: Mutex::new(TcpInner {
                local_endpoint: IpListenEndpoint { addr: None, port },
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
            file_data,
        }
    }

    pub fn new_with(iple:IpListenEndpoint) -> Self{
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        // 将socket加入interface，返回handler
        let handler = NET_INTERFACE.add_socket(socket);
        info!("[TcpSocket::new] new{}", handler);
        NET_INTERFACE.poll();
        let port = unsafe { Ports.positive_u32() as u16 };
        info!("[TcpSocket handle{} : port is {}]", handler, port);
        let mut file_data = FileMeta::new(None);
        let net_inode = NetInode::new();
        file_data.inode = Option::from(net_inode as Arc<dyn Inode>);
        Self {
            socket_handle: handler,
            inner: Mutex::new(TcpInner {
                local_endpoint: iple,
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
            file_data,
        }
    }

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        let mut inner = self.inner.lock();
        inner.remote_endpoint = Some(remote_endpoint);
        let local = inner.local_endpoint;
        info!(
            "[Tcp::connect] local: {:?}, remote: {:?}",
            local, remote_endpoint
        );
        drop(inner);
        NET_INTERFACE.inner_handler(|inner| {
            let socket = inner.sockets_set.get_mut::<tcp::Socket>(self.socket_handle);
            let ret = socket.connect(inner.i_face.context(), remote_endpoint, local);
            if ret.is_err() {
                info!("[Tcp::connect] {} connect error occur", self.socket_handle);
                return match ret.err().unwrap() {
                    tcp::ConnectError::Unaddressable => Err(EINVAL),
                    tcp::ConnectError::InvalidState => Err(EISCONN),
                };
            }
            info!("Before poll socket state: {}", socket.state());
            Ok(())
        })?;
        Ok(())
    }

    /// tcp_socket wait for a connection to it , if connected , return remote IpEndpoint
    async fn tcp_accept(&self, flags: OpenFlags) -> SyscallResult<IpEndpoint> {
        let future = current_thread()
            .event_bus
            .suspend_with(Event::KILL_THREAD, TcpAcceptFuture::new(self, flags));
        match future.await {
            Ok(ret) => Ok(ret),
            Err(ret) => Err(ret),
        }
    }
}
#[async_trait]
impl File for TcpSocket {
    fn metadata(&self) -> &FileMeta {
        &self.file_data
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        info!("[Tcp::pollin] {} enter", self.socket_handle);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_tcp_socket(self.socket_handle,|socket|{
           if socket.can_recv(){
               log::info!("[Tcp::pollin] {} recv buf have item", self.socket_handle);
               Ok(true)
           } else if socket.state() == tcp::State::CloseWait
               || socket.state() == tcp::State::FinWait2
               || socket.state() == tcp::State::TimeWait
               || (self.inner.lock().last_state == tcp::State::Listen
               && socket.state() == tcp::State::Established)
               || socket.state() == tcp::State::SynReceived
           {
               log::info!("[Tcp::pollin] state become {:?}", socket.state());
               Ok(true)
           }else{
               log::info!("[Tcp::pollin] nothing to read, state {:?}", socket.state());
               if let Some(waker) = waker {
                   socket.register_recv_waker(&waker);
               }
               Ok(false)
           }
        })
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        info!("[Tcp::pollout] {} enter", self.socket_handle);
        NET_INTERFACE.poll();
        NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| {
            if socket.can_send() {
                log::info!("[Tcp::pollout] {} tx buf have slots", self.socket_handle);
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
        log::info!("[Tcp::read] {} enter", self.socket_handle);

        let future = current_thread().event_bus.suspend_with(
            Event::KILL_THREAD,
            TcpRecvFuture::new(self,buf,flags),
        );
        match future.await {
            Ok(len) => {
                if len>MAX_BUFFER_SIZE/2{
                    sleep_for(Duration::from_millis(2)).await;

                }else{
                    yield_now().await;
                }
                Ok(len as isize)
            }
            Err(e) => {
                Err(e)
            }
        }

    }

    async fn socket_write(&self, buf: &[u8], flags: OpenFlags) -> SyscallResult<isize> {
        log::info!("[Tcp::write] {} enter", self.socket_handle);

        let future = current_thread().event_bus.suspend_with(
            Event::KILL_THREAD,
            TcpSendFuture::new(self,buf,flags),
        );
        match future.await {
            Ok(len) => {
                if len>MAX_BUFFER_SIZE/2{
                    sleep_for(Duration::from_millis(2)).await;
                }else{
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
impl Socket for TcpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult<usize> {

        info!("[locked?], {:?}",self.inner.is_locked());
        info!("[tcp::bind] into tcp::bind");
        self.inner.lock().local_endpoint = addr;
        info!("[locked?], {:?}",self.inner.is_locked());
        // info!("[locked?], {}",self.inner.is_locked());
        Ok(0)
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult<usize> {
        let remote_endpoint = endpoint(addr)?;
        // 若不是多核心启动，需要在这里yield ,防止单核心Debug 没有Yeild，这里直接Yield
        // yield_now().await;
        self.tcp_connect(remote_endpoint)?;
        loop {
            NET_INTERFACE.poll();
            let state =
                NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| socket.state());
            match state {
                State::Closed => {
                    info!(
                        "[Tcp::connect] {} already closed, try again",
                        self.socket_handle
                    );
                    self.tcp_connect(remote_endpoint)?;
                    yield_now().await;
                }
                State::Established => {
                    info!(
                        "[Tcp::connect] {} connected, state {:?}",
                        self.socket_handle, state
                    );
                    yield_now().await;
                    return Ok(0);
                }
                _ => {
                    info!(
                        "[Tcp::connect] {} not connect yet, state {:?}",
                        self.socket_handle, state
                    );
                    yield_now().await;
                }
            }
        }
    }

    fn listen(&self) -> SyscallResult<usize> {
        info!("[socket::listen]: enter");
        let local = self.inner.lock().local_endpoint;
        info!(
            "[Tcp::listen] {} listening: {:?}",
            self.socket_handle, local
        );
        NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| {
            let ret = socket.listen(local).ok().ok_or(Errno::EADDRINUSE);
            self.inner.lock().last_state = socket.state();
            ret
        })?;
        Ok(0)
    }

    async fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult<usize> {
        info!("[sys_accept]: in tcp::accept");
        let proc = current_process().inner.lock();
        let old_file = proc.fd_table.get(socketfd as FdNum).unwrap();
        let old_flags = old_file.flags;
        drop(proc);
        let peer_addr = self.tcp_accept(old_flags).await?;
        log::info!("[Socket::accept] get peer_addr: {:?}", peer_addr);
        let local = self.local_endpoint().unwrap();
        log::info!("[Socket::accept] new socket try bind to : {:?}", local);

        log::info!("[Socket::accept::new] new socket build");
        let local_ep:IpListenEndpoint = local.try_into().expect("cannot convert to ListenEndpoint");
        let new_socket = TcpSocket::new_with(local_ep);
        info!("[locked?], {:?}",new_socket.inner.is_locked());
        // new_socket.bind(local_ep)?;
        log::info!("[Socket::accept] new socket listen");
        new_socket.listen()?;
        fill_with_endpoint(peer_addr, addr, addrlen)?;

        let new_socket = Arc::new(new_socket);
        let mut proc_inner = current_process().inner.lock();
        let fd = proc_inner.fd_table.alloc_fd()?;
        let old_file = proc_inner.fd_table.take(socketfd as FdNum).unwrap().unwrap();
        let old_socket: Option<Arc<dyn Socket>> =
            proc_inner.socket_table.get_ref(socketfd as FdNum).cloned();
        // replace old
        log::debug!("[Socket::accept] replace old sock to new");
        proc_inner.fd_table.put(FileDescriptor::new(new_socket.clone(), old_file.flags),
                                socketfd as FdNum,);
        proc_inner.socket_table.insert(fd as FdNum,old_socket.unwrap());
        drop(proc_inner);
        Ok(fd)
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
            NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(())
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| match how {
            SHUT_WR => socket.close(),
            _ => socket.abort(),
        });
        NET_INTERFACE.poll();
        Ok(())
    }

    fn socket_type(&self) -> SocketType {
        SocketType::SOCK_STREAM
    }

    fn local_endpoint(&self) -> SyscallResult<IpListenEndpoint> {
        let inner = self.inner.lock();
        let res = inner.local_endpoint.clone();
        drop(inner);
        Ok(res)
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        NET_INTERFACE.poll();
        let ret =
            NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| socket.remote_endpoint());
        NET_INTERFACE.poll();
        ret
    }

    fn shutdown(&self, how: u32) -> SyscallResult<()> {
        info!("[TcpSocket::shutdown] how {}", how);
        NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| match how {
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
        NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| {
            socket.set_nagle_enabled(enabled)
        });
        Ok(0)
    }

    fn set_keep_alive(&self, enabled: bool) -> SyscallResult<usize> {
        if enabled {
            NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| {
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(0)
    }
}
impl Drop for TcpSocket {
    // 在TcpSocket被清除时，我们将它的端口号放回分配器中
    fn drop(&mut self) {
        info!(
            "[TcpSocket::drop] drop socket {}, localep {:?}",
            self.socket_handle,
            self.inner.lock().local_endpoint
        );
        NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| {
            info!("[TcpSocket::drop] before state is {:?}", socket.state());
            if socket.is_open() {
                socket.close();
            }
            info!("[TcpSocket::drop] after state is {:?}", socket.state());
        });
        NET_INTERFACE.poll();
        NET_INTERFACE.remove(self.socket_handle);
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
        let ret = NET_INTERFACE.handle_tcp_socket(self.socket.socket_handle, |socket| {
            if !socket.is_open() {
                info!("[TcpAcceptFuture::poll] this socket is not open");
                return Poll::Ready(Err(EINVAL));
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
                return Poll::Ready(Err(EAGAIN));
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
        let ret = NET_INTERFACE.handle_tcp_socket(self.socket.socket_handle, |socket| {
            if socket.state() == tcp::State::CloseWait || socket.state() == tcp::State::TimeWait {
                info!("[TcpRecvFuture::poll] state become {:?}", socket.state());
                return Poll::Ready(Ok(0));
            }
            if !socket.may_recv() {
                info!(
                    "[TcpRecvFuture::poll] err when recv, state {:?}",
                    socket.state()
                );
                return Poll::Ready(Err(ENOTCONN));
            }
            info!("[TcpRecvFuture::poll] state {:?}", socket.state());
            if !socket.can_recv() {
                info!("[TcpRecvFuture::poll] cannot recv yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
                    info!("[TcpRecvFuture::poll] already set nonblock");
                    return Poll::Ready(Err(EAGAIN));
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
                Err(_) => Err(ENOTCONN),
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
        let ret = NET_INTERFACE.handle_tcp_socket(self.socket.socket_handle, |socket| {
            if !socket.may_send() {
                info!("[TcpSendFuture::poll] err when send");
                return Poll::Ready(Err(ENOTCONN));
            }
            if !socket.can_send() {
                info!("[TcpSendFuture::poll] cannot send yet");
                if self.flags.contains(OpenFlags::O_NONBLOCK) {
                    info!("[TcpSendFuture::poll] already set nonblock");
                    return Poll::Ready(Err(EAGAIN));
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
                Err(_) => Err(ENOTCONN),
            })
        });
        NET_INTERFACE.poll();
        ret
    }
}

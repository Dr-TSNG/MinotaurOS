#![allow(unused)]

use crate::arch::VirtAddr;
use crate::fs::ffi::InodeMode::IFSOCK;
use crate::fs::ffi::{InodeMode, OpenFlags};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::future::err;
use log::info;
use managed::ManagedSlice;
use smoltcp::phy::Medium;
use smoltcp::socket::tcp;
use smoltcp::time::Duration;
use smoltcp::wire::IpEndpoint;
use smoltcp::{iface::SocketHandle, wire::IpListenEndpoint};
use xmas_elf::program::Flags;
use crate::fs::fd::{FdNum, FdTable};

use crate::fs::file::{File, FileMeta, Seek};
use crate::net::iface::NET_INTERFACE;
use crate::net::port::{PortAllocator, PORT_ALLOCATOR};
use crate::net::socket::{endpoint, Socket, SocketType, BUFFER_SIZE, fill_with_endpoint};
use crate::net::socket::{SHUT_RD, SHUT_RDWR, SHUT_WR};
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::Errno::{EADDRINUSE, EAGAIN, EINVAL, EISCONN, ENOTCONN};
use crate::result::{Errno, SyscallResult};
use crate::sched::iomultiplex::IOMultiplexFuture;
use crate::sched::time::current_time;
use crate::sync::mutex::Mutex;

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
        // 没有处理分配完port，不能再多分配，返回None的情况。。。
        let port = PORT_ALLOCATOR.take().unwrap();
        info!("[TcpSocket handle{} : port is {}]", handler, port);
        Self {
            socket_handle: handler,
            inner: Mutex::new(TcpInner {
                local_endpoint: IpListenEndpoint { addr: None, port },
                remote_endpoint: None,
                last_state: tcp::State::Closed,
                recv_buf_size: BUFFER_SIZE,
                send_buf_size: BUFFER_SIZE,
            }),
            file_data: FileMeta::new(None),
        }
    }

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        self.inner.lock().remote_endpoint = Some(remote_endpoint);
        let local = self.inner.lock().local_endpoint;
        info!(
            "[Tcp::connect] local: {:?}, remote: {:?}",
            local, remote_endpoint
        );
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

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode == InodeMode::IFDIR {
            return Err(Errno::EISDIR);
        }
        let mut inner = self.file_data.inner.lock().await;
        let count = inode.read(buf, inner.pos).await?;
        inner.pos += count;
        Ok(count)
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode == InodeMode::IFDIR {
            return Err(Errno::EISDIR);
        }
        let mut inner = self.file_data.inner.lock().await;
        let count = inode.write(buf, inner.pos).await?;
        inner.pos += count;
        Ok(count)
    }

    async fn truncate(&self, size: isize) -> SyscallResult {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode == InodeMode::IFDIR {
            return Err(Errno::EISDIR);
        }
        inode.truncate(size).await?;
        Ok(())
    }
    async fn sync(&self) -> SyscallResult {
        let inode = self.file_data.inode.as_ref().unwrap();
        inode.sync().await?;
        Ok(())
    }
    async fn seek(&self, seek: Seek) -> SyscallResult<isize> {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode == InodeMode::IFDIR {
            return Err(Errno::EISDIR);
        }
        let mut inner = self.file_data.inner.lock().await;
        inner.pos = match seek {
            Seek::Set(offset) => {
                if offset < 0 {
                    return Err(EINVAL);
                }
                offset
            }
            Seek::Cur(offset) => match inner.pos.checked_add(offset) {
                Some(new_pos) => new_pos,
                None => return Err(if offset < 0 { EINVAL } else { Errno::EOVERFLOW }),
            },
            Seek::End(offset) => {
                let size = self
                    .file_data
                    .inode
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .inner
                    .lock()
                    .size;
                match size.checked_add(offset) {
                    Some(new_pos) => new_pos,
                    None => return Err(if offset < 0 { EINVAL } else { Errno::EOVERFLOW }),
                }
            }
        };
        Ok(inner.pos)
    }

    async fn pread(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let _lock = self.metadata().prw_lock.lock().await;
        let old = self.seek(Seek::Cur(0)).await?;
        self.seek(Seek::Set(offset)).await?;
        let ret = self.read(buf).await;
        self.seek(Seek::Set(old)).await?;
        ret
    }

    async fn pwrite(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let _lock = self.metadata().prw_lock.lock().await;
        let old = self.seek(Seek::Cur(0)).await?;
        self.seek(Seek::Set(offset)).await?;
        let ret = self.write(buf).await;
        self.seek(Seek::Set(old)).await?;
        ret
    }
}
#[async_trait]
impl Socket for TcpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult<usize> {
        info!("[tcp::bind] bind to: {:?}", addr);
        self.inner.lock().local_endpoint = addr;
        Ok(0)
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        todo!()
    }

    fn listen(&self) -> SyscallResult<usize> {
        let local = self.inner.lock().local_endpoint;
        info!(
            "[Tcp::listen] {} listening: {:?}",
            self.socket_handle, local
        );
        NET_INTERFACE.handle_tcp_socket(self.socket_handle,|socket|{
            let ret = socket.listen(local).ok().ok_or(Errno::EADDRINUSE);
            self.inner.lock().last_state = socket.state();
            ret
        })?;
        Ok(0)
    }

    async fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult {
        let proc = current_process().inner.lock();
        let old_file = proc.fd_table.get(socketfd as FdNum).unwrap();
        let old_flags = old_file.flags;
        let peer_addr = self.tcp_accept(old_flags).await?;
        log::info!("[Socket::accept] get peer_addr: {:?}", peer_addr);
        let local = self.local_endpoint().unwrap();
        log::info!("[Socket::accept] new socket try bind to : {:?}", local);
        let new_socket = TcpSocket::new();
        new_socket.bind(local.try_into().expect("cannot convert to ListenEndpoint"))?;
        log::info!("[Socket::accept] new socket listen");
        new_socket.listen()?;
        fill_with_endpoint(peer_addr,addr,addrlen)?;

        let new_socket = Arc::new(new_socket);
        //
        //  need  here ... ...
        //
        Ok(())
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
        Ok(self.inner.lock().local_endpoint)
    }

    fn remote_endpoint(&self) -> Option<IpEndpoint> {
        NET_INTERFACE.poll();
        let ret = NET_INTERFACE.handle_tcp_socket(self.socket_handle, |socket| socket.remote_endpoint());
        NET_INTERFACE.poll();
        ret
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
        PORT_ALLOCATOR.recycle(self.inner.lock().local_endpoint.port);
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

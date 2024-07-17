use alloc::boxed::Box;
use alloc::vec;
use async_trait::async_trait;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use futures::future::{Either, select};
use log::{debug, info, warn};
use managed::ManagedSlice;
use crate::fs::ffi::OpenFlags;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::PacketMeta;
use smoltcp::socket;
use smoltcp::socket::udp;
use smoltcp::socket::udp::{PacketMetadata, SendError, UdpMetadata};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use crate::fs::file::{File, FileMeta};
use crate::net::iface::NET_INTERFACE;
use crate::net::MAX_BUFFER_SIZE;
use crate::net::netaddress::{endpoint, is_local, SocketAddressV4};
use crate::net::socket::{Socket};
use crate::net::socket::{SocketType, BUFFER_SIZE};
use crate::processor::current_thread;
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
        let (handle_loop, handle_dev) = NET_INTERFACE.add_socket(socket_loop, socket_dev);
        info!("[UdpSocket::new] new (handler_loop {}, handler_dev {})", handle_loop, handle_dev);
        Self {
            metadata: FileMeta::new(None, OpenFlags::empty()),
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

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        /*
        {
            info!(
                "[Ucp::read] (handle_loop {}, handle_dev {}) enter",
                self.inner.lock().handle_loop,self.inner.lock().handle_dev
            );
        }
         */
        let buf_start = buf.as_ptr() as usize;
        let flags = self.metadata().flags.lock();
        // back loop dev
        let future1 = UdpRecvFuture::new(self, buf_start, buf.len(), *flags, true);
        // os virt-net dev
        let future2 = UdpRecvFuture::new(self,buf_start,buf.len(),*flags,false);
        match select(future1,future2).await {
            Either::Left(ret1) => {
                match ret1 {
                    (len,future) => {
                        match len {
                            Ok(len) => {
                                if len > MAX_BUFFER_SIZE / 2 {
                                    // need to be slow
                                    sleep_for(Duration::from_millis(1)).await.expect("TODO: panic message");
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
            }
            Either::Right(ret2) => {
                match ret2 {
                    (len,future) => {
                        match len {
                            Ok(len) => {
                                if len > MAX_BUFFER_SIZE / 2 {
                                    // need to be slow
                                    sleep_for(Duration::from_millis(1)).await.expect("TODO: panic message");
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
            }
        }
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        info!("Entry udp write");
        info!("[Udp::inner locked? {}]",self.inner.is_locked());
        {
            /*
            info!(
                "[Ucp::write] (handle_loop {}, handle_dev {}) enter",
                self.inner.lock().handle_loop,self.inner.lock().handle_dev
            );

             */
        }
        info!("[Udp::write] prepare");
        let flags = self.metadata().flags.lock();
        match UdpSendFuture::new(self, buf, *flags).await {
            Ok(len) => {
                if len > MAX_BUFFER_SIZE / 2 {
                    sleep_for(Duration::from_millis(2)).await?;
                } else {
                    yield_now().await;
                }
                info!("udp send ok");
                Ok(len as isize)
            }
            Err(e) => Err(e),
        }
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        info!(
            "[Udp::pollin] (handle_loop {}, handle_dev {}) enter",
            self.inner.lock().handle_loop, self.inner.lock().handle_dev
        );
        let poll_func = |socket: &mut udp::Socket<'_>|{
            if socket.can_recv() {
                info!(
                    "[Udp::pollin] (handle_loop {}, handle_dev {}) recv buf have item",
                    self.inner.lock().handle_loop,
                    self.inner.lock().handle_dev,
                );
                Ok(true)
            } else {
                if let Some(waker) = waker.clone() {
                    socket.register_recv_waker(&waker);
                }
                Ok(false)
            }
        };
        NET_INTERFACE.poll_all();
        Ok(NET_INTERFACE.handle_udp_socket_loop(self.inner.lock().handle_loop,poll_func)?
            || NET_INTERFACE.handle_udp_socket_dev(self.inner.lock().handle_dev,poll_func)?)
    }

    fn pollout(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        info!(
            "[Udp::pollout] (handle_loop {}, handle_dev {}) enter",
            self.inner.lock().handle_loop, self.inner.lock().handle_dev
        );
        let is_local = is_local(self.remote_endpoint().unwrap());
        let poll_func = |socket: &mut udp::Socket<'_>| {
            if socket.can_send() {
                info!(
                    "[Udp::pollout] (handle_loop {}, handle_dev {}) tx buf have slots",
                    self.inner.lock().handle_loop,
                    self.inner.lock().handle_dev,
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
            NET_INTERFACE.handle_udp_socket_loop(self.inner.lock().handle_loop, poll_func)
        } else {
            NET_INTERFACE.handle_udp_socket_dev(self.inner.lock().handle_dev, poll_func)
        }
    }
}

#[async_trait]
impl Socket for UdpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        info!("[Udp::bind] bind to {:?}", addr);
        NET_INTERFACE.handle_udp_socket_loop(self.inner.lock().handle_loop, |socket| {
            socket.bind(addr).ok().ok_or(Errno::EINVAL)
        })?;
        NET_INTERFACE.handle_udp_socket_dev(self.inner.lock().handle_dev, |socket| {
            socket.bind(addr).ok().ok_or(Errno::EINVAL)
        })?;
        self.inner.lock().local_endpoint = addr;
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
                    }
                }
                info!("[Udp::bind] bind to {:?}", endpoint);
                Ok(())
            } else {
                Ok(())
            }
        };
        info!("udp connect");
        info!("is_local: {}",is_local);

        // you can see lots of this dead lock , handle this one by one
        drop(inner);
        info!("self.inner is locked?: {}",self.inner.is_locked());
        if is_local{
            NET_INTERFACE.handle_udp_socket_loop(self.inner.lock().handle_loop,poll_func)?;
        }else {
            NET_INTERFACE.handle_udp_socket_dev(self.inner.lock().handle_dev,poll_func)?;
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
}
impl Drop for UdpSocket {
    fn drop(&mut self) {
        info!(
            "[UdpSocket::drop] drop socket (handle_loop {}, handle_dev {}), remoteep {:?}",
            self.inner.lock().handle_loop,
            self.inner.lock().handle_dev,
            self.inner.lock().remote_endpoint
        );
        NET_INTERFACE.handle_udp_socket_loop(self.inner.lock().handle_loop, |socket| {
            if socket.is_open() {
                socket.close();
            }
        });
        NET_INTERFACE.handle_udp_socket_dev(self.inner.lock().handle_dev, |socket| {
            if socket.is_open() {
                socket.close();
            }
        });
        NET_INTERFACE.remove(self.inner.lock().handle_loop,self.inner.lock().handle_dev);
        NET_INTERFACE.poll_all();
    }
}


// udp recv future 无连接过程， 不知道远程发送信息的 socket 是否是 local ，
// 所以这里加入 for_loop ， 在 recv 时，同时启动两个接受过程 。
// 方法有两个，一个是在 recv函数中启动两个future ， 等待任意一个结束；
// 另一个是改造 UdpRecvFuture，使它可以等待 本地loop成功接受或者 os virt-net成功接受
struct UdpRecvFuture<'a> {
    socket: &'a UdpSocket,
    // buf: ManagedSlice<'a, u8>,
    buf_start: usize,
    buf_len: usize,
    flags: OpenFlags,
    for_loop: bool,
}
impl<'a> UdpRecvFuture<'a> {
    fn new(
        socket: &'a UdpSocket,
        buf_start: usize,
        buf_len: usize,
        flags: OpenFlags,
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
        NET_INTERFACE.poll_all();
        if self.for_loop{
            let handle_loop_lock = self.socket.inner.lock();
            let handle_loop = handle_loop_lock.handle_loop;
            drop(handle_loop_lock);
            // 本地网络
            NET_INTERFACE.handle_udp_socket_loop(handle_loop, |socket| {
                let this = self.get_mut();
                if !socket.can_recv() {
                    info!("[UdpRecvFuture::poll] cannot recv yet");
                    if this.flags.contains(OpenFlags::O_NONBLOCK) {
                        info!("[UdpRecvFuture::poll] already set nonblock");
                        return Poll::Ready(Err(Errno::EAGAIN));
                    }
                    socket.register_recv_waker(cx.waker());
                    return Poll::Pending;
                }
                info!("[UdpRecvFuture::poll] start to recv...");
                Poll::Ready({
                    let (ret, meta) = socket
                        .recv_slice(unsafe {
                            &mut core::slice::from_raw_parts_mut(
                                this.buf_start as *mut u8,
                                this.buf_len,
                            )
                        })
                        .ok()
                        .ok_or(Errno::ENOTCONN)?;
                    let remote = meta.endpoint;
                    info!(
                        "[UdpRecvFuture::poll] {:?} <- {:?}",
                        socket.endpoint(),
                        remote
                    );
                    this.socket.inner.lock().remote_endpoint = Some(remote);
                    debug!("[UdpRecvFuture::poll] recv {} bytes", ret);
                    Ok(ret)
                })
            })
        }else {
            let handle_dev_lock = self.socket.inner.lock();
            let handle_dev = handle_dev_lock.handle_dev;
            drop(handle_dev_lock);
            NET_INTERFACE.handle_udp_socket_dev(handle_dev, |socket| {
                let this = self.get_mut();
                if !socket.can_recv() {
                    info!("[UdpRecvFuture::poll] cannot recv yet");
                    if this.flags.contains(OpenFlags::O_NONBLOCK) {
                        info!("[UdpRecvFuture::poll] already set nonblock");
                        return Poll::Ready(Err(Errno::EAGAIN));
                    }
                    socket.register_recv_waker(cx.waker());
                    return Poll::Pending;
                }
                info!("[UdpRecvFuture::poll] start to recv...");
                Poll::Ready({
                    let (ret, meta) = socket
                        .recv_slice(unsafe {
                            &mut core::slice::from_raw_parts_mut(
                                this.buf_start as *mut u8,
                                this.buf_len,
                            )
                        })
                        .ok()
                        .ok_or(Errno::ENOTCONN)?;
                    let remote = meta.endpoint;
                    info!(
                        "[UdpRecvFuture::poll] {:?} <- {:?}",
                        socket.endpoint(),
                        remote
                    );
                    this.socket.inner.lock().remote_endpoint = Some(remote);
                    info!("[UdpRecvFuture::poll] recv {} bytes", ret);
                    Ok(ret)
                })
            })
        }
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
        let is_local = is_local(self.socket.remote_endpoint().unwrap());
        NET_INTERFACE.poll(is_local);
        let ret = if is_local{
            let inner = self.socket.inner.lock();
            let remote_endpoint = inner.remote_endpoint;
            drop(inner);
            NET_INTERFACE.handle_udp_socket_loop(self.socket.inner.lock().handle_loop, |socket| {
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
                let remote = remote_endpoint;
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
                        Err(Errno::ENOTCONN)
                    } else {
                        Err(Errno::ENOBUFS)
                    }
                } else {
                    debug!("[UdpSendFuture::poll] send {} bytes", len);
                    Ok(len)
                })
            })
        }else{
            NET_INTERFACE.handle_udp_socket_dev(self.socket.inner.lock().handle_dev, |socket| {
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
                        Err(Errno::ENOTCONN)
                    } else {
                        Err(Errno::ENOBUFS)
                    }
                } else {
                    debug!("[UdpSendFuture::poll] send {} bytes", len);
                    Ok(len)
                })
            })
        };
        NET_INTERFACE.poll(is_local);
        ret
    }
}

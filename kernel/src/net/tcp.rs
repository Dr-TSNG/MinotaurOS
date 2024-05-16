use crate::fs::ffi::InodeMode::{FileFIFO, IFSOCK};
use alloc::vec;
use async_trait::async_trait;
use log::info;
use smoltcp::phy::Medium;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use smoltcp::{iface::SocketHandle, wire::IpListenEndpoint};
use smoltcp::time::Duration;
use crate::fs::ffi::InodeMode;

use crate::fs::file::{File, FileMeta, Seek};
use crate::net::iface::NET_INTERFACE;
use crate::net::port::{PortAllocator, PORT_ALLOCATOR};
use crate::net::socket::{Socket, SocketType, BUFFER_SIZE, endpoint};
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;
use crate::net::socket::{SHUT_RD,SHUT_WR,SHUT_RDWR};
use crate::processor::current_process;
use crate::result::Errno::EADDRINUSE;
use crate::sched::time::current_time;

pub struct TcpSocket {
    inner: Mutex<TcpInner>,
    socket_handle: SocketHandle,
    file_data: FileMeta,
}

struct TcpInner {
    local_endpoint: IpListenEndpoint,
    remote_endpoint: IpListenEndpoint,
    last_state: smoltcp::socket::tcp::State,
    recv_buf_size: usize,
    send_buf_size: usize,
}

impl TcpSocket {
    pub fn new() -> Self {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0u8; BUFFER_SIZE]);
        let socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);
        // 将socket加入interface，返回handler
        let handler = NET_INTERFACE.add_tcpsocket(socket);
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
            file_data: FileMeta::new(Some(IFSOCK)),
        }
    }

    /// this tcp_socket to connect someone else tcp_socket
    fn tcp_connect(&self, remote_endpoint: IpEndpoint) -> SyscallResult<()> {
        todo!()
    }

    /// tcp_socket wait for a connection to it , if connected , return remote IpEndpoint
    fn tcp_accept(&self) -> SyscallResult<IpEndpoint> {
        todo!()
    }
}

#[async_trait]
impl File for TcpSocket {
    fn metadata(&self) -> &FileMeta {
        &self.file_data
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode == InodeMode::IFDIR{
            return Err(Errno::EISDIR);
        }
        let mut inner = self.file_data.inner.lock().await;
        let count = inode.read(buf,inner.pos).await?;
        inner.pos+=count;
        Ok(count)
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode==InodeMode::IFDIR{
            return Err(Errno::EISDIR);
        }
        let mut inner = self.file_data.inner.lock().await;
        let count = inode.write(buf,inner.pos).await?;
        inner.pos+=count;
        Ok(count)
    }

    async fn truncate(&self, size: isize) -> SyscallResult {
        let inode = self.file_data.inode.as_ref().unwrap();
        if inode.metadata().mode == InodeMode::IFDIR{
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
                    return Err(Errno::EINVAL);
                }
                offset
            }
            Seek::Cur(offset) => {
                match inner.pos.checked_add(offset) {
                    Some(new_pos) => new_pos,
                    None => return Err(if offset < 0 { Errno::EINVAL } else { Errno::EOVERFLOW }),
                }
            }
            Seek::End(offset) => {
                let size = self.file_data.inode.as_ref().unwrap().metadata().inner.lock().size;
                match size.checked_add(offset) {
                    Some(new_pos) => new_pos,
                    None => return Err(if offset < 0 { Errno::EINVAL } else { Errno::EOVERFLOW }),
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
    }}

#[async_trait]
impl Socket for TcpSocket {
    fn bind(&self, addr: IpListenEndpoint) -> SyscallResult {
        self.inner.lock().local_endpoint = addr;
        Ok(())
    }

    async fn connect(&self, addr: &[u8]) -> SyscallResult {
        todo!()

    }

    async fn listen(&self) -> SyscallResult {
        let local = self.inner.lock().local_endpoint;
        NET_INTERFACE.handle_tcp_socket(self.socket_handle,|socket|{
            let ret = socket.listen(local).ok().ok_or(SyscallResult::Err(EADDRINUSE));
            self.inner.lock().last_state = socket.state();
            ret
        });
        Ok(())
    }

    async fn accept(&self, socketfd: u32, addr: usize, addrlen: usize) -> SyscallResult {
        todo!()
    }

    fn set_send_buf_size(&self, size: usize) -> SyscallResult {
        let t = self.inner.lock();
        t.send_buf_size = size;
        Ok(())
    }

    fn set_recv_buf_size(&self, size: usize) -> SyscallResult {
        let t = self.inner.lock();
        t.recv_buf_size = size;
        Ok(())
    }

    fn set_keep_live(&self, enabled: bool) -> SyscallResult {
        if enabled{
            NET_INTERFACE.handle_tcp_socket(self.socket_handle,|socket|{
                socket.set_keep_alive(Some(Duration::from_secs(1).into()))
            });
        }
        Ok(())
    }

    fn dis_connect(&self, how: u32) -> SyscallResult {
        NET_INTERFACE.handle_tcp_socket(self.socket_handle,|socket|{
            match how {
                SHUT_WR => {socket.close()},
                _ => {socket.abort()},
            }
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
}

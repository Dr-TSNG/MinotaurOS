```rust
//使用crate::sync::mutex::Mutex<T>
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
```
在tcp::accept里，
```rust
info!("[sys_accept]: in tcp::accept");
        let proc = current_process().inner.lock();
        let old_file = proc.fd_table.get(socketfd as FdNum).unwrap();
        let old_flags = old_file.flags;
        drop(proc);
        let peer_addr = self.tcp_accept(old_flags).await?;
        log::info!("[Socket::accept] get peer_addr: {:?}", peer_addr);
        let local = self.local_endpoint().unwrap();
        log::info!("[Socket::accept] new socket try bind to : {:?}", local);
        let new_socket = TcpSocket::new();
        info!("[locked?], {:?}",new_socket.inner.is_locked());
        log::info!("[Socket::accept::new] new socket build");
        let local_ep:IpListenEndpoint = local.try_into().expect("cannot convert to ListenEndpoint");
        info!("[locked?], {:?}",new_socket.inner.is_locked());
        new_socket.bind(local_ep)?；
```
socket的new函数：
```rust
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
```

在bind函数中new_socket.bind(local_ep)

```rust

fn bind(&self, addr: IpListenEndpoint) -> SyscallResult<usize> {
    info!("[locked?], {:?}",self.inner.is_locked());
    info!("[tcp::bind] into tcp::bind");
    self.inner.lock().local_endpoint = addr;
    info!("[locked?], {:?}",self.inner.is_locked());
    // info!("[locked?], {}",self.inner.is_locked());
    Ok(0)
}
```
下面是日志
```
//使用crate::sync::mutex::Mutex<T>
[18.501s] [INFO ] [HART 0] [4, 4] | [sys_connect]: sys_connect
[18.502s] [INFO ] [HART 0] [4, 4] | [Tcp::connect] local: ListenEndpoint { addr: None, port: 235 }, remote: Endpoint { addr: Ipv4(Address([127, 0, 0, 1])), port: 99 }
[18.503s] [INFO ] [HART 0] [4, 4] | Before poll socket state: SYN-SENT
[18.506s] [INFO ] [HART 0] [4, 4] | [Tcp::connect] #0 connected, state Established
[18.506s] [SCALL] [HART 1] [4, 4] | return: Ok(0)
[18.507s] [SCALL] [HART 1] [4, 4] | sys_accept, args: (3, 18446744071562067240, 18446744071562067236), pc: 0x43aa4
[18.507s] [INFO ] [HART 1] [4, 4] | [sys_accept]:sys_accept
[18.508s] [INFO ] [HART 1] [4, 4] | [sys_accept]: in tcp::accept
[18.508s] [INFO ] [HART 1] [4, 4] | [TcpAcceptFuture::poll] state become Established
[18.509s] [INFO ] [HART 1] [4, 4] | [Socket::accept] get peer_addr: Endpoint { addr: Ipv4(Address([127, 0, 0, 1])), port: 235 }
[18.509s] [INFO ] [HART 1] [4, 4] | [Socket::accept] new socket try bind to : ListenEndpoint { addr: None, port: 99 }
[18.51s] [INFO ] [HART 1] [4, 4] | [TcpSocket::new] new#1
[18.51s] [INFO ] [HART 1] [4, 4] | [TcpSocket handle#1 : port is 179]
[18.511s] [INFO ] [HART 1] [4, 4] | [locked?], false
[18.511s] [INFO ] [HART 1] [4, 4] | [Socket::accept::new] new socket build
[18.511s] [INFO ] [HART 1] [4, 4] | [locked?], false
[18.512s] [INFO ] [HART 1] [4, 4] | [locked?], false
[18.512s] [INFO ] [HART 1] [4, 4] | [tcp::bind] into tcp::bind
[23.513s] [ERROR] [HART 1] [4, 4] | ----------------------------------
[23.513s] [ERROR] [HART 1] [4, 4] |      !!!   KERNEL PANIC   !!!     
[23.514s] [ERROR] [HART 1] [4, 4] | ----------------------------------
[23.514s] [ERROR] [HART 1] [4, 4] | Panicked at kernel/src/sync/mutex/spin.rs:60 SpinMutex deadlock
```

为什么刚刚建立的socket，new_socket去bind会死锁？
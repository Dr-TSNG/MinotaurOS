#import "../components/prelude.typ": *

= 网络系统

== 网络协议栈

MinotaurOS 使用的网络协议栈是smoltcp，能够处理IPv4和IPv6两类IP地址。smoltcp 提供了基本的网络硬件设备和 Socket 抽象，在此基础上，MinotaurOS 实现了网络设备，提供网络设备调用接口。网络接口的定义如#[@lst:NetInterface定义]所示。

#code-figure(
  ```rs
  pub struct NetInterface {
      pub iface: Interface,
      pub device: Loopback,
      pub sockets: SocketSet<'static>,
      pub port_cx: PortContext,
  }
  ```,
  caption: [NetInterface 定义],
  label-name: "NetInterface定义",
)

#h(2em) 通过调用接口的方法，可以实现收发数据包的功能。

值得一提的是，在 smoltcp 中，没有实现 Udp 一对多发送的功能，所以 MinotaurOS 对 smoltcp 进行修改，使其在适配内核的基础上实现 Udp 一对多发送的功能。

== 本地网络设备

MinotaurOS 将网络设备分为两类，一种是本地网络设备，另外一类是虚拟网络设备，之后可能会对于实际的开发板实现具体的物理网络设备。

基于 smoltcp 的Loopback定义，MinotaurOS 实现了本地网络的接口，如#[@lst:NetInterface定义]所示。

== 虚拟网络设备

MinotaurOS 基于 virtio-drivers，实现了虚拟网络设备。可以用于在 QEMU 模拟器上模拟网络。虚拟网络设备定义如#[@lst:VirtIONetDevice定义]所示。

#code-figure(
  ```rs
  pub struct VirtIONetDevice {
      metadata: DeviceMeta,
      base_addr: VirtAddr,
      dev: LateInit<Arc<Mutex<Net>>>,
  }
  ```,
  caption: [VirtIONetDevice 定义],
  label-name: "VirtIONetDevice定义",
)

== Socket定义

MinotaurOS 实现网络系统调用的关键是 Socket trait 的定义和实现，通过 Socket，MinotaurOS 抽象出了系统 Socket 具体的功能。Socket trait 如#[@lst:Sockettrait定义]所示。

#code-figure(
  ```rs
  pub trait Socket: File {
      fn bind(&self, addr: SockAddr) -> SyscallResult;

      async fn connect(&self, addr: SockAddr) -> SyscallResult;

      fn listen(&self) -> SyscallResult;

      async fn accept(&self,
            addr: Option<&mut SockAddr>) 
      -> SyscallResult<Arc<dyn Socket>>;

      fn set_send_buf_size(&self, size: usize) -> SyscallResult;

      fn set_recv_buf_size(&self, size: usize) -> SyscallResult;

      fn dis_connect(&self, how: u32) -> SyscallResult;

      fn socket_type(&self) -> SocketType;

      fn sock_name(&self) -> SockAddr;

      fn peer_name(&self) -> Option<SockAddr>;

      fn shutdown(&self, how: u32) -> SyscallResult;

      fn recv_buf_size(&self) -> SyscallResult<usize>;

      fn send_buf_size(&self) -> SyscallResult<usize>;

      fn set_keep_alive(&self, enabled: bool) -> SyscallResult;

      fn set_nagle_enabled(&self, enabled: bool) -> SyscallResult;

      async fn recv(&self, 
            buf: &mut [u8], 
            flags: RecvFromFlags, 
            src: Option<&mut SockAddr>,) 
      -> SyscallResult<isize>;

      async fn send(&self, 
            buf: &[u8], 
            flags: RecvFromFlags, 
            dest: Option<SockAddr>,) 
      -> SyscallResult<isize>;
}
  ```,
  caption: [Socket trait 定义],
  label-name: "Sockettrait定义",
)

== 与文件系统连接

基于 Socket trait 对于 File trait 的限定，一个 Socket 同时是一个文件，每当 MinotaurOS 创建一个 Socket，都会创建一个对应的逻辑上的文件，并返回文件句柄，可以通过这个句柄操作这个 Socket。

由于每个进程都有自己的文件描述符表，所以 MinotaurOS 将每个Socket看作一个文件，文件描述符和 Socket 的对应关系存储在进程的 fd_table 中。

Socket与File的关系密不可分，当我们需要将一个 File 转换为 Socket 时，调用如#[@lst:Socket转化函数]所示的函数。具体的 Socket 对于这个函数有自己的实现，而其他类型的文件则不会理会。

#code-figure(
  ```rs
  pub trait File: Send + Sync {

      fn as_socket(self: Arc<Self>) -> SyscallResult<Arc<dyn Socket>> {
          Err(Errno::ENOTSOCK)
      }

  }
  ```,
  caption: [Socket 转化函数],
  label-name: "Socket转化函数",
)


== 实现Tcp和Udp

对于具体实现 Socket 的内容，TcpSocket 和 UdpSocket 结构体是 MinotaurOS 对 Socket 的具体操作的对象。这两个结构体内部并不会直接存储 Socket 的实现细节，那是 smoltcp 的工作，而是存储 Socket 的状态信息，供 MinotaurOS 在调用时查找，并决定后续的行为。

TcpSocket 和 UdpSocket 如#[@lst:TcpSocket和UdpSocket结构体]所示。

#code-figure(
  ```rs
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
  ```,
  caption: [TcpSocket和UdpSocket 结构体],
  label-name: "TcpSocket和UdpSocket结构体",
)

#h(2em) MinotaurOS 为这两个结构实现 Socket 和 File 的trait，从而满足网络系统调用的需求。

#pagebreak()

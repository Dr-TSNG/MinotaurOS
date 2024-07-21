use core::mem::size_of;
use core::slice;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};
use crate::net::port::random_port;
use crate::net::socket::{AF_INET, AF_INET6};
use crate::result::{Errno, SyscallResult};

pub type IpAddr = IpAddress;



/// used when you want trans a socket_address to IpEndPoint or IpListenEndPoint
pub enum SocketAddress {
    V4(SocketAddressV4),
    V6(SocketAddressV6),
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[repr(C)]
pub struct SocketAddressV4 {
    port: [u8; 2],
    addr_v4: [u8; 4],
}

impl SocketAddressV4 {
    pub fn new(buf: &[u8]) -> Self {
        let addr = Self {
            port: buf[2..4].try_into().expect("ipv4 port len err"),
            addr_v4: buf[4..8].try_into().expect("ipv4 addr len err"),
        };
        addr
    }
    pub fn fill(&self, addr_buf: &mut [u8], addrlen: usize) {
        addr_buf.fill(0);
        addr_buf[0..2].copy_from_slice(u16::to_ne_bytes(AF_INET).as_slice());
        addr_buf[2..4].copy_from_slice(self.port.as_slice());
        addr_buf[4..8].copy_from_slice(self.addr_v4.as_slice());
        unsafe {
            *(addrlen as *mut u32) = 8;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[repr(C)]
pub struct SocketAddressV6 {
    port: [u8; 2],
    flowinfo: [u8; 4],
    addr_v6: [u8; 16],
}

impl SocketAddressV6 {
    pub fn new(buf: &[u8]) -> Self {
        let addr = Self {
            port: buf[2..4].try_into().expect("ipv6 port len err"),
            flowinfo: buf[4..8].try_into().expect("ipv6 flowinfo len err"),
            addr_v6: buf[8..24].try_into().expect("ipv6 addr len err"),
        };
        addr
    }
    pub fn fill(&self, addr_buf: &mut [u8], addrlen: usize) {
        addr_buf.fill(0);
        addr_buf[0..2].copy_from_slice(u16::to_ne_bytes(AF_INET6).as_slice());
        addr_buf[2..4].copy_from_slice(self.port.as_slice());
        addr_buf[4..8].copy_from_slice(self.flowinfo.as_slice());
        addr_buf[8..24].copy_from_slice(self.addr_v6.as_slice());
        unsafe {
            *(addrlen as *mut u32) = 24;
        }
    }
}

impl From<IpEndpoint> for SocketAddressV4 {
    fn from(value: IpEndpoint) -> Self {
        Self {
            port: value.port.to_be_bytes(),
            addr_v4: value
                .addr
                .as_bytes()
                .try_into()
                .expect("ipv4 address length error!"),
        }
    }
}

impl From<SocketAddressV4> for IpEndpoint {
    fn from(value: SocketAddressV4) -> Self {
        let port = u16::from_be_bytes(value.port);
        Self::new(IpAddress::Ipv4(Ipv4Address(value.addr_v4)), port)
    }
}

impl From<SocketAddressV4> for IpListenEndpoint {
    fn from(value: SocketAddressV4) -> Self {
        let port = u16::from_be_bytes(value.port);
        let addr = Ipv4Address(value.addr_v4);
        if addr.is_unspecified() {
            if port != 0 {
                IpListenEndpoint { addr: None, port }
            } else {
                IpListenEndpoint {
                    addr: None,
                    port: random_port(),
                }
            }
        } else {
            IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(addr)),
                port,
            }
        }
    }
}

impl From<IpEndpoint> for SocketAddressV6 {
    fn from(value: IpEndpoint) -> Self {
        Self {
            port: value.port.to_be_bytes(),
            flowinfo: [0u8; 4],
            addr_v6: value
                .addr
                .as_bytes()
                .try_into()
                .expect("ipv6 addr length error!"),
        }
    }
}

impl From<SocketAddressV6> for IpEndpoint {
    fn from(value: SocketAddressV6) -> Self {
        let port = u16::from_be_bytes(value.port);
        Self::new(IpAddress::Ipv6(Ipv6Address(value.addr_v6)), port)
    }
}

impl From<SocketAddressV6> for IpListenEndpoint {
    fn from(value: SocketAddressV6) -> Self {
        let port = u16::from_be_bytes(value.port);
        let addr = Ipv6Address(value.addr_v6);
        if addr.is_unspecified() {
            if port != 0 {
                IpListenEndpoint { addr: None, port }
            } else {
                IpListenEndpoint {
                    addr: None,
                    port: random_port(),
                }
            }
        } else {
            IpListenEndpoint {
                addr: Some(IpAddress::Ipv6(addr)),
                port,
            }
        }
    }
}

pub fn to_endpoint(listen_endpoint: IpListenEndpoint) -> IpEndpoint {
    let addr = if listen_endpoint.addr.is_none() {
        IpAddress::v4(127, 0, 0, 1)
    } else {
        listen_endpoint.addr.unwrap()
    };
    IpEndpoint::new(addr, listen_endpoint.port)
}
pub fn listen_endpoint(addr_buf: &[u8]) -> SyscallResult<IpListenEndpoint> {
    let family = u16::from_ne_bytes(addr_buf[0..2].try_into().expect("family size wrong"));
    match family {
        AF_INET => {
            let ipv4 = SocketAddressV4::new(addr_buf);
            Ok(IpListenEndpoint::from(ipv4))
        }
        AF_INET6 => {
            let ipv6 = SocketAddressV6::new(addr_buf);
            Ok(IpListenEndpoint::from(ipv6))
        }
        _ => {
            return Err(Errno::EINVAL);
        }
    }
}
pub fn endpoint(addr_buf: &[u8]) -> SyscallResult<IpEndpoint> {
    let listen_endpoint = listen_endpoint(addr_buf)?;
    let addr = if listen_endpoint.addr.is_none() {
        IpAddress::v4(127, 0, 0, 1)
    } else {
        listen_endpoint.addr.unwrap()
    };
    Ok(IpEndpoint::new(addr, listen_endpoint.port))
}
pub fn fill_with_endpoint(
    endpoint: IpEndpoint,
    addr: usize,
    addrlen: usize,
) -> SyscallResult<usize> {
    match endpoint.addr {
        IpAddress::Ipv4(_) => {
            let len = size_of::<u16>() + size_of::<SocketAddressV4>();
            // tos在此处使用UserCheck检查了addr开始处的len长度内存是否支持写入。
            let addr_buf = unsafe { slice::from_raw_parts_mut(addr as *mut u8, len) };
            SocketAddressV4::from(endpoint).fill(addr_buf, addrlen);
        }
        IpAddress::Ipv6(_) => {
            let len = size_of::<u16>() + size_of::<SocketAddressV6>();
            let addr_buf = unsafe { slice::from_raw_parts_mut(addr as *mut u8, len) };
            SocketAddressV6::from(endpoint).fill(addr_buf, addrlen);
        }
    }
    Ok(0)
}

pub fn is_local(endpoint: IpEndpoint) -> bool {
    if endpoint.addr.is_unicast() && endpoint.addr.as_bytes()[0] != 127 {
        false
    } else {
        true
    }
}
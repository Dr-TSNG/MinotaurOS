use core::cmp::min;
use core::mem::size_of;
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address};
use tap::Tap;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::net::iface::NetInterface;
use crate::net::socket::{AF_INET, AF_INET6, AF_UNIX};
use crate::result::{Errno, SyscallResult};

/// sockaddr 大端序
pub enum SockAddr {
    Uninit,
    In4(SockAddrIn4),
    In6(SockAddrIn6),
    Un(SockAddrUn),
}

#[derive(Debug, Clone, Copy, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct SockAddrIn4 {
    family: u16,
    port: u16,
    addr_v4: [u8; 4],
    _zero: [u8; 8],
}

impl Default for SockAddrIn4 {
    fn default() -> Self {
        Self::new_zeroed().tap_mut(|it| it.family = AF_INET)
    }
}

#[derive(Debug, Clone, Copy, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr_v6: [u8; 16],
    scope_id: u32,
}

impl Default for SockAddrIn6 {
    fn default() -> Self {
        Self::new_zeroed().tap_mut(|it| it.family = AF_INET6)
    }
}

#[derive(Debug, Clone, Copy, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct SockAddrUn {
    family: u16,
    path: [u8; 108],
}

impl Default for SockAddrUn {
    fn default() -> Self {
        Self::new_zeroed().tap_mut(|it| it.family = AF_UNIX)
    }
}

impl SockAddr {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SockAddr::Uninit => &[],
            SockAddr::In4(addr) => addr.as_bytes(),
            SockAddr::In6(addr) => addr.as_bytes(),
            SockAddr::Un(addr) => addr.as_bytes(),
        }
    }
}

impl From<IpEndpoint> for SockAddr {
    fn from(value: IpEndpoint) -> Self {
        match value.addr {
            IpAddress::Ipv4(addr) => {
                Self::In4(SockAddrIn4 {
                    family: AF_INET,
                    port: value.port.to_be(),
                    addr_v4: addr.0,
                    ..SockAddrIn4::new_zeroed()
                })
            }
            IpAddress::Ipv6(addr) => {
                Self::In6(SockAddrIn6 {
                    family: AF_INET6,
                    port: value.port.to_be(),
                    addr_v6: addr.0,
                    ..SockAddrIn6::new_zeroed()
                })
            }
        }
    }
}

impl SockAddr {
    pub fn from_bytes(buf: &[u8]) -> SyscallResult<Self> {
        if buf.len() < size_of::<u16>() {
            return Err(Errno::EINVAL);
        }
        let family = u16::from_ne_bytes(buf[0..2].try_into().unwrap());
        match family {
            AF_INET => {
                let addr = SockAddrIn4::read_from(buf).ok_or(Errno::EINVAL)?;
                Ok(Self::In4(addr))
            }
            AF_INET6 => {
                let addr = SockAddrIn6::read_from(buf).ok_or(Errno::EINVAL)?;
                Ok(Self::In6(addr))
            }
            _ => Err(Errno::EINVAL),
        }
    }
}

impl TryFrom<SockAddr> for IpEndpoint {
    type Error = Errno;

    fn try_from(value: SockAddr) -> SyscallResult<Self> {
        match value {
            SockAddr::In4(addr) => {
                Ok(Self {
                    addr: IpAddress::Ipv4(Ipv4Address(addr.addr_v4)),
                    port: addr.port.to_be(),
                })
            }
            SockAddr::In6(addr) => {
                Ok(Self {
                    addr: IpAddress::Ipv6(Ipv6Address(addr.addr_v6)),
                    port: addr.port.to_be(),
                })
            }
            _ => Err(Errno::EINVAL),
        }
    }
}

pub fn unspecified_ipep() -> IpEndpoint {
    IpEndpoint {
        addr: Ipv4Address::default().into(),
        port: 0,
    }
}

pub fn specify_ipep(net: &mut NetInterface, ep: &mut IpEndpoint) {
    if ep.addr.is_unspecified() {
        ep.addr = Ipv4Address::new(127, 0, 0, 1).into();
    }
    if ep.port == 0 {
        ep.port = net.port_cx.alloc_physical();
    }
}

pub fn copy_back_addr(addr: &mut [u8], buf: &SockAddr) -> usize {
    let bytes = buf.as_bytes();
    let copy = min(addr.len(), bytes.len());
    addr[..copy].copy_from_slice(&bytes[..copy]);
    copy
}

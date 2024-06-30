//！ 通过interface实现的方法来实现socket的操作。

use alloc::vec;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Loopback, Medium};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr};

use crate::net::netaddress::IpAddr;
use crate::sched::time::current_time;
use crate::strace;
use crate::sync::mutex::Mutex;

pub fn init() {
    NET_INTERFACE.init();
}

pub static NET_INTERFACE: NetInterface = NetInterface::new();

pub struct NetInterface<'a> {
    inner: Mutex<Option<InterfaceInner<'a>>>,
}

pub struct InterfaceInner<'a> {
    pub dev: Loopback,
    pub i_face: Interface,
    pub sockets_set: SocketSet<'a>,
}

impl<'a> NetInterface<'a> {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub fn init(&self) {
        *self.inner.lock() = Some(InterfaceInner::new());
    }

    pub fn add_socket<T>(&self, socket: T) -> SocketHandle
    where
        T: AnySocket<'a>,
    {
        self.inner.lock().as_mut().unwrap().sockets_set.add(socket)
    }

    pub fn remove(&self, handler: SocketHandle) {
        self.inner_handler(|inner| {
            inner.sockets_set.remove(handler);
        });
    }

    pub fn handle_udp_socket<T>(
        &self,
        handler: SocketHandle,
        f: impl FnOnce(&mut udp::Socket) -> T,
    ) -> T {
        f(self
            .inner
            .lock()
            .as_mut()
            .unwrap()
            .sockets_set
            .get_mut::<udp::Socket>(handler))
    }

    pub fn inner_handler<T>(&self, f: impl FnOnce(&mut InterfaceInner<'a>) -> T) -> T {
        f(&mut self.inner.lock().as_mut().unwrap())
    }

    pub fn handle_tcp_socket<T>(
        &self,
        handler: SocketHandle,
        f: impl FnOnce(&mut tcp::Socket) -> T,
    ) -> T {
        f(self
            .inner
            .lock()
            .as_mut()
            .unwrap()
            .sockets_set
            .get_mut::<tcp::Socket>(handler))
    }

    pub fn inner_handle<T>(&self, f: impl FnOnce(&mut InterfaceInner<'a>) -> T) -> T {
        f(&mut self.inner.lock().as_mut().unwrap())
    }

    /// Transmit packets queued in the given sockets, and receive packets queued in the device.
    pub fn poll(&self) {
        self.inner_handle(|inner| {
            inner.i_face.poll(
                Instant::from_millis(current_time().as_millis() as i64),
                &mut inner.dev,
                &mut inner.sockets_set,
            );
        });
    }
}

impl<'a> InterfaceInner<'a> {
    pub fn new() -> Self {
        let mut dev = Loopback::new(Medium::Ethernet);
        let config = match dev.capabilities().medium {
            Medium::Ethernet => {
                Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
            }
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            _ => {
                panic!("Not Impl Net Medium Type!")
            }
        };
        let mut i_face = Interface::new(
            config,
            &mut dev,
            Instant::from_millis(current_time().as_millis() as i64),
        );
        i_face.update_ip_addrs(|ip_address| {
            ip_address
                .push(IpCidr::new(IpAddr::v4(127, 0, 0, 1), 8))
                .unwrap();
            ip_address
                .push(IpCidr::new(IpAddr::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
                .unwrap();
        });
        Self {
            dev,
            i_face,
            sockets_set: SocketSet::new(vec![]),
        }
    }
}

//！ 通过interface实现的方法来实现socket的操作。

use alloc::vec;
use core::str::FromStr;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Loopback, Medium};
use smoltcp::socket::AnySocket;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};
use crate::driver::NET_DEVICE;
use crate::net::netaddress::IpAddr;
use crate::sched::time::cpu_time;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

const IP: &str = "10.0.2.15"; // QEMU user networking default IP
const GATEWAY: &str = "10.0.2.2"; // QEMU user networking gateway

pub static NET_INTERFACE: LateInit<Mutex<NetInterface>> = LateInit::new();

pub struct NetInterface<'a> {
    pub device: OSNetDevice,
    pub loopback: LoopbackDevice,
    pub sockets_dev: SocketSet<'a>,
    pub sockets_loop: SocketSet<'a>,
}

pub struct OSNetDevice {
    pub iface: Interface,
}

pub struct LoopbackDevice {
    pub device: Loopback,
    pub iface: Interface,
}

impl OSNetDevice {
    /// 这里是 os net dev的配置初始化
    fn new() -> Self {
        let mut device_lock = NET_DEVICE.lock();
        let device = device_lock.as_mut().unwrap();
        let config = match device.capabilities().medium {
            Medium::Ethernet => {
                Config::new(EthernetAddress([0x03, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
            }
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        };
        let mut iface = Interface::new(
            config,
            device,
            Instant::from_millis(cpu_time().as_millis() as i64),
        );
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddr::from_str(IP).unwrap(), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from_str(GATEWAY).unwrap())
            .unwrap();

        Self { iface }
    }
}

impl LoopbackDevice {
    pub fn new() -> Self {
        let mut device = Loopback::new(Medium::Ip);
        let config = match device.capabilities().medium {
            Medium::Ethernet => {
                Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
            }
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        };
        let mut iface = Interface::new(
            config,
            &mut device,
            Instant::from_millis(cpu_time().as_millis() as i64),
        );
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddr::v4(127, 0, 0, 1), 8))
                .unwrap();
        });

        Self { device, iface }
    }
}

impl<'a> NetInterface<'a> {
    pub fn new() -> Self {
        Self {
            device: OSNetDevice::new(),
            loopback: LoopbackDevice::new(),
            sockets_dev: SocketSet::new(vec![]),
            sockets_loop: SocketSet::new(vec![]),
        }
    }

    pub fn add_socket<T>(&mut self, socket_loop: T, socket_dev: T) -> (SocketHandle, SocketHandle)
    where
        T: AnySocket<'a>,
    {
        let loop_handle = self.sockets_loop.add(socket_dev);
        let dev_handle = self.sockets_dev.add(socket_loop);
        (loop_handle, dev_handle)
    }

    fn poll_loopback(&mut self) {
        // info!("[NetInterface::poll] poll loopback...");
        self.loopback.iface.poll(
            Instant::from_millis(cpu_time().as_millis() as i64),
            &mut self.loopback.device,
            &mut self.sockets_loop,
        );
    }

    fn poll_device(&mut self) {
        // info!("[NetInterface::poll] poll device...");
        self.device.iface.poll(
            Instant::from_millis(cpu_time().as_millis() as i64),
            NET_DEVICE.lock().as_mut().unwrap(),
            &mut self.sockets_dev,
        );
    }

    pub fn poll(&mut self, is_local: bool) {
        if is_local {
            self.poll_loopback();
        } else {
            self.poll_device();
        }
    }

    pub fn poll_all(&mut self) {
        self.poll_loopback();
        self.poll_device();
    }

    pub fn remove(&mut self, handle_loop: SocketHandle, handle_dev: SocketHandle) {
        self.sockets_loop.remove(handle_loop);
        self.sockets_dev.remove(handle_dev);
    }
}

pub fn init() {
    NET_INTERFACE.init(Mutex::new(NetInterface::new()));
}

//！ 通过interface实现的方法来实现socket的操作。

use alloc::vec;
use core::str::FromStr;
use log::info;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Loopback, Medium};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};
use crate::driver::{DEVICES, NET_DEVICE, NetDevice};

use crate::driver::Device as DriverDevice;
use crate::driver::virtnet::VirtIONetDevice;
use crate::net::netaddress::IpAddr;
use crate::net::netaddress::to_endpoint;
use crate::sched::time::cpu_time;
use crate::sync::mutex::Mutex;

const IP: &str = "10.0.2.15"; // QEMU user networking default IP
const GATEWAY: &str = "10.0.2.2"; // QEMU user networking gateway

pub fn init() {
    NET_INTERFACE.init();
}

pub static NET_INTERFACE: NetInterface = NetInterface::new();

pub struct NetInterface<'a> {
    device:Mutex<Option<OSNetDevice>>,
    loop_back:Mutex<Option<LoopBackDev>>,
    sockets_loop_back: Mutex<Option<SocketSet<'a>>>,
    sockets_dev: Mutex<Option<SocketSet<'a>>>,
}

pub struct OSNetDevice {
    pub iface: Interface,
    // pub device: VirtIONetDevice,
}

pub struct LoopBackDev{
    pub device: Loopback,
    pub iface: Interface,
}

impl LoopBackDev {
    pub fn new() -> Self {
        let mut device = Loopback::new(Medium::Ip);
        let iface = {
            let config = match device.capabilities().medium {
                Medium::Ethernet => {
                    Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
                }
                Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
                _ => {
                    panic!("Not Impl Net Medium Type!")
                }
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

            iface
        };
        Self {
            device,
            iface,
        }
    }
}

impl OSNetDevice {

    /// 这里是 os net dev的配置初始化
    fn new() -> Self {
        let mut device_lock = NET_DEVICE.lock();
        let device = device_lock.as_mut().unwrap();
        let iface = {
            let config = match device.capabilities().medium {
                Medium::Ethernet => {
                    Config::new(EthernetAddress([0x03, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
                }
                Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
                _ => {
                    panic!("Not Impl Net Medium Type!")
                }
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

            iface
        };
        Self{
            iface,
        }

        /*
        for device in DEVICES.read().values() {
            if let DriverDevice::Net(device) = device {
                let iface = {
                    let mut device = device as VirtIONetDevice;
                    let config = match device.capabilities().medium {
                        Medium::Ethernet => {
                            Config::new(EthernetAddress([0x03, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
                        }
                        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
                        _ => {
                            panic!("Not Impl Net Medium Type!")
                        }
                    };
                    let mut iface = Interface::new(
                        config,
                        &mut device,
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

                    iface
                };
                info!("find one net device , now quit search");
                return Self {
                    iface,
                    // device: device as VirtIONetDevice,
                }
            }
        }
        panic!("cannot find NetDevice , add NetDevice in DEVICES , ERROR!!!");
         */
    }
}

impl<'a> NetInterface<'a>{
    pub const fn new() -> Self {
        Self {
            device: Mutex::new(None),
            loop_back: Mutex::new(None),
            sockets_loop_back: Mutex::new(None),
            sockets_dev: Mutex::new(None),
        }
    }

    pub fn init(&self) {
        *self.device.lock() = Some(OSNetDevice::new());
        *self.loop_back.lock() = Some(LoopBackDev::new());
        *self.sockets_loop_back.lock() = Some(SocketSet::new(vec![]));
        *self.sockets_dev.lock() = Some(SocketSet::new(vec![]));
    }

    pub fn add_socket<T>(&self, socket_loop: T, socket_dev: T) -> (SocketHandle, SocketHandle)
    where
        T: AnySocket<'a>,
    {
        let socket_loop_handle = self.sockets_loop_back.lock().as_mut().unwrap().add(socket_loop);
        let socket_dev_handle = self.sockets_dev.lock().as_mut().unwrap().add(socket_dev);
        (socket_loop_handle,socket_dev_handle)
    }

    pub fn handle_tcp_socket_loop<T>(
        &self,
        handler: SocketHandle,
        f: impl FnOnce(&mut tcp::Socket) -> T,
    ) -> T {
        f(self
            .sockets_loop_back
            .lock()
            .as_mut()
            .unwrap()
            .get_mut::<tcp::Socket>(handler))
    }

    pub fn handle_tcp_socket_dev<T>(
        &self,
        handler: SocketHandle,
        f: impl FnOnce(&mut tcp::Socket) -> T,
    ) -> T {
        f(self
            .sockets_dev
            .lock()
            .as_mut()
            .unwrap()
            .get_mut::<tcp::Socket>(handler))
    }

    pub fn handle_udp_socket_loop<T>(
        &self,
        handler: SocketHandle,
        f: impl FnOnce(&mut udp::Socket) -> T,
    ) -> T {
        f(self
            .sockets_loop_back
            .lock()
            .as_mut()
            .unwrap()
            .get_mut::<udp::Socket>(handler))
    }

    pub fn handle_udp_socket_dev<T>(
        &self,
        handler: SocketHandle,
        f: impl FnOnce(&mut udp::Socket) -> T,
    ) -> T {
        f(self
            .sockets_dev
            .lock()
            .as_mut()
            .unwrap()
            .get_mut::<udp::Socket>(handler))
    }

    pub fn loopback<T>(&self, f: impl FnOnce(&mut LoopBackDev) -> T) -> T {
        f(&mut self.loop_back.lock().as_mut().unwrap())
    }
    pub fn device<T>(&self, f: impl FnOnce(&mut OSNetDevice) -> T) -> T {
        f(&mut self.device.lock().as_mut().unwrap())
    }

    fn poll_loopback(&self) {
        info!("[NetInterface::poll] poll loopback...");
        self.loopback(|inner| {
            inner.iface.poll(
                Instant::from_millis(cpu_time().as_millis() as i64),
                &mut inner.device,
                &mut self.sockets_loop_back.lock().as_mut().unwrap(),
            );
        });
    }

    fn poll_device(&self) {
        info!("[NetInterface::poll] poll device...");
        self.device(|inner|{
            inner.iface.poll(
                Instant::from_millis(cpu_time().as_millis() as i64),
                NET_DEVICE.lock().as_mut().unwrap(),
                &mut self.sockets_dev.lock().as_mut().unwrap(),
            )
        });
    }

    pub fn poll(&self, is_local: bool) {
        if is_local {
            self.poll_loopback();
        } else {
            self.poll_device();
        }
    }

    pub fn poll_all(&self) {
        self.poll_loopback();
        self.poll_device();
    }

    pub fn remove(&self, handler_loop: SocketHandle, handler_dev: SocketHandle) {
        self.sockets_loop_back
            .lock()
            .as_mut()
            .unwrap()
            .remove(handler_loop);
        self.sockets_dev
            .lock()
            .as_mut()
            .unwrap()
            .remove(handler_dev);
    }
}


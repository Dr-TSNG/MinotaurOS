//！ 通过interface实现的方法来实现socket的操作。

use alloc::vec;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use crate::net::port::PortContext;
use crate::sched::time::cpu_time;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

pub static NET_INTERFACE: LateInit<Mutex<NetInterface>> = LateInit::new();

pub struct NetInterface {
    pub iface: Interface,
    pub device: Loopback,
    pub sockets: SocketSet<'static>,
    pub port_cx: PortContext,
}

impl NetInterface {
    pub fn new() -> Self {
        let mut device = Loopback::new(Medium::Ip);
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(
            config,
            &mut device,
            Instant::from_millis(cpu_time().as_millis() as i64),
        );
        
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
        Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            port_cx: PortContext::new(),
        }
    }

    pub fn poll(&mut self) {
        // info!("[NetInterface::poll] poll loopback...");
        self.iface.poll(
            Instant::from_millis(cpu_time().as_millis() as i64),
            &mut self.device,
            &mut self.sockets,
        );
    }
}

pub fn init() {
    NET_INTERFACE.init(Mutex::new(NetInterface::new()));
}

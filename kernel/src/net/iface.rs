//！ 通过interface实现的方法来实现socket的获取。

use crate::net::netaddress::IpAddr;
use crate::sched::time::current_time;
use alloc::vec;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr};
use crate::net::tcp::TcpSocket;
use crate::sync::mutex::Mutex;


/*
    temp , used like this in https://github.com/smoltcp-rs/smoltcp/blob/main/examples/loopback.rs

    -------------------------------------------------------------
    // Create interface
    let mut config = match device.capabilities().medium {
        Medium::Ethernet => {
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        Medium::Ieee802154 => todo!(),
    };

    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
            .unwrap();
    });

    // Create sockets
    let server_socket = {
        // It is not strictly necessary to use a `static mut` and unsafe code here, but
        // on embedded systems that smoltcp targets it is far better to allocate the data
        // statically to verify that it fits into RAM rather than get undefined behavior
        // when stack overflows.
        static mut TCP_SERVER_RX_DATA: [u8; 1024] = [0; 1024];
        static mut TCP_SERVER_TX_DATA: [u8; 1024] = [0; 1024];
        let tcp_rx_buffer = tcp::SocketBuffer::new(unsafe { &mut TCP_SERVER_RX_DATA[..] });
        let tcp_tx_buffer = tcp::SocketBuffer::new(unsafe { &mut TCP_SERVER_TX_DATA[..] });
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let client_socket = {
        static mut TCP_CLIENT_RX_DATA: [u8; 1024] = [0; 1024];
        static mut TCP_CLIENT_TX_DATA: [u8; 1024] = [0; 1024];
        let tcp_rx_buffer = tcp::SocketBuffer::new(unsafe { &mut TCP_CLIENT_RX_DATA[..] });
        let tcp_tx_buffer = tcp::SocketBuffer::new(unsafe { &mut TCP_CLIENT_TX_DATA[..] });
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let mut sockets: [_; 2] = Default::default();
    let mut sockets = SocketSet::new(&mut sockets[..]);
    let server_handle = sockets.add(server_socket);
    let client_handle = sockets.add(client_socket);

    let mut did_listen = false;
    let mut did_connect = false;
    let mut done = false;
    while !done && clock.elapsed() < Instant::from_millis(10_000) {
        iface.poll(clock.elapsed(), &mut device, &mut sockets);

        let mut socket = sockets.get_mut::<tcp::Socket>(server_handle);
        if !socket.is_active() && !socket.is_listening() {
            if !did_listen {
                debug!("listening");
                socket.listen(1234).unwrap();
                did_listen = true;
            }
        }

        if socket.can_recv() {
            debug!(
                "got {:?}",
                socket.recv(|buffer| { (buffer.len(), str::from_utf8(buffer).unwrap()) })
            );
            socket.close();
            done = true;
        }

        let mut socket = sockets.get_mut::<tcp::Socket>(client_handle);
        let cx = iface.context();
        if !socket.is_open() {
            if !did_connect {
                debug!("connecting");
                socket
                    .connect(cx, (IpAddress::v4(127, 0, 0, 1), 1234), 65000)
                    .unwrap();
                did_connect = true;
            }
        }

        if socket.can_send() {
            debug!("sending");
            socket.send_slice(b"0123456789abcdef").unwrap();
            socket.close();
        }

        match iface.poll_delay(clock.elapsed(), &sockets) {
            Some(Duration::ZERO) => debug!("resuming"),
            Some(delay) => {
                debug!("sleeping for {} ms", delay);
                clock.advance(delay)
            }
            None => clock.advance(Duration::from_millis(1)),
        }
    }

    if done {
        info!("done")
    } else {
        error!("this is taking too long, bailing out")
    }


*/
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
    pub fn new() -> Self {
        let i_inner = InterfaceInner::new();
        Self {
            inner: Mutex::new(Some(i_inner)),
        }
    }

    /// Transmit packets queued in the given sockets, and receive packets queued in the device.
    pub fn poll(&self) {
        let mut inner = self.inner.lock().as_mut().unwrap();
        let ret = inner.i_face.poll(
            Instant::from_millis(current_time().as_millis() as i64),
            &mut inner.dev,
            &mut inner.sockets_set,
        );
    }

    /// 将tcp socket加入到INTERFACE中，返回 handler给 tcp结构体使用
    pub fn add_tcpsocket(socket: TcpSocket) -> SocketHandle{
        todo!();
    }

    /// 将tcp socket加入到INTERFACE中，返回 handler给 udp结构体使用
    pub fn add_udpsocket() -> SocketHandle{
        todo!();
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
            _ => {panic!("Not Impl Net Medium Type!")}
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

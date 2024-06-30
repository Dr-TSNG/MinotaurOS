mod iface;
mod netaddress;
mod port;
mod socket;
mod tcp;
mod udp;
mod unix;

pub const MAX_BUFFER_SIZE: usize = 1 << 17;

pub use crate::net::socket::listen_endpoint;
pub use crate::net::socket::Socket;
pub use crate::net::socket::SocketAddressV4;
pub use crate::net::socket::SocketAddressV6;
pub use crate::net::socket::SocketType;
pub use crate::net::tcp::*;
pub use crate::net::unix::make_unix_socket_pair;
pub use iface::NET_INTERFACE;
pub use socket::SocketTable;
pub use crate::net::iface::init;

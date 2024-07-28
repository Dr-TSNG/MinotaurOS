mod iface;
mod netaddress;
mod port;
mod socket;
mod tcp;
mod udp;
mod unix;

const MAX_BUFFER_SIZE: usize = 1 << 17;

pub use crate::net::socket::Socket;
pub use crate::net::socket::{SocketType, RecvFromFlags};
pub use crate::net::tcp::TCP_MSS;
pub use crate::net::netaddress::{SockAddr, copy_back_addr};
pub use crate::net::unix::make_unix_socket_pair;
pub use crate::net::iface::init;

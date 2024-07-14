use alloc::string::ToString;
use alloc::sync::Arc;

use async_trait::async_trait;
use smoltcp::{
    phy::{self, DeviceCapabilities},
    time::Instant,
};
use spin::mutex::SpinMutex;
use virtio_drivers::{
    device::net::{RxBuffer, VirtIONet},
    Error,
    transport::mmio::{MmioTransport, VirtIOHeader},
};

use crate::arch::VirtAddr;
use crate::driver::DeviceMeta;
use crate::driver::virtio::VirtioHal;
use crate::sync::once::LateInit;

type Mutex<T> = SpinMutex<T>;

const QUEUE_SIZE: usize = 1 << 10;
const BUF_LEN: usize = 1 << 12;

// Virt-NetIO的驱动
type NetDevice = VirtIONet<VirtioHal, MmioTransport, QUEUE_SIZE>;


pub struct VirtIONetDevice{
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    dev:LateInit<Arc<Mutex<NetDevice>>>,
}

#[async_trait]
impl super::NetDevice for VirtIONetDevice{
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn init(&self) {
        unsafe {
            let header = self.base_addr.as_ptr().cast::<VirtIOHeader>().as_mut().unwrap();
            let transport = MmioTransport::new(header.into()).unwrap();
            let netdev = NetDevice::new(transport,BUF_LEN).unwrap();
            self.dev.init(Arc::new(Mutex::new(netdev)))
        }
    }
}

pub struct VirtioRxToken(Arc<Mutex<NetDevice>>, RxBuffer);
pub struct VirtioTxToken(Arc<Mutex<NetDevice>>);

impl smoltcp::phy::Device for VirtIONetDevice{
    type RxToken<'a>
    = VirtioRxToken where
        Self: 'a;
    type TxToken<'a> =
    VirtioTxToken
    where
        Self: 'a
    ;

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.dev.lock().receive() {
            Ok(buf) => {
                Some((
                    VirtioRxToken(self.dev.clone(),buf),
                    VirtioTxToken(self.dev.clone()),
                ))
            },
            Err(Error::NotReady) => {None},
            Err(err) => {panic!("receive failed : {}",err)},
        }
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken(self.dev.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_burst_size = Some(1);
        cap.max_transmission_unit = 1536;
        cap
    }
}

impl phy::RxToken for VirtioRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut rx_buf = self.1;
        let ret = f(rx_buf.packet_mut());
        self.0.lock().recycle_rx_buffer(rx_buf).unwrap();
        ret
    }
}
impl phy::TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut dev = self.0.lock();
        let mut tx_buf = dev.new_tx_buffer(len);
        let ret = f(tx_buf.packet_mut());
        dev.send(tx_buf).expect("failed to send packet");
        ret
    }
}

impl VirtIONetDevice {
    pub fn new(base_addr: VirtAddr) -> Self {
        Self{
            base_addr,
            metadata: DeviceMeta::new("virtio-net".to_string()),
            dev: LateInit::new(),
        }
    }
}
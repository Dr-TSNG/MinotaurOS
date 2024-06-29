use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use log::error;
use crate::driver::BlockDevice;
use crate::result::Errno;
use crate::sync::block_on;

const BLOCK_SIZE: usize = 512;

pub struct BlockDeviceWrapper(Arc<dyn BlockDevice>);

impl BlockDeviceWrapper {
    pub fn new(device: Arc<dyn BlockDevice>) -> Arc<Self> {
        Arc::new(Self(device))
    }
}

impl ext4_rs::BlockDevice for BlockDeviceWrapper {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        let mut buf = vec![0; BLOCK_SIZE];
        block_on(self.0.read_block(offset / BLOCK_SIZE, &mut buf)).unwrap();
        buf
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        block_on(self.0.write_block(offset / BLOCK_SIZE, data)).unwrap();
    }
}

pub(super) fn map_errno(e: ext4_rs::Ext4Error) -> Errno {
    error!("[Ext4] {:?}", e);
    unsafe { core::mem::transmute(e.error()) }
}

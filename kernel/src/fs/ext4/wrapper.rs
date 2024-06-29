use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use log::error;
use tap::Tap;
use crate::driver::BlockDevice;
use crate::result::Errno;
use crate::sync::block_on;

pub struct BlockDeviceWrapper(Arc<dyn BlockDevice>);

impl BlockDeviceWrapper {
    pub fn new(device: Arc<dyn BlockDevice>) -> Arc<Self> {
        Arc::new(Self(device))
    }
}

impl ext4_rs::BlockDevice for BlockDeviceWrapper {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        let sec_size = self.0.sector_size();
        let off_blk = offset / sec_size;
        let off_off = offset % sec_size;
        let buf_size = match off_off {
            0 => ext4_rs::BLOCK_SIZE,
            _ => ext4_rs::BLOCK_SIZE + sec_size,
        };
        let mut buf = vec![0; buf_size];
        for i in 0..buf_size / sec_size {
            let start = i * sec_size;
            let end = (i + 1) * sec_size;
            block_on(self.0.read_block(off_blk + i, &mut buf[start..end])).unwrap();
        }
        buf.split_off(off_off).tap_mut(|buf| buf.truncate(ext4_rs::BLOCK_SIZE))
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        let sec_size = self.0.sector_size();
        let off_blk = offset / sec_size;
        let off_off = offset % sec_size;
        let buf_size = (off_off + data.len()).div_ceil(sec_size) * sec_size;
        let mut buf = vec![0; buf_size];
        block_on(self.0.read_block(off_blk, &mut buf[..sec_size])).unwrap();
        block_on(self.0.read_block(off_blk + buf_size / sec_size - 1, &mut buf[buf_size - sec_size..])).unwrap();
        buf[off_off..off_off + data.len()].copy_from_slice(data);
        for i in 0..buf_size / sec_size {
            let start = i * sec_size;
            let end = (i + 1) * sec_size;
            block_on(self.0.write_block(off_blk + i, &buf[start..end])).unwrap();
        }
    }
}

pub(super) fn map_errno(e: ext4_rs::Ext4Error) -> Errno {
    error!("[ext4] {:?}", e);
    unsafe { core::mem::transmute(e.error()) }
}

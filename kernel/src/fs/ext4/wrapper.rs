use alloc::sync::Arc;
use alloc::vec;
use core::ops::Deref;

use lwext4_rust::{Ext4BlockWrapper, KernelDevOp};

use crate::driver::BlockDevice;
use crate::sync::block_on;

pub struct Ext4(Ext4BlockWrapper<Ext4Disk>);

unsafe impl Send for Ext4 {}

unsafe impl Sync for Ext4 {}

impl Deref for Ext4 {
    type Target = Ext4BlockWrapper<Ext4Disk>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ext4 {
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self(Ext4BlockWrapper::new(Ext4Disk::new(device)).unwrap())
    }
}

pub struct Ext4Disk {
    device: Arc<dyn BlockDevice>,
    offset: usize,
}

impl Ext4Disk {
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self { device, offset: 0 }
    }
}

impl KernelDevOp for Ext4Disk {
    type DevType = Self;

    fn write(op: &mut Self::DevType, data: &[u8]) -> Result<usize, i32> {
        let sec_size = op.device.sector_size();
        let off_blk = op.offset / sec_size;
        let off_off = op.offset % sec_size;
        let buf_size = (off_off + data.len()).div_ceil(sec_size) * sec_size;
        let mut buf = vec![0; buf_size];
        block_on(op.device.read_block(off_blk, &mut buf[..sec_size])).unwrap();
        block_on(op.device.read_block(off_blk + buf_size / sec_size - 1, &mut buf[buf_size - sec_size..])).unwrap();
        buf[off_off..off_off + data.len()].copy_from_slice(data);
        for i in 0..buf_size / sec_size {
            let start = i * sec_size;
            let end = (i + 1) * sec_size;
            block_on(op.device.write_block(off_blk + i, &buf[start..end])).unwrap();
        }
        op.offset += data.len();
        Ok(data.len())
    }

    fn read(op: &mut Self::DevType, data: &mut [u8]) -> Result<usize, i32> {
        let sec_size = op.device.sector_size();
        let off_blk = op.offset / sec_size;
        let off_off = op.offset % sec_size;
        let buf_size = (off_off + data.len()).div_ceil(sec_size) * sec_size;
        let mut buf = vec![0; buf_size];
        for i in 0..buf_size / sec_size {
            let start = i * sec_size;
            let end = (i + 1) * sec_size;
            block_on(op.device.read_block(off_blk + i, &mut buf[start..end])).unwrap();
        }
        data.copy_from_slice(&buf[off_off..off_off + data.len()]);
        op.offset += data.len();
        Ok(data.len())
    }

    fn seek(op: &mut Self::DevType, off: i64, whence: i32) -> Result<i64, i32> {
        op.offset = match whence as u32 {
            lwext4_rust::bindings::SEEK_SET => off as usize,
            lwext4_rust::bindings::SEEK_CUR => op.offset + off as usize,
            lwext4_rust::bindings::SEEK_END => op.device.dev_size() + off as usize,
            _ => panic!("Invalid whence: {}", whence),
        };
        if op.offset > op.device.dev_size() {
            panic!("Seeking beyond device size");
        }
        Ok(op.offset as i64)
    }

    fn flush(_: &mut Self::DevType) -> Result<usize, i32>
    where
        Self: Sized,
    {
        Ok(0)
    }
}

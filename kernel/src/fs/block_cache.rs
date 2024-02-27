use alloc::sync::Arc;
use lru::LruCache;
use crate::driver::BlockDevice;
use crate::result::{MosError, MosResult};
use crate::sync::mutex::AsyncMutex;

/// 异步块缓存
///
/// B: 块字节数
pub struct BlockCache<const B: usize> {
    device: Arc<dyn BlockDevice>,
    cache: AsyncMutex<LruCache<usize, CacheValue<B>>>,
}

pub struct CacheValue<const B: usize> {
    dirty: bool,
    data: [u8; B],
}

impl<const B: usize> Drop for CacheValue<B> {
    fn drop(&mut self) {
        if self.dirty {
            panic!("Dirty cache block dropped without sync")
        }
    }
}

impl<const B: usize> CacheValue<B> {
    fn new(dirty: bool, data: [u8; B]) -> Self {
        Self {
            dirty,
            data,
        }
    }
}

impl<const B: usize> BlockCache<B> {
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self {
            device,
            cache: AsyncMutex::new(LruCache::new(B.try_into().unwrap())),
        }
    }

    pub async fn read_block(&self, block_id: usize, buf: &mut [u8], offset: usize) -> MosResult {
        // 越界检查
        let copy_end = buf.len().checked_add(offset)
            .take_if(|v| *v > B)
            .ok_or(MosError::CrossBoundary)?;

        // 缓存命中
        let mut cache = self.cache.lock().await;
        if let Some(block) = cache.get(&block_id) {
            buf.copy_from_slice(&block.data[offset..copy_end]);
            return Ok(());
        }
        drop(cache);

        // 缓存不命中
        let mut data = [0; B];
        self.device.read_block(block_id, &mut data).await?;
        buf.copy_from_slice(&data[offset..copy_end]);
        let mut cache = self.cache.lock().await;
        let write_back = cache.push(block_id, CacheValue::new(false, data));
        drop(cache);

        // 缓存替换
        if let Some(e) = write_back {
            self.sync(e.0, e.1).await?;
        }
        Ok(())
    }

    pub async fn write_block(&self, block_id: usize, buf: &[u8], offset: usize) -> MosResult {
        // 越界检查
        let copy_end = buf.len().checked_add(offset)
            .take_if(|v| *v > B)
            .ok_or(MosError::CrossBoundary)?;

        // 缓存命中
        let mut cache = self.cache.lock().await;
        if let Some(block) = cache.get_mut(&block_id) {
            block.dirty = true;
            block.data[offset..copy_end].copy_from_slice(buf);
            return Ok(());
        }
        drop(cache);

        // 缓存不命中
        let mut data = [0; B];
        self.device.read_block(block_id, &mut data).await?;
        data[offset..copy_end].copy_from_slice(buf);
        let mut cache = self.cache.lock().await;
        let write_back = cache.push(block_id, CacheValue::new(true, data));
        drop(cache);

        // 缓存替换
        if let Some(e) = write_back {
            self.sync(e.0, e.1).await?;
        }
        Ok(())
    }
    
    pub async fn sync_all(&self) -> MosResult {
        let mut cache = self.cache.lock().await;
        while let Some((block_id, cache)) = cache.pop_lru() {
            self.sync(block_id, cache).await?;
        }
        Ok(())
    }

    async fn sync(&self, block_id: usize, cache: CacheValue<B>) -> MosResult {
        if cache.dirty {
            self.device.write_block(block_id, &cache.data).await?;
        }
        Ok(())
    }
}

pub const SIG_START: u32 = 0x41615252;
pub const SIG_END: u32 = 0xAA550000;

/// FSInfo 扇区偏移
enum FSInfoOffset {
    /// FSInfo 扇区头部标志，值为 [SIG_START]
    LeadSig = 0,
    /// 保留位
    Reserved1 = 4,
    /// 最新的剩余簇数量
    /// 
    /// 如果为 0xFFFFFFFF 表示剩余簇未知，需要重新计算
    FreeCount = 488,
    /// 驱动程序最后分配出去的簇号
    /// 
    /// 如果为 0xFFFFFFFF，需要从簇 2 开始查找
    NxtFree = 492,
    /// 保留位
    Reserved2 = 496,
    /// FSInfo 扇区尾部标志，值为 [SIG_END]
    TrailSig = 508,
    /// 结束
    End = 512,
}

impl FSInfoOffset {
    /// FSInfo 扇区头部标志，值为 [SIG_START]
    pub fn lead_sig(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, LeadSig, Reserved1))
    }
    
    /// 最新的剩余簇数量
    pub fn free_count(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, FreeCount, NxtFree))
    }
    
    /// 驱动程序最后分配出去的簇号
    pub fn next_free(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, NxtFree, Reserved2))
    }
    
    /// FSInfo 扇区尾部标志，值为 [SIG_END]
    pub fn trail_sig(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, TrailSig, End))
    }

    fn split(sector: &[u8], start: Self, end: Self) -> &[u8] {
        &sector[start as usize..end as usize]
    }
}

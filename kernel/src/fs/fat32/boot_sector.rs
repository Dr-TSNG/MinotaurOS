use alloc::string::String;

macro_rules! section {
    ($buf:ident, $start:ident, $end:ident) => {
        Self::split($buf, Self::$start, Self::$end).try_into().unwrap()
    }
}

/// Boot Sector 偏移
pub enum BootSectorOffset {
    /// 此项忽略
    JmpBoot = 0,
    /// 此项忽略
    OEMName = 3,
    /// 此项忽略
    DrvNum = 64,
    /// 保留位
    Reserved1 = 65,
    /// 扩展引导标记，用于指明此后的 3 个域可用
    BootSig = 66,
    /// 此项忽略
    VolID = 67,
    /// 磁盘卷标
    ///
    /// 此项必须与根目录中 11 字节长的卷标一致
    VolLab = 71,
    /// 文件系统类型
    ///
    /// 此项可为 FAT12、FAT16、FAT32 之一
    FilSysType = 82,
}

impl BootSectorOffset {
    pub fn boot_sig(sector: &[u8]) -> u8 {
        u8::from_le_bytes(section!(sector, BootSig, VolID))
    }

    pub fn vol_lab(sector: &[u8]) -> String {
        String::from_utf8(section!(sector, VolLab, FilSysType))
            .unwrap_or_default()
    }

    fn split(sector: &[u8], start: Self, end: Self) -> &[u8] {
        &sector[start as usize..end as usize]
    }
}

/// BIOS Parameter Block (BPB) 偏移
pub enum BPBOffset {
    /// 每扇区字节数
    ///
    /// 取值只能是以下的几种情况：512、1024、2048 或是 4096
    BytsPerSec = 11,
    /// 每簇扇区数
    ///
    /// 其值必须是 2 的整数次方
    SecPerClus = 13,
    /// 保留区中保留扇区的数目
    RsvdSecCnt = 14,
    /// 此卷中 FAT 表的份数，通常为 2
    NumFATs = 16,
    /// 对于 FAT32，此项必须为 0
    RootEntCnt = 17,
    /// 对于 FAT32，此项必须为 0
    TotSec16 = 19,
    /// 此项忽略
    Media = 21,
    /// 对于 FAT32，此项必须为 0
    FATSz16 = 22,
    /// 此项忽略
    SecPerTrk = 24,
    /// 此项忽略
    NumHeads = 26,
    /// 在此 FAT 卷之前所隐藏的扇区数
    HiddSec = 28,
    /// 该卷总扇区数
    TotSec32 = 32,
    /// 一个 FAT 表包含的扇区数
    FATSz32 = 36,
    /// Bits 0-3：活动 FAT 表，只有在镜像禁止时才有效
    ///
    /// Bits 7：0 表示 FAT 实时镜像到所有的 FAT 表中；1 表示只有一个活动的 FAT 表
    ExtFlags = 40,
    /// FAT32 版本号
    ///
    /// 高位为主版本号，低位为次版本号
    FSVer = 42,
    /// 根目录所在第一个簇的簇号
    RootClus = 44,
    /// 保留区中 FAT32 卷 FSINFO 结构所占的扇区数
    FSInfo = 48,
    /// 此项忽略
    BkBootSec = 50,
    /// 保留位
    Reserved = 52,
}

impl BPBOffset {
    /// 每扇区字节数
    pub fn bytes_per_sector(sector: &[u8]) -> u16 {
        u16::from_le_bytes(section!(sector, BytsPerSec, SecPerClus))
    }

    /// 每簇扇区数
    pub fn sector_per_cluster(sector: &[u8]) -> u8 {
        u8::from_le_bytes(section!(sector, SecPerClus, RsvdSecCnt))
    }

    /// 保留区中保留扇区的数目
    pub fn reserved_sectors(sector: &[u8]) -> u16 {
        u16::from_le_bytes(section!(sector, RsvdSecCnt, NumFATs))
    }

    /// FAT 表数目
    pub fn fats_number(sector: &[u8]) -> u8 {
        u8::from_le_bytes(section!(sector, NumFATs, RootEntCnt))
    }

    /// 该卷总扇区数
    pub fn total_sectors(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, TotSec32, FATSz32))
    }

    /// 一个 FAT 表包含的扇区数
    pub fn fat_size(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, FATSz32, ExtFlags))
    }

    /// 扩展标签
    pub fn extend_flags(sector: &[u8]) -> u16 {
        u16::from_le_bytes(section!(sector, ExtFlags, FSVer))
    }

    /// 根目录所在第一个簇的簇号
    pub fn root_cluster(sector: &[u8]) -> u32 {
        u32::from_le_bytes(section!(sector, RootClus, FSInfo))
    }

    /// 保留区中 FAT32 卷 FSINFO 结构所占的扇区数
    pub fn fs_info(sector: &[u8]) -> u16 {
        u16::from_le_bytes(section!(sector, FSInfo, BkBootSec))
    }

    fn split(sector: &[u8], start: Self, end: Self) -> &[u8] {
        &sector[start as usize..end as usize]
    }
}

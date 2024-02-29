use alloc::string::String;
use bitflags::bitflags;
use time::{Date, Month, Time};
use crate::fs::ffi::TimeSpec;

/// 目录项偏移
enum DirOffset {
    /// 短文件名
    Name = 0,
    /// 文件属性
    Attr = 11,
    /// 此项忽略
    NTRes = 12,
    /// 文件创建时间的毫秒级时间戳
    ///
    /// 由于 CrtTime 的精度为 2 秒，所以此域的有效值在 0-199 之间
    CrtTimeTeenth = 13,
    /// 文件创建时间
    CrtTime = 14,
    /// 文件创建日期
    CrtDate = 16,
    /// 最后访问日期
    LastAccDate = 18,
    /// 该目录项簇号的高位字
    FstClusHI = 20,
    /// 最后写的时间
    WrtTime = 22,
    /// 最后写的日期
    WrtDate = 24,
    /// 该目录项簇号的低位字
    FstClusLO = 26,
    /// 文件大小
    FileSize = 28,
    /// 结束
    End = 32,
}

impl DirOffset {
    fn acc_time(value: &[u8]) -> (u16, u16) {
        let date = u16::from_le_bytes(section!(value, LastAccDate, FstClusHI));
        (date, 0)
    }

    fn wrt_time(value: &[u8]) -> (u16, u16) {
        let date = u16::from_le_bytes(section!(value, WrtDate, FstClusLO));
        let time = u16::from_le_bytes(section!(value, WrtTime, WrtDate));
        (date, time)
    }

    fn crt_time(value: &[u8]) -> (u16, u16) {
        let date = u16::from_le_bytes(section!(value, CrtDate, LastAccDate));
        let time = u16::from_le_bytes(section!(value, CrtTime, CrtDate));
        (date, time)
    }

    fn cluster(value: &[u8]) -> u32 {
        let hi = u16::from_le_bytes(section!(value, FstClusHI, WrtTime));
        let lo = u16::from_le_bytes(section!(value, FstClusLO, FileSize));
        (u32::from(hi) << 16) + u32::from(lo)
    }

    fn size(value: &[u8]) -> u32 {
        u32::from_le_bytes(section!(value, FileSize, End))
    }

    fn split(value: &[u8], start: Self, end: Self) -> &[u8] {
        &value[start as usize..end as usize]
    }
}

const LAST_LONG_ENTRY: u8 = 0x40;

/// 长目录项偏移
enum LongDirOffset {
    /// 该长目录项在本组中的序号
    ///
    /// 如果标记为 [LAST_LONG_ENTRY] 则表明是该组的最后一个长目录项
    Ord = 0,
    /// 长文件名子项的第 1-5 个字符
    Name1 = 1,
    /// 属性必须为 [FileAttr::ATTR_LONG_NAME]
    Attr = 11,
    /// 如果为 0 表明是长文件名的子项
    Type = 12,
    /// 短文件名的校验和
    Chksum = 13,
    /// 长文件名子项的第 6-11 个字符
    Name2 = 14,
    /// 此项必须为 0
    FstClusLO = 26,
    /// 长文件名子项的第 12-13 个字符
    Name3 = 28,
    /// 结束
    End = 32,
}

impl LongDirOffset {
    fn name(value: &[u8]) -> String {
        let str1: [u16; 5] = bytemuck::pod_read_unaligned(Self::split(value, Self::Name1, Self::Attr));
        let str2: [u16; 6] = bytemuck::pod_read_unaligned(Self::split(value, Self::Name2, Self::FstClusLO));
        let str3: [u16; 2] = bytemuck::pod_read_unaligned(Self::split(value, Self::Name3, Self::End));
        let str1 = String::from_utf16_lossy(&str1);
        let str2 = String::from_utf16_lossy(&str2);
        let str3 = String::from_utf16_lossy(&str3);
        let mut name = str1 + str2.as_ref() + str3.as_ref();
        if let Some(end) = name.find('\0') {
            name.drain(end..);
        }
        name
    }

    fn split(value: &[u8], start: Self, end: Self) -> &[u8] {
        &value[start as usize..end as usize]
    }
}

bitflags! {
    #[derive(Default)]
    pub struct FileAttr: u8 {
        const ATTR_READ_ONLY = 0x01;
        const ATTR_HIDDEN    = 0x02;
        const ATTR_SYSTEM    = 0x04;
        const ATTR_VOLUME_ID = 0x08;
        const ATTR_DIRECTORY = 0x10;
        const ATTR_ARCHIVE   = 0x20;
        const ATTR_LONG_NAME = 0x0F;
    }
}

#[derive(Debug, Default)]
pub struct FAT32Dirent {
    pub name: String,
    pub attr: FileAttr,
    pub acc_time: TimeSpec,
    pub wrt_time: TimeSpec,
    pub crt_time: TimeSpec,
    pub cluster: u32,
    pub size: u32,
}

impl From<&[u8]> for FAT32Dirent {
    fn from(value: &[u8]) -> Self {
        let attr = FileAttr::from_bits_truncate(value[DirOffset::Attr as usize]);
        assert!(attr.contains(FileAttr::ATTR_LONG_NAME));
        let acc_time = DirOffset::acc_time(value);
        let wrt_time = DirOffset::wrt_time(value);
        let crt_time = DirOffset::crt_time(value);
        Self {
            name: String::new(),
            attr,
            acc_time: Self::time_normalize(acc_time.0, acc_time.1).unwrap_or_default(),
            wrt_time: Self::time_normalize(wrt_time.0, wrt_time.1).unwrap_or_default(),
            crt_time: Self::time_normalize(crt_time.0, crt_time.1).unwrap_or_default(),
            cluster: DirOffset::cluster(value),
            size: DirOffset::size(value),
        }
    }
}

impl FAT32Dirent {
    pub fn is_empty(value: &[u8]) -> bool {
        value[DirOffset::Name as usize] == 0x00
    }
    
    pub fn is_long_dirent(value: &[u8]) -> bool {
        let attr = FileAttr::from_bits_truncate(value[DirOffset::Attr as usize]);
        attr == FileAttr::ATTR_LONG_NAME
    }

    /// 添加一个长目录项
    pub fn append(&mut self, long_dir: &[u8]) {
        assert!(Self::is_long_dirent(long_dir));
        self.name = LongDirOffset::name(long_dir) + &self.name;
    }

    /// 添加最后的短目录项
    pub fn last(&mut self, short_dir: &[u8]) {
        assert!(!Self::is_long_dirent(short_dir));
        self.attr = FileAttr::from_bits_truncate(short_dir[DirOffset::Attr as usize]);
        let acc_time = DirOffset::acc_time(short_dir);
        let wrt_time = DirOffset::wrt_time(short_dir);
        let crt_time = DirOffset::crt_time(short_dir);
        self.acc_time = Self::time_normalize(acc_time.0, acc_time.1).unwrap_or_default();
        self.wrt_time = Self::time_normalize(wrt_time.0, wrt_time.1).unwrap_or_default();
        self.crt_time = Self::time_normalize(crt_time.0, crt_time.1).unwrap_or_default();
        self.cluster = DirOffset::cluster(short_dir);
        self.size = DirOffset::size(short_dir);
    }

    fn time_normalize(date: u16, hms: u16) -> Option<TimeSpec> {
        let day = (date & 0xf) as u8;
        let month = (date & 0xf0 >> 4) as u8;
        let year = (1980 + date >> 8) as i32;
        let second = ((hms & 0xf) * 2) as u8;
        let minute = (hms & 0x3ff >> 4) as u8;
        let hour = (hms >> 10) as u8;
        let month = Month::try_from(month).ok()?;
        let date = Date::from_calendar_date(year, month, day).ok()?;
        let hms = Time::from_hms(hour, minute, second).ok()?;
        let time = time::PrimitiveDateTime::new(date, hms);
        Some(TimeSpec::new(time.assume_utc().unix_timestamp(), 0))
    }
}

use crate::sched::ffi::TimeSpec;
use crate::sched::time::current_time;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bitflags::bitflags;
use time::{Date, Month, Time};

/// 目录项偏移
#[allow(unused)]
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
#[allow(unused)]
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
        let str1: [u16; 5] =
            bytemuck::pod_read_unaligned(Self::split(value, Self::Name1, Self::Attr));
        let str2: [u16; 6] =
            bytemuck::pod_read_unaligned(Self::split(value, Self::Name2, Self::FstClusLO));
        let str3: [u16; 2] =
            bytemuck::pod_read_unaligned(Self::split(value, Self::Name3, Self::End));
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

#[derive(Clone, Debug, Default)]
pub struct FAT32Dirent {
    pub name: String,
    pub attr: FileAttr,
    pub acc_time: TimeSpec,
    pub wrt_time: TimeSpec,
    pub crt_time: TimeSpec,
    pub cluster: u32,
    pub size: u32,
}

impl FAT32Dirent {
    pub fn is_end(value: &[u8]) -> bool {
        value[DirOffset::Name as usize] == 0x00
    }

    pub fn is_empty(value: &[u8]) -> bool {
        value[DirOffset::Name as usize] == 0xE5
    }

    pub fn is_long_dirent(value: &[u8]) -> bool {
        let attr = FileAttr::from_bits_truncate(value[DirOffset::Attr as usize]);
        attr == FileAttr::ATTR_LONG_NAME
    }

    pub fn end() -> [u8; 32] {
        [0; 32]
    }

    pub fn empty() -> [u8; 32] {
        let mut dir = [0; 32];
        dir[DirOffset::Name as usize] = 0xE5;
        dir
    }

    pub fn new(name: String, attr: FileAttr, cluster: u32, size: u32) -> Self {
        let now = current_time();
        Self {
            name,
            attr,
            acc_time: now.into(),
            wrt_time: now.into(),
            crt_time: now.into(),
            cluster,
            size,
        }
    }

    /// 添加一个长目录项
    pub fn append_long(&mut self, long_dir: &[u8]) {
        assert!(Self::is_long_dirent(long_dir));
        self.name = LongDirOffset::name(long_dir) + &self.name;
    }

    /// 添加最后的短目录项
    pub fn append_short(&mut self, short_dir: &[u8]) {
        assert!(!Self::is_long_dirent(short_dir));
        if self.name.is_empty() {
            let name = DirOffset::split(short_dir, DirOffset::Name, DirOffset::Attr);
            let name = name.split(|&x| x == 0x20).next().unwrap_or(name);
            self.name = String::from_utf8_lossy(name).to_string();
        }
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

    pub fn to_dirs(&self) -> VecDeque<[u8; 32]> {
        let short_name = self.short_name();
        let checksum = short_name.iter().fold(0u8, |sum, c| {
            (sum & 1)
                .wrapping_shl(7)
                .wrapping_add(sum >> 1)
                .wrapping_add(*c)
        });
        let mut dirs = VecDeque::new();
        let mut name: Vec<u16> = self.name.encode_utf16().collect();
        if name.len() % 13 != 0 {
            name.push(0);
        }
        for _ in name.len() % 13..13 {
            name.push(0xFFFF);
        }
        for i in 0..name.len() / 13 {
            let mut long_dir = [0; 32];
            long_dir[LongDirOffset::Ord as usize] = (i + 1) as u8;
            let slice = &name[i * 13..(i + 1) * 13];
            long_dir[LongDirOffset::Name1 as usize..LongDirOffset::Attr as usize]
                .copy_from_slice(bytemuck::cast_slice(&slice[..5]));
            long_dir[LongDirOffset::Name2 as usize..LongDirOffset::FstClusLO as usize]
                .copy_from_slice(bytemuck::cast_slice(&slice[5..11]));
            long_dir[LongDirOffset::Name3 as usize..LongDirOffset::End as usize]
                .copy_from_slice(bytemuck::cast_slice(&slice[11..]));
            long_dir[LongDirOffset::Attr as usize] = FileAttr::ATTR_LONG_NAME.bits();
            long_dir[LongDirOffset::Chksum as usize] = checksum;
            dirs.push_front(long_dir);
        }
        dirs[0][LongDirOffset::Ord as usize] |= LAST_LONG_ENTRY;

        let mut short_dir = [0; 32];
        short_dir[DirOffset::Name as usize..DirOffset::Attr as usize].copy_from_slice(&short_name);
        short_dir[DirOffset::Attr as usize] = self.attr.bits();
        let hi = (self.cluster >> 16) as u16;
        let lo = self.cluster as u16;
        short_dir[DirOffset::FstClusHI as usize..DirOffset::WrtTime as usize]
            .copy_from_slice(&hi.to_le_bytes());
        short_dir[DirOffset::FstClusLO as usize..DirOffset::FileSize as usize]
            .copy_from_slice(&lo.to_le_bytes());
        dirs.push_back(short_dir);
        dirs
    }

    fn short_name(&self) -> [u8; 11] {
        let mut short_name = [b' '; 11];
        let parts: Vec<&str> = self.name.split('.').collect();

        // Process the file name
        let file_name = parts[0].chars().take(8).collect::<String>().to_uppercase();
        for (i, c) in file_name.chars().enumerate() {
            short_name[i] = c as u8;
        }

        // Process the extension if it exists
        if parts.len() > 1 {
            let extension = parts[1].chars().take(3).collect::<String>().to_uppercase();
            for (i, c) in extension.chars().enumerate() {
                short_name[8 + i] = c as u8;
            }
        }

        // If the filename is too long, truncate and append "~1"
        if parts[0].len() > 8 {
            short_name[6] = b'~';
            short_name[7] = b'1';
        }

        short_name
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

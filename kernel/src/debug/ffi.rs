use num_enum::TryFromPrimitive;

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(i32)]
pub enum SyslogCmd {
    SYSLOG_ACTION_CLOSE = 0,
    SYSLOG_ACTION_OPEN = 1,
    SYSLOG_ACTION_READ = 2,
    SYSLOG_ACTION_READ_ALL = 3,
    SYSLOG_ACTION_READ_CLEAR = 4,
    SYSLOG_ACTION_CLEAR = 5,
    SYSLOG_ACTION_CONSOLE_OFF = 6,
    SYSLOG_ACTION_CONSOLE_ON = 7,
    SYSLOG_ACTION_CONSOLE_LEVEL = 8,
    SYSLOG_ACTION_SIZE_UNREAD = 9,
    SYSLOG_ACTION_SIZE_BUFFER = 10,
}

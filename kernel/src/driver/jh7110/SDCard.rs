use crate::sync::mutex::Mutex;
use crate::driver::jh7110::spi;

pub struct SDCardSpi{
    spi: crate::driver::jh7110::spi,
    hc: bool,
}

pub struct SDCard{
    spi: Mutex<SDCardSpi>,
}
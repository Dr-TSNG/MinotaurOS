use crate::arch::VirtAddr;
use crate::driver::jh7110::gpio::Gpio;

/* spi0 cs control from gpio 49 , if we want to control cs , we have to control this gpio
ssp0-pins_cs {
			starfive,pins = <PAD_GPIO49>;
			starfive,pinmux = <PAD_GPIO49_FUNC_SEL 0>;
			starfive,pin-ioconfig = <IO(GPIO_IE(1))>;
			starfive,pin-gpio-dout = <GPO_SPI0_SSPFSSOUT>;
			starfive,pin-gpio-doen = <OEN_LOW>;
		};
*/
pub struct SPI{
    base_addr: VirtAddr,
    cs_gpio: Gpio,
}

impl SPI{
    pub fn init(&mut self){
        unsafe {
            // 禁用SPI
            self.cr1_ptr().write_volatile(0);

            // 设置CR0: 数据格式、SPI模式、时钟等
            self.cr0_ptr().write_volatile(
                0x07 |      // 设置数据帧大小为8位
                    (0<<6) |    // 设置SPI模式，CPOL = 0, CPHA = 0
                    (0<<8),     // 设置为串行时钟速率
            );

            // 设置时钟分频器
            self.cpsr_ptr().write_volatile(2);

            // 使能SPI
            self.cr1_ptr().write_volatile(1 << 1); // SSE 位

            // 配置DMA控制器为0（禁用）
            self.dmactl_ptr().write_volatile(0);
        }
    }
    pub fn new(base_addr: VirtAddr , gpio_base_addr: VirtAddr) -> Self {
        Self { base_addr, cs_gpio: Gpio::new(gpio_base_addr) }
    }

    fn cr0_ptr(&self) -> *mut u32 {
        self.base_addr.0 as *mut u32
    }
    fn cr1_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x4).0 as *mut u32
    }
    fn dr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x8).0 as *mut u32
    }
    fn sr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0xc).0 as *mut u32
    }
    fn cpsr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x10).0 as *mut u32
    }
    fn im_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x14).0 as *mut u32
    }
    fn ris_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x18).0 as *mut u32
    }
    fn mis_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x1c).0 as *mut u32
    }
    fn icr_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x20).0 as *mut u32
    }
    fn dmactl_ptr(&self) -> *mut u32 {
        (self.base_addr + 0x24).0 as *mut u32
    }
    fn cc_ptr(&self) -> *mut u32 {
        (self.base_addr + 0xfc8).0 as *mut u32
    }

    pub fn configure(&self,protocol: u32,endian: u32){
        unsafe {
            let fmt = (protocol & 3) | ((endian & 1) << 2) | (0 << 3) | (8 << 16);
            self.cr0_ptr().write_volatile(fmt);
        }
    }

    pub fn set_clk_rate(&self, div: u32) {
        unsafe {
            self.cpsr_ptr().write_volatile(div);
        }
    }

    pub fn send_data(&self, tx: &[u8]){
        const CHUNK_LEN: usize = 4;
        for s in tx.chunks(CHUNK_LEN) {
            let n = s.len();
            unsafe {
                while (self.sr_ptr().read_volatile() & (1 << 1)) == 0 {
                    // 等待发送FIFO空闲
                }
                for i in 0..n {
                    self.dr_ptr().write_volatile(s[i].into());
                }
            }
        }
    }

    pub fn recv_data(&self, rx: &mut [u8]) {
        const CHUNK_LEN: usize = 4;
        for s in rx.chunks_mut(CHUNK_LEN) {
            let n = s.len();
            unsafe {
                while (self.sr_ptr().read_volatile() & (1 << 2)) == 0 {
                    // 等待接收FIFO非空
                }
                for i in 0..n {
                    s[i] = (self.dr_ptr().read_volatile() & 0xff) as u8;
                }
            }
        }
    }
}


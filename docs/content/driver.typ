#import "../components/prelude.typ": *

= 设备驱动模块

== 设备树解析

MinotaurOS 使用设备树（Device Tree）来描述硬件信息。设备树是一种描述硬件信息的数据结构，通常以 `.dts` 或 `.dtb` 文件的形式存在。设备树的结构是一个树状结构，每个节点表示一个硬件设备，节点之间通过属性和子节点进行关联。

在引导流程中，SBI 在完成硬件初始化后跳转到内核时，会将设备树的地址使用`a1`寄存器传递。MinotaurOS 在内核启动时，会解析设备树，根据设备树完成硬件识别。设备树解析的过程如下：

（1）解析`cpus`节点，获取时钟频率，CPU 核心个数和每个核心的信息；

（2）解析`memory`节点，获取内存的基地址和大小；

（3）解析`soc`节点，获取 SoC 的信息，包括串口、时钟、中断控制器等，并记录 MMIO 地址。

通过实现设备树解析功能，MinotaurOS 能够实现一次编译运行在不同的硬件平台上，而无需修改内核代码。

设备树描述的内存布局会保存到`GlobalMapping`结构中（如#[@lst:GlobalMapping结构]所示）。`GlobalMapping`记录了内存区域的物理地址、虚拟地址和大小，其中最重要的两个区域是物理内存和 virtio_mmio / sdcard_mmio：前者包含了内核镜像和用户页帧需要的内存，后者包含了磁盘设备的 MMIO 地址。

#code-figure(
  ```rs
  pub struct GlobalMapping {
      pub name: String,
      pub phys_start: PhysAddr,
      pub virt_start: VirtAddr,
      pub size: usize,
      pub perms: ASPerms,
  }
  ```,
  caption: [GlobalMapping 结构],
  label-name: "GlobalMapping结构",
)

#h(2em) 解析设备树之前，需要首先初始化堆分配器，保证`GlobalMapping`能够构造。在设备树解析完成后，会初始化用户页帧分配器，然后构造内核地址空间和页表。在此之后，会根据`GlobalMapping`记录的 MMIO 信息完成设备驱动的初始化。

MinotaurOS 使用`Device`结构表示一个硬件设备，如#[@lst:Device结构]所示。MinotaurOS 支持三种类型的设备：块设备、字符设备和网络设备。每种设备类型都有对应的接口。设备驱动程序需要实现对应的接口，并将设备注册到全局驱动表中。每种设备类型都提供了`metadata`方法，获取设备的元数据。设备元数据包含设备名和唯一的设备 ID，用于在设备表中查找设备。

#code-figure(
  ```rs
  #[derive(Clone)]
  pub enum Device {
      Block(Arc<dyn BlockDevice>),
      Character(Arc<dyn CharacterDevice>),
      Network(Arc<dyn NetworkDevice>),
  }

  pub struct DeviceMeta {
      pub dev_id: usize,
      pub dev_name: String,
  }
  ```,
  caption: [Device 结构],
  label-name: "Device结构",
)

== 块设备驱动

块设备驱动是 MinotaurOS 设备驱动的一种，用于访问块设备。块设备是一种随机访问设备，数据以块为单位进行读写。MinotaurOS 的块设备驱动接口定义如#[@lst:块设备接口]所示。块设备驱动需要实现`BlockDevice`接口，包括获取设备元数据、初始化、读取块数据和写入块数据四个方法。

#code-figure(
  ```rs
  pub trait BlockDevice: Send + Sync {
      /// 设备元数据
      fn metadata(&self) -> &DeviceMeta;

      /// MMIO 映射完成后初始化
      fn init(&self);

      /// 从块设备读取数据
      async fn read_block(&self, block_id: usize, buf: &mut [u8])
          -> SyscallResult;

      /// 向块设备写入数据
      async fn write_block(&self, block_id: usize, buf: &[u8])
          -> SyscallResult;
  }
  ```,
  caption: [块设备接口],
  label-name: "块设备接口",
)

=== VirtIO 驱动

MinotaurOS 使用 VirtIO 块设备驱动来访问 QEMU 模拟器的磁盘设备。VirtIO 是一种虚拟化设备标准，用于在虚拟机和宿主机之间传输数据。VirtIO 设备包括 VirtIO 网卡、VirtIO 块设备等。VirtIO 设备通过 MMIO 地址进行访问，MinotaurOS 使用 virtio-drivers 库来实现 VirtIO 设备的操作。但是，由于 virtio-drivers 库并没有实现 Rust 的 Async 支持，因此 MinotaurOS 采用自旋锁的方式来模拟异步读写，导致了一定程度的性能损失。

== 字符设备驱动

字符设备驱动是 MinotaurOS 设备驱动的一种，用于访问字符设备。字符设备是一种流设备，数据以字符为单位进行读写。MinotaurOS 的字符设备驱动接口定义如#[@lst:字符设备接口]所示。字符设备驱动需要实现`CharacterDevice`接口，包括获取设备元数据、读取字符和写入字符等方法。与块设备不同，字符设备的读写是串行的，没有块 ID 的概念。

#code-figure(
  ```rs
  pub trait CharacterDevice: Send + Sync {
      /// 设备元数据
      fn metadata(&self) -> &DeviceMeta;

      /// MMIO 映射完成后初始化
      fn init(&self);

      /// 是否有数据
      fn has_data(&self) -> bool;

      /// 注册唤醒器
      fn register_waker(&self, waker: Waker);

      /// 从字符设备读取数据
      async fn getchar(&self) -> SyscallResult<u8>;

      /// 向字符设备写入数据
      async fn putchar(&self, ch: u8) -> SyscallResult;
  }
  ```,
  caption: [字符设备接口],
  label-name: "字符设备接口",
)

=== TTY 驱动

TTY 通常用于描述一个文本输入/输出环境。在 UNIX 和 UNIX-like 系统（如 Linux）中，TTY 用来描述任何一种文本终端，无论它是物理设备还是虚拟设备。传统的 TTY 实现方式是使用 SBI 的 DBCN 扩展，但是直接使用 SBI 存在一定的局限性，例如无法实现 ppoll 系统调用和异步读写。因此，MinotaurOS 使用 ns16550a 兼容的 UART 驱动来实现 TTY，通过解析如#[@lst:serial-dts]所示的设备树串口结点，从对应的 MMIO 寄存器读写和处理外设中断来实现串口的输入和输出。

#code-figure(
  ```dts
   serial@10000000 {
  	 	interrupts = <0x0a>;
  	  interrupt-parent = <0x05>;
  	  clock-frequency = "\08@";
  	  reg = <0x00 0x10000000 0x00 0x100>;
  	  compatible = "ns16550a";
  };
  ```,
  caption: [serial dts],
  label-name: "serial-dts",
)

=== 零设备和空设备驱动

`/dev/zero` 是一个特殊的字符设备，用于提供无限的空数据流。读取 `/dev/zero` 会返回无限的 0 字节，写入 `/dev/zero` 则会被忽略。`/dev/null` 是一个特殊的字符设备，用于丢弃数据。读取 `/dev/null` 会返回空数据，写入 `/dev/null` 则会被忽略。

#pagebreak()

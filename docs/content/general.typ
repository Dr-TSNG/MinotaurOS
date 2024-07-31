= 内核整体设计

MinotaurOS 整体结构为宏内核，如#[@fig:系统架构]所示。在监督模式层面，硬件抽象层（HAL）负责与硬件交互，包括中断处理、CPU 核心管理、SBI 调用和设备驱动等。往下细分为 4 个模块，分别为块设备管理模块、字符设备管理模块、网络设备管理模块和虚拟内存管理模块，其中块设备管理器和字符设备管理器组成文件系统。MinotaurOS 将可执行块分为两大基本类，即用户线程和内核线程，两者在协程执行器的管理下统一调度。在用户模式层面，系统调用 Trap 回到内核态后，仍然在协程执行器的控制下。这样的设计使得 MinotaurOS 能够充分利用多核特性，实现内核异步模型。

#figure(
  image("img/系统架构.png", width: 80%),
  caption: [MinotaurOS 系统架构],
  supplement: [图],
)<系统架构>

#h(2em) 在硬件操作上，MinotaurOS 一部分使用 RISC-V 的标准 SBI 接口与运行在机器模式下的 OpenSBI 交互；一部分通过设备树信息直接操作 MMIO。MinotaurOS 通过 SBI 接口管理 CPU 核心的启动和暂停；通过设备树直接管理内存、磁盘、时钟和串口等硬件资源。

MinotaurOS 目前可以运行在 QEMU 虚拟机和 Vision Five 2 硬件平台，通过解析设备树实现一套二进制兼容不同硬件。MinotaurOS 支持了 108 个 Linux 系统调用，并且能够通过一系列测试用例，如#[@fig:pre-2024]。

#figure(
  image("img/pre-2024.png", width: 90%),
  caption: [运行 2024 oscomp 初赛测试用例],
  supplement: [图],
)<pre-2024>

#h(2em) 与此同时，MinotaurOS 还能够支持 iozone、lmbench 等 Linux 程序的运行。截至一阶段结束，MinotaurOS 取得了第三名的成绩，并且具有优秀的性能，如#[@fig:决赛一阶段成绩]所示。

#figure(
  image("img/决赛一阶段成绩.png", width: 90%),
  caption: [决赛一阶段成绩],
  supplement: [图],
)<决赛一阶段成绩>

#pagebreak()

# MinotaurOS

## 项目简介

MinotaurOS 是一个使用 Rust 语言编写的基于 RISC-V 架构的操作系统，目标是实现一个 Linux 兼容的多核操作系统，支持进程调度、文件系统、网络等功能。

## 环境搭建

+ Rust：nightly-2024-02-03
+ QEMU：7.0.0-9.0.0
+ RISC-V 工具链：riscv64-unknown-linux-gnu
+ 在 `prebuilts` 目录下放置磁盘文件 `disk.img` 和 bootloader 文件 `rustsbi-qemu.bin`

## 编译和运行

- 环境准备：`make env`
- 编译用户态二进制：`make user`
- 编译内核态二进制：`make kernel`
- 全部编译：`make all`
- 运行模拟器：`cargo task run`

## 目录架构

- kernel/src：内核代码
  - arch：架构相关代码
  - builtin：集成用户程序
  - debug：调试和日志模块
  - driver：设备驱动
  - fs：文件系统
  - mm：内存管理
  - net：网络模块
  - process：进程管理
  - processor：多核心管理
  - sched：调度和时钟模块
  - signal：信号处理模块
  - sync：锁和同步机制
  - syscall：系统调用处理函数
  - trap：中断和异常处理
  - main.rs：主程序
- user：用户程序
- prebuilts：预编译文件
- tasks：编译任务
- docs：项目文档

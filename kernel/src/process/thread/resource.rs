use core::cmp::max;
use core::time::Duration;
use crate::sched::time::cpu_time;

pub struct ResourceUsage {
    pub spawn_time: Duration,
    pub user_time: Duration,
    pub sys_time: Duration,
    pub last_sched_in_time: Duration,
    pub last_sched_out_time: Duration,
    pub last_trap_in_time: Duration,
    pub last_trap_out_time: Duration,
}

impl ResourceUsage {
    pub fn new() -> Self {
        let cpu_time = cpu_time();
        Self {
            spawn_time: cpu_time,
            user_time: Duration::ZERO,
            sys_time: Duration::ZERO,
            last_sched_in_time: cpu_time,
            last_sched_out_time: cpu_time,
            last_trap_in_time: Duration::ZERO,
            last_trap_out_time: Duration::ZERO,
        }
    }

    /// 调度进入
    pub fn sched_in(&mut self) {
        self.last_sched_in_time = cpu_time();
    }

    /// 调度离开
    pub fn sched_out(&mut self) {
        let cpu_time = cpu_time();
        self.sys_time += cpu_time - max(self.last_sched_in_time, self.last_trap_in_time);
        self.last_sched_out_time = cpu_time;
    }

    /// 进入内核态
    pub fn trap_in(&mut self) {
        let cpu_time = cpu_time();
        self.user_time += cpu_time - self.last_trap_out_time;
        self.last_trap_in_time = cpu_time;
    }

    /// 返回用户态
    pub fn trap_out(&mut self) {
        let cpu_time = cpu_time();
        self.sys_time += cpu_time - max(self.last_sched_in_time, self.last_trap_in_time);
        self.last_trap_out_time = cpu_time;
    }
}

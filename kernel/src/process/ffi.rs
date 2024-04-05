use bitflags::bitflags;

bitflags! {
    pub struct CloneFlags: u32 {
        const SIGCHLD = 17;
        const CLONE_VM = 1 << 8;
        const CLONE_FS = 1 << 9;
        const CLONE_FILES = 1 << 10;
        const CLONE_SIGHAND = 1 << 11;
        const CLONE_PIDFD = 1 << 12;
        const CLONE_PTRACE = 1 << 13;
        const CLONE_VFORK = 1 << 14;
        const CLONE_PARENT = 1 << 15;
        const CLONE_THREAD = 1 << 16;
        const CLONE_NEWNS = 1 << 17;
        const CLONE_SYSVSEM = 1 << 18;
        const CLONE_SETTLS = 1 << 19;
        const CLONE_PARENT_SETTID = 1 << 20;
        const CLONE_CHILD_CLEARTID = 1 << 21;
        const CLONE_DETACHED = 1 << 22;
        const CLONE_UNTRACED = 1 << 23;
        const CLONE_CHILD_SETTID = 1 << 24;
        const CLONE_NEWCGROUP = 1 << 25;
        const CLONE_NEWUTS = 1 << 26;
        const CLONE_NEWIPC = 1 << 27;
        const CLONE_NEWUSER = 1 << 28;
        const CLONE_NEWPID = 1 << 29;
        const CLONE_NEWNET = 1 << 30;
        const CLONE_IO = 1 << 31;
    }
}

bitflags! {
    pub struct WaitOptions: u32 {
        const WNOHANG = 1;
        const WUNTRACED = 1 << 1;
        const WCONTINUED = 1 << 3;
    }
}

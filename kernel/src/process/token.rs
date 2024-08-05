use crate::process::{Gid, Uid};

#[derive(Copy, Clone)]
pub struct AccessToken {
    pub uid: Uid,
    pub gid: Gid,
}

impl AccessToken {
    pub const fn root() -> Self {
        Self { uid: 0, gid: 0 }
    }

    pub fn new(uid: Uid, gid: Gid) -> Self {
        Self { uid, gid }
    }
}

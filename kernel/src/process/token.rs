use crate::process::Uid;

#[derive(Copy, Clone)]
pub struct AccessToken {
    pub uid: Uid,
    pub gid: Uid,
}

impl AccessToken {
    pub const fn root() -> Self {
        Self { uid: 0, gid: 0 }
    }

    pub fn new(uid: Uid, gid: Uid) -> Self {
        Self { uid, gid }
    }
}

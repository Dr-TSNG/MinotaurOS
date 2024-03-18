use bitflags::bitflags;
use crate::mm::addr_space::ASPerms;

bitflags! {
    pub struct MapFlags: u32 {
        const MAP_SHARED  = 0x01;
        const MAP_PRIVATE = 0x02;
        const MAP_FIXED   = 0x10;
    }
    
    pub struct MapProt: u32 {
        const PROT_READ  = 0x1;
        const PROT_WRITE = 0x2;
        const PROT_EXEC  = 0x4;
    }
}

impl From<MapProt> for ASPerms {
    fn from(prot: MapProt) -> Self {
        let mut perms = ASPerms::U;
        if prot.contains(MapProt::PROT_READ) {
            perms |= ASPerms::R;
        }
        if prot.contains(MapProt::PROT_WRITE) {
            perms |= ASPerms::W;
        }
        if prot.contains(MapProt::PROT_EXEC) {
            perms |= ASPerms::X;
        }
        perms
    }    
}

use alloc::{format, vec};
use alloc::string::String;
use alloc::vec::Vec;
use bitflags::bitflags;
use spin::Mutex;
use crate::kobject;
use crate::kobject::{KObject, KObjectType, KoID};
use crate::mm::page_table::PageTable;
use crate::mm::vmo::direct::VMObjectDirect;
use crate::result::MosResult;

bitflags! {
    pub struct ASPerms: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
    }
}

// static ASID_POOL: Mutex<WeakValueHashMap<ASID, AddressSpace>> = Mutex::default();

pub type ASID = u16;

pub struct AddressSpace {
    pub root_pt: PageTable,
    id: KoID,
    inner: Mutex<AddressSpaceInner>,
}

struct AddressSpaceInner {
    asid: ASID,
    pt_pages: Vec<VMObjectDirect>,
}

impl KObject for AddressSpace {
    fn id(&self) -> KoID {
        self.id
    }

    fn res_type(&self) -> KObjectType {
        KObjectType::AddressSpace
    }

    fn description(&self) -> String {
        format!("AddressSpace(root: {:?})", self.root_pt)
    }
}

impl AddressSpace {
    pub fn new() -> MosResult<AddressSpace> {
        let root_page = VMObjectDirect::new(ASPerms::R | ASPerms::W)?;
        let root_pt = PageTable::new(root_page.ppn);
        let inner = AddressSpaceInner::new(root_page);
        let addrs = AddressSpace {
            root_pt,
            id: kobject::new_koid(),
            inner: Mutex::new(inner),
        };
        Ok(addrs)
    }

    pub fn insert_pt(&mut self, obj: VMObjectDirect) {
        self.inner.lock().pt_pages.push(obj);
    }
}

impl AddressSpaceInner {
    fn new(root_page: VMObjectDirect) -> AddressSpaceInner {
        AddressSpaceInner {
            asid: 0,
            pt_pages: vec![root_page],
        }
    }
}

//! Test-only, single-threaded CPU backing model. Addresses are numbers, not host
//! mappings. A logical physical extent owns sparse 64 KiB pages; a view holds a
//! reference to that extent and translates guest addresses to physical offsets.
//! This specifies neither the console ABI nor host residency or GPU behavior.

use super::*;
use std::{cell::RefCell, rc::Rc};

const PAGE: u64 = PageMode::Large64KiB.bytes();
const REPLACEMENT: Metadata = Metadata {
    allocation_type: MEM_RESERVE | MEM_REPLACE_PLACEHOLDER | MEM_PHYSICAL | MEM_LARGE_PAGES,
    attributes: 0,
    protect: 4,
};

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Vm(VmError),
    PhysicalBounds,
    Unmapped,
}

// Cloning this handle extends the lifetime, not the physical contents.
#[derive(Clone)]
struct Physical(Rc<RefCell<Extent>>);

struct Extent {
    len: u64,
    pages: BTreeMap<u64, Box<[u8]>>,
}

impl Physical {
    fn new(len: u64) -> Self {
        assert!(len > 0 && len % PAGE == 0);
        Self(Rc::new(RefCell::new(Extent {
            len,
            pages: BTreeMap::new(),
        })))
    }
}

struct View {
    backing: Physical,
    offset: u64,
}

struct Cpu {
    vm: GuestVm,
    views: BTreeMap<u64, View>,
}

impl Cpu {
    fn new(vm: GuestVm) -> Self {
        Self {
            vm,
            views: BTreeMap::new(),
        }
    }

    fn map(&mut self, base: u64, len: u64, backing: &Physical, offset: u64) -> Result<(), Error> {
        if offset % PAGE != 0 {
            return Err(Error::Vm(VmError::Misaligned));
        }
        if !offset
            .checked_add(len)
            .is_some_and(|end| end <= backing.0.borrow().len)
        {
            return Err(Error::PhysicalBounds);
        }
        // The VM validates guest alignment, arithmetic, arena bounds and the
        // placeholder before changing anything. No backing page is allocated here.
        self.vm
            .allocate(Some(base), len, REPLACEMENT)
            .map_err(Error::Vm)?;
        self.views.insert(
            base,
            View {
                backing: backing.clone(),
                offset,
            },
        );
        Ok(())
    }

    fn unmap(&mut self, base: u64) -> Result<(), Error> {
        if !self.views.contains_key(&base) {
            return Err(Error::Unmapped);
        }
        self.vm.release(base).map_err(Error::Vm)?;
        self.views.remove(&base);
        Ok(())
    }

    fn translate(&self, address: u64) -> Result<(&Physical, u64, usize), Error> {
        let region = self.vm.region_at(address).ok_or(Error::Unmapped)?;
        let view = self.views.get(&region.range.start).ok_or(Error::Unmapped)?;
        // The containing interval and the physical range were checked by map.
        let physical = view.offset + (address - region.range.start);
        Ok((&view.backing, physical / PAGE, (physical % PAGE) as usize))
    }

    fn read(&self, address: u64) -> Result<u8, Error> {
        let (backing, page, byte) = self.translate(address)?;
        Ok(backing.0.borrow().pages.get(&page).map_or(0, |p| p[byte]))
    }

    fn write(&self, address: u64, value: u8) -> Result<(), Error> {
        let (backing, page, byte) = self.translate(address)?;
        let mut extent = backing.0.borrow_mut();
        let bytes = extent
            .pages
            .entry(page)
            .or_insert_with(|| vec![0; PAGE as usize].into_boxed_slice());
        bytes[byte] = value;
        Ok(())
    }
}

const A: u64 = 0x40_0000;
const B: u64 = A + 3 * PAGE;
const PLACEHOLDER: Metadata = Metadata {
    allocation_type: MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
    attributes: 0,
    protect: 1,
};

fn cpu() -> Cpu {
    let mut vm = GuestVm::new(A..B + 2 * PAGE).unwrap();
    vm.allocate(Some(A), B + 2 * PAGE - A, PLACEHOLDER).unwrap();
    Cpu::new(vm)
}

#[test]
fn offset_views_share_exactly_the_overlapping_page_and_allocate_on_write() {
    let mut cpu = cpu();
    let backing = Physical::new(16 * 1024 * 1024 * 1024);
    cpu.map(A, 2 * PAGE, &backing, 0).unwrap();
    cpu.map(B, 2 * PAGE, &backing, PAGE).unwrap();
    assert_eq!(cpu.vm.region_at(A).unwrap().page_mode, PageMode::Large64KiB);

    // A's second page is B's first page; reads never materialize absent pages.
    for addr in [A + PAGE - 1, A + PAGE, B, B + PAGE - 1, B + PAGE] {
        assert_eq!(cpu.read(addr), Ok(0));
    }
    assert!(backing.0.borrow().pages.is_empty());
    cpu.write(A + PAGE, 0x41).unwrap();
    assert_eq!(cpu.read(B), Ok(0x41));
    cpu.write(B + PAGE - 1, 0x42).unwrap();
    assert_eq!(cpu.read(A + 2 * PAGE - 1), Ok(0x42));
    assert_eq!(cpu.read(A + PAGE - 1), Ok(0));
    assert_eq!(cpu.read(B + PAGE), Ok(0));
    assert_eq!(backing.0.borrow().pages.len(), 1);

    cpu.write(A + PAGE - 1, 0x43).unwrap();
    cpu.write(B + PAGE, 0x44).unwrap();
    assert_eq!(cpu.read(B), Ok(0x41));
    assert_eq!(cpu.read(A + 2 * PAGE - 1), Ok(0x42));
    assert_eq!(cpu.read(A + PAGE - 1), Ok(0x43));
    assert_eq!(cpu.read(B + PAGE), Ok(0x44));
    assert_eq!(backing.0.borrow().pages.len(), 3);
}

#[test]
fn backing_outlives_views_or_owner_until_last_reference() {
    let mut cpu = cpu();
    let backing = Physical::new(PAGE);
    let lifetime = Rc::downgrade(&backing.0);
    cpu.map(A, PAGE, &backing, 0).unwrap();
    cpu.write(A, 0xA5).unwrap();
    cpu.unmap(A).unwrap();
    assert_eq!(cpu.read(A), Err(Error::Unmapped));
    assert!(cpu.vm.region_at(A).is_none()); // No placeholder restoration.

    // No mapped view remained, but the owner's handle kept the data alive.
    cpu.vm.allocate(Some(A), PAGE, PLACEHOLDER).unwrap();
    cpu.map(A, PAGE, &backing, 0).unwrap();
    cpu.map(B, PAGE, &backing, 0).unwrap();
    assert_eq!(cpu.read(A), Ok(0xA5));
    drop(backing);
    cpu.unmap(B).unwrap();
    assert_eq!(cpu.write(B, 0), Err(Error::Unmapped));
    assert_eq!(cpu.read(A), Ok(0xA5));
    cpu.write(A, 0x5A).unwrap();
    assert!(lifetime.upgrade().is_some());
    cpu.unmap(A).unwrap();
    assert!(lifetime.upgrade().is_none());
}

#[test]
fn invalid_ranges_and_non_base_unmaps_leave_state_unchanged() {
    let mut cpu = cpu();
    let backing = Physical::new(2 * PAGE);
    cpu.map(A, PAGE, &backing, 0).unwrap();
    let vm = cpu.vm.clone();
    for (base, len, offset, error) in [
        (B, 0, 0, Error::Vm(VmError::EmptyRange)),
        (B, PAGE, 1, Error::Vm(VmError::Misaligned)),
        (B + 1, PAGE, 0, Error::Vm(VmError::Misaligned)),
        (B, PAGE - 1, 0, Error::Vm(VmError::Misaligned)),
        (B, 2 * PAGE, PAGE, Error::PhysicalBounds),
        (B, PAGE, u64::MAX & !(PAGE - 1), Error::PhysicalBounds),
        (B + PAGE, 2 * PAGE, 0, Error::Vm(VmError::OutsideArena)),
        (A, PAGE, 0, Error::Vm(VmError::NotPlaceholder)),
    ] {
        assert_eq!(cpu.map(base, len, &backing, offset), Err(error));
        assert_eq!(cpu.vm, vm);
        assert_eq!(cpu.views.len(), 1);
    }
    assert_eq!(cpu.unmap(A + 1), Err(Error::Unmapped));
    assert_eq!(cpu.unmap(B), Err(Error::Unmapped));
    for addr in [A - 1, A + PAGE, B, B + 2 * PAGE, u64::MAX] {
        assert_eq!(cpu.read(addr), Err(Error::Unmapped));
        assert_eq!(cpu.write(addr, 0xFF), Err(Error::Unmapped));
    }
    assert!(backing.0.borrow().pages.is_empty());
    assert_eq!(cpu.vm, vm);
    assert_eq!(cpu.views.len(), 1);
    assert_eq!(cpu.read(A + PAGE - 1), Ok(0));
}

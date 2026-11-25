//! Owned device identity and IUnknown bookkeeping. No import or GPU provider.

use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

pub const IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
/// IID requested by the observed Scarlett creation caller, in Win64 byte order.
/// Its desktop UUID name does not import the desktop vtable or semantics.
pub const OBSERVED_DEVICE_IID: [u8; 16] = [
    0x44, 0xc3, 0x05, 0x54, 0x57, 0xd4, 0x44, 0x44, 0xb4, 0xdd, 0x23, 0x66, 0xe4, 0x5a, 0xee, 0x39,
];

/// Measured caller-initialized prefix, not a validated parameter layout or size.
pub const OBSERVED_INITIALIZED_PREFIX: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceId(NonZeroU64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedAdapter,
    UnsupportedInterface,
    UnsupportedParameters,
    BackendUnavailable,
    Capacity,
    UnknownDevice,
    ReferenceOverflow,
}

struct Device<B> {
    backend: B,
    creation_prefix: [u8; OBSERVED_INITIALIZED_PREFIX],
    references: u32,
}

/// A bounded host-side ledger. Its IDs are not guest pointers/COM addresses.
/// Use external synchronization if dispatching concurrently. Guest-facing ABI
/// and writable/readable memory checks must be implemented at another boundary.
pub struct OwnedDevices<B = ()> {
    devices: BTreeMap<DeviceId, Device<B>>,
    capacity: usize,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl<B> OwnedDevices<B> {
    pub fn new(capacity: usize) -> Self {
        Self {
            devices: BTreeMap::new(),
            capacity,
        }
    }

    /// Construct an owned object only. Snapshot bytes are stored opaquely and
    /// do not authorize a retail call or establish VM/GPU creation success.
    pub fn create_with_backend(
        &mut self,
        has_adapter: bool,
        iid: [u8; 16],
        creation_prefix: [u8; OBSERVED_INITIALIZED_PREFIX],
        allowed_prefix: &[u8; OBSERVED_INITIALIZED_PREFIX],
        make_backend: impl FnOnce() -> Option<B>,
    ) -> Result<DeviceId, Error> {
        if has_adapter {
            return Err(Error::UnsupportedAdapter);
        }
        if iid != OBSERVED_DEVICE_IID {
            return Err(Error::UnsupportedInterface);
        }
        if &creation_prefix != allowed_prefix {
            return Err(Error::UnsupportedParameters);
        }
        if self.devices.len() >= self.capacity {
            return Err(Error::Capacity);
        }
        let backend = make_backend().ok_or(Error::BackendUnavailable)?;
        let next = NEXT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::Capacity)?;
        let id = DeviceId(NonZeroU64::new(next).expect("IDs start at one and do not wrap"));
        self.devices.insert(
            id,
            Device {
                backend,
                creation_prefix,
                references: 1,
            },
        );
        Ok(id)
    }

    /// Borrow the retained backend only while the device lifetime is live.
    pub fn backend(&self, id: DeviceId) -> Result<&B, Error> {
        Ok(&self.devices.get(&id).ok_or(Error::UnknownDevice)?.backend)
    }

    pub fn creation_prefix(
        &self,
        id: DeviceId,
    ) -> Result<&[u8; OBSERVED_INITIALIZED_PREFIX], Error> {
        Ok(&self
            .devices
            .get(&id)
            .ok_or(Error::UnknownDevice)?
            .creation_prefix)
    }

    pub fn query(&mut self, id: DeviceId, iid: [u8; 16]) -> Result<DeviceId, Error> {
        let device = self.devices.get_mut(&id).ok_or(Error::UnknownDevice)?;
        if !matches!(iid, IUNKNOWN | OBSERVED_DEVICE_IID) {
            return Err(Error::UnsupportedInterface);
        }
        Self::retain(device)?;
        Ok(id)
    }

    fn retain(device: &mut Device<B>) -> Result<u32, Error> {
        device.references = device
            .references
            .checked_add(1)
            .ok_or(Error::ReferenceOverflow)?;
        Ok(device.references)
    }

    pub fn add_ref(&mut self, id: DeviceId) -> Result<u32, Error> {
        Self::retain(self.devices.get_mut(&id).ok_or(Error::UnknownDevice)?)
    }

    pub fn release(&mut self, id: DeviceId) -> Result<u32, Error> {
        let device = self.devices.get_mut(&id).ok_or(Error::UnknownDevice)?;
        device.references -= 1;
        let remaining = device.references;
        if remaining == 0 {
            self.devices.remove(&id);
        }
        Ok(remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl OwnedDevices<()> {
        fn create(
            &mut self,
            adapter: bool,
            iid: [u8; 16],
            bytes: [u8; 80],
        ) -> Result<DeviceId, Error> {
            self.create_with_backend(adapter, iid, bytes, &bytes, || Some(()))
        }
    }

    #[test]
    fn exhaustion_cannot_wrap_references_or_resurrect_an_identity() {
        let mut ledger = OwnedDevices::new(1);
        let id = ledger.create(false, OBSERVED_DEVICE_IID, [1; 80]).unwrap();
        ledger.devices.get_mut(&id).unwrap().references = u32::MAX;
        assert_eq!(ledger.add_ref(id), Err(Error::ReferenceOverflow));
        assert_eq!(ledger.query(id, IUNKNOWN), Err(Error::ReferenceOverflow));
        assert_eq!(ledger.release(id), Ok(u32::MAX - 1));
        ledger.devices.get_mut(&id).unwrap().references = 1;
        assert_eq!(ledger.release(id), Ok(0));
        assert_eq!(ledger.release(id), Err(Error::UnknownDevice));
        let new = ledger.create(false, OBSERVED_DEVICE_IID, [2; 80]).unwrap();
        assert_ne!(id, new);
        assert_eq!(ledger.creation_prefix(id), Err(Error::UnknownDevice));
    }

    #[test]
    fn identities_are_ledger_local_and_failures_do_not_consume_capacity() {
        let mut a = OwnedDevices::new(1);
        let mut b = OwnedDevices::new(1);
        assert_eq!(
            a.create(true, OBSERVED_DEVICE_IID, [0; 80]),
            Err(Error::UnsupportedAdapter)
        );
        assert_eq!(
            a.create(false, IUNKNOWN, [0; 80]),
            Err(Error::UnsupportedInterface)
        );
        let id = a.create(false, OBSERVED_DEVICE_IID, [41; 80]).unwrap();
        let other = b.create(false, OBSERVED_DEVICE_IID, [41; 80]).unwrap();
        assert_eq!(
            a.create(false, OBSERVED_DEVICE_IID, [0; 80]),
            Err(Error::Capacity)
        );
        assert_eq!(b.release(id), Err(Error::UnknownDevice));
        assert_eq!(a.query(id, [0; 16]), Err(Error::UnsupportedInterface));
        assert_eq!(a.creation_prefix(id), Ok(&[41; 80]));
        assert_eq!(a.query(id, IUNKNOWN), Ok(id));
        assert_eq!(a.release(id), Ok(1));
        assert_eq!(a.release(id), Ok(0));
        assert_eq!(b.release(other), Ok(0));
    }
}

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

/// Deliberately synthetic, never a retail device creation configuration.
pub const OWNED_FIXTURE_PREFIX: [u8; OBSERVED_INITIALIZED_PREFIX] =
    [0x5a; OBSERVED_INITIALIZED_PREFIX];

const fn scarlett_recognition_prefix() -> [u8; OBSERVED_INITIALIZED_PREFIX] {
    let mut prefix = [0; OBSERVED_INITIALIZED_PREFIX];
    // Measured LE dwords: +00 0x20004, +08 0x100000, +20/+24/+28 1, +3c 0x20.
    prefix[0x00] = 4;
    prefix[0x02] = 2;
    prefix[0x0a] = 0x10;
    prefix[0x20] = 1;
    prefix[0x24] = 1;
    prefix[0x28] = 1;
    prefix[0x3c] = 0x20;
    prefix
}
const SCARLETT_RECOGNITION_PREFIX: [u8; OBSERVED_INITIALIZED_PREFIX] =
    scarlett_recognition_prefix();

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceId(NonZeroU64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedAdapter,
    UnsupportedInterface,
    UnsupportedParameters,
    RecognizedUnsupportedCreationEffects,
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

/// Tentatively owns the initial reference. Dropping before commit revokes the
/// identity and drops the backend, including on unwind. No access to the
/// ledger while this guard is live. Only publish to a caller at commit time;
/// rollback does not undo external writes or revoke escaped host handles.
#[must_use]
pub struct PendingDevice<'a, B> {
    devices: &'a mut OwnedDevices<B>,
    id: DeviceId,
    committed: bool,
}

impl<B> PendingDevice<'_, B> {
    pub fn commit(mut self) -> DeviceId {
        self.committed = true;
        self.id
    }
}

impl<B> Drop for PendingDevice<'_, B> {
    fn drop(&mut self) {
        if !self.committed {
            self.devices.devices.remove(&self.id);
        }
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl<B> OwnedDevices<B> {
    pub fn new(capacity: usize) -> Self {
        Self {
            devices: BTreeMap::new(),
            capacity,
        }
    }

    /// Stage only the synthetic owned profile. A recognized retail byte
    /// span never authorizes a factory call; the span has no layout contract.
    pub fn stage_owned(
        &mut self,
        has_adapter: bool,
        iid: [u8; 16],
        creation_prefix: [u8; OBSERVED_INITIALIZED_PREFIX],
        make_backend: impl FnOnce() -> Option<B>,
    ) -> Result<PendingDevice<'_, B>, Error> {
        if has_adapter {
            return Err(Error::UnsupportedAdapter);
        }
        if iid != OBSERVED_DEVICE_IID {
            return Err(Error::UnsupportedInterface);
        }
        if creation_prefix == SCARLETT_RECOGNITION_PREFIX {
            return Err(Error::RecognizedUnsupportedCreationEffects);
        }
        if creation_prefix != OWNED_FIXTURE_PREFIX {
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
        Ok(PendingDevice {
            devices: self,
            id,
            committed: false,
        })
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
            self.stage_owned(adapter, iid, bytes, || Some(()))
                .map(PendingDevice::commit)
        }
    }

    #[test]
    fn recognition_and_all_single_byte_mutations_refuse_before_factory() {
        let mut ledger = OwnedDevices::<()>::new(1);
        assert_eq!(
            ledger
                .stage_owned(
                    false,
                    OBSERVED_DEVICE_IID,
                    SCARLETT_RECOGNITION_PREFIX,
                    || panic!("must not run factory")
                )
                .err(),
            Some(Error::RecognizedUnsupportedCreationEffects)
        );
        for profile in [SCARLETT_RECOGNITION_PREFIX, OWNED_FIXTURE_PREFIX] {
            for i in 0..profile.len() {
                let mut mutated = profile;
                mutated[i] ^= 1;
                assert_eq!(
                    ledger
                        .stage_owned(false, OBSERVED_DEVICE_IID, mutated, || panic!(
                            "must not run factory"
                        ))
                        .err(),
                    Some(Error::UnsupportedParameters)
                );
            }
        }
        assert!(ledger.devices.is_empty());
    }

    #[test]
    fn dropped_or_unwound_stage_revokes_identity_and_releases_backend_once() {
        use std::{
            cell::Cell,
            panic::{AssertUnwindSafe, catch_unwind},
        };
        struct Tracked<'a>(&'a Cell<usize>);
        impl Drop for Tracked<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let mut ledger = OwnedDevices::new(1);
        assert_eq!(
            ledger
                .stage_owned(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX, || None)
                .err(),
            Some(Error::BackendUnavailable)
        );
        let pending = ledger
            .stage_owned(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX, || {
                Some(Tracked(&drops))
            })
            .unwrap();
        let revoked = pending.id;
        drop(pending);
        assert_eq!(drops.get(), 1);
        assert!(matches!(ledger.backend(revoked), Err(Error::UnknownDevice)));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _pending = ledger
                    .stage_owned(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX, || {
                        Some(Tracked(&drops))
                    })
                    .unwrap();
                panic!("synthetic publication panic");
            }))
            .is_err()
        );
        assert_eq!(drops.get(), 2);
        let live = ledger
            .stage_owned(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX, || {
                Some(Tracked(&drops))
            })
            .unwrap()
            .commit();
        assert_ne!(revoked, live);
        assert_eq!(
            ledger
                .stage_owned(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX, || panic!(
                    "full ledger ran factory"
                ))
                .err(),
            Some(Error::Capacity)
        );
        assert_eq!(ledger.release(live), Ok(0));
        assert_eq!(drops.get(), 3);
        assert_eq!(ledger.release(live), Err(Error::UnknownDevice));
    }

    #[test]
    fn exhaustion_cannot_wrap_references_or_resurrect_an_identity() {
        let mut ledger = OwnedDevices::new(1);
        let id = ledger
            .create(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX)
            .unwrap();
        ledger.devices.get_mut(&id).unwrap().references = u32::MAX;
        assert_eq!(ledger.add_ref(id), Err(Error::ReferenceOverflow));
        assert_eq!(ledger.query(id, IUNKNOWN), Err(Error::ReferenceOverflow));
        assert_eq!(ledger.release(id), Ok(u32::MAX - 1));
        ledger.devices.get_mut(&id).unwrap().references = 1;
        assert_eq!(ledger.release(id), Ok(0));
        assert_eq!(ledger.release(id), Err(Error::UnknownDevice));
        let new = ledger
            .create(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX)
            .unwrap();
        assert_ne!(id, new);
        assert_eq!(ledger.creation_prefix(id), Err(Error::UnknownDevice));
    }

    #[test]
    fn identities_are_ledger_local_and_failures_do_not_consume_capacity() {
        let mut a = OwnedDevices::new(1);
        let mut b = OwnedDevices::new(1);
        assert_eq!(
            a.create(true, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX),
            Err(Error::UnsupportedAdapter)
        );
        assert_eq!(
            a.create(false, IUNKNOWN, OWNED_FIXTURE_PREFIX),
            Err(Error::UnsupportedInterface)
        );
        let id = a
            .create(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX)
            .unwrap();
        let other = b
            .create(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX)
            .unwrap();
        assert_eq!(
            a.create(false, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX),
            Err(Error::Capacity)
        );
        assert_eq!(b.release(id), Err(Error::UnknownDevice));
        assert_eq!(a.query(id, [0; 16]), Err(Error::UnsupportedInterface));
        assert_eq!(a.creation_prefix(id), Ok(&OWNED_FIXTURE_PREFIX));
        assert_eq!(a.query(id, IUNKNOWN), Ok(id));
        assert_eq!(a.release(id), Ok(1));
        assert_eq!(a.release(id), Ok(0));
        assert_eq!(b.release(other), Ok(0));
    }
}

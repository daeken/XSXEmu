//! Executable-backed RPF9 algorithm 0x10. No title data is built into the library.
use std::io::{Read, Seek, SeekFrom};

use super::rpf9::{Error, Result};

// Raw PE file offsets for the supported Scarlett layout, not virtual addresses.
const TABLES: u64 = 0x6035d30;
const REGISTRY: u64 = 0x66e4700;
const IV: u64 = 0x62fc270;
const BLOB_SIZE: usize = 0x10f4;

pub(crate) fn read_at<R: Read + Seek>(r: &mut R, at: u64, buf: &mut [u8]) -> Result<()> {
    r.seek(SeekFrom::Start(at))?;
    r.read_exact(buf)?;
    Ok(())
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

pub struct ScarlettContext {
    input: Box<[u8; 4096]>,
    rounds: Box<[u8; 16384]>,
    registry: [(u64, u64, u64); 24],
    initial_iv: [u8; 16],
}

impl ScarlettContext {
    pub(crate) fn load<R: Read + Seek>(exe: &mut R) -> Result<Self> {
        let mut result = Self {
            input: Box::new([0; 4096]),
            rounds: Box::new([0; 16384]),
            registry: [(0, 0, 0); 24],
            initial_iv: [0; 16],
        };
        read_at(exe, TABLES, result.input.as_mut())?;
        read_at(exe, TABLES + 4096, result.rounds.as_mut())?;
        read_at(exe, IV, &mut result.initial_iv)?;
        let mut raw = [0; 24 * 24];
        read_at(exe, REGISTRY, &mut raw)?;
        for (slot, record) in result.registry.iter_mut().zip(raw.chunks_exact(24)) {
            let q = |n| u64::from_le_bytes(record[n..n + 8].try_into().unwrap());
            *slot = (q(0), q(8), q(16));
        }
        Ok(result)
    }

    pub(crate) fn initial<R: Read + Seek>(&self, exe: &mut R) -> Result<Cipher<'_>> {
        self.cipher(exe, 0x1000_0001, self.initial_iv)
    }

    pub(crate) fn cipher<R: Read + Seek>(
        &self,
        exe: &mut R,
        id: u32,
        iv: [u8; 16],
    ) -> Result<Cipher<'_>> {
        let handle = u64::from(id) << 32 | 0x0200_0000;
        let (_, va, size) = self
            .registry
            .iter()
            .copied()
            .find(|x| x.0 == handle)
            .ok_or(Error::Unsupported(
                "algorithm 0x10 context not in executable",
            ))?;
        if size != BLOB_SIZE as u64 {
            return Err(Error::Invalid("unexpected executable context size"));
        }
        // Accept pointers only to the contiguous context records in this layout.
        let rva = va
            .checked_sub(0x140000000)
            .ok_or(Error::Invalid("context VA"))?;
        if !(0x66e5b40..=0x66ef460).contains(&rva) || rva % 16 != 0 {
            return Err(Error::Invalid("context outside executable table"));
        }
        let mut blob = Box::new([0; BLOB_SIZE]);
        read_at(exe, rva - 0x1200, blob.as_mut())?;
        if word(&blob[..4]) != 0x4e3b9b8e {
            return Err(Error::Invalid("executable context tag"));
        }
        Ok(Cipher {
            tables: self,
            blob,
            iv,
        })
    }
}

pub(crate) struct Cipher<'a> {
    tables: &'a ScarlettContext,
    blob: Box<[u8; BLOB_SIZE]>,
    iv: [u8; 16],
}

impl Cipher<'_> {
    fn block(&self, input: [u8; 16]) -> [u8; 16] {
        // Positions after inverse row rotation. Bytes are numbered column-major.
        const ROWS: [[usize; 4]; 4] =
            [[0, 13, 10, 7], [4, 1, 14, 11], [8, 5, 2, 15], [12, 9, 6, 3]];
        let round_word = |round: usize, col: usize| {
            let at = 4 + 16 * round + 4 * col;
            word(&self.blob[at..at + 4])
        };
        let mut state = [0; 16];
        for col in 0..4 {
            let at = col * 4;
            let input_word = std::array::from_fn(|r| {
                let i = at + r;
                self.tables.input[i * 256 + usize::from(input[i])]
            });
            state[at..at + 4].copy_from_slice(
                &(u32::from_be_bytes(input_word) ^ round_word(0, col)).to_be_bytes(),
            );
        }
        for round in 1..14 {
            let previous = state;
            for (col, positions) in ROWS.iter().enumerate() {
                let mut mixed = round_word(round, col);
                for &pos in positions {
                    let i = 4 * (pos * 256 + usize::from(previous[pos]));
                    mixed ^= word(&self.tables.rounds[i..i + 4]);
                }
                state[col * 4..col * 4 + 4].copy_from_slice(&mixed.to_be_bytes());
            }
        }
        std::array::from_fn(|i| self.blob[244 + 256 * i + usize::from(state[ROWS[i / 4][i % 4]])])
    }

    // Each call starts a fresh CBC stream. Chaining spans pass the same `previous`.
    pub(crate) fn initial_block(&self) -> [u8; 16] {
        self.iv
    }

    pub(crate) fn decrypt(&self, bytes: &mut [u8], previous: &mut [u8; 16]) -> Result<()> {
        if bytes.len() % 16 != 0 {
            return Err(Error::Invalid("encrypted RPF9 span is not block-aligned"));
        }
        for block in bytes.chunks_exact_mut(16) {
            let encrypted = <[u8; 16]>::try_from(&*block).unwrap();
            let decoded = self.block(encrypted);
            for i in 0..16 {
                block[i] = decoded[i] ^ previous[i];
            }
            *previous = encrypted;
        }
        Ok(())
    }
}

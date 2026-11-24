//! DXBC retail digest: MD5 compression (RFC 1321) with a distinct final
//! block layout. References: Microsoft DXC `ComputeHashRetail` and
//! vkd3d-proton `vkd3d_compute_dxbc_checksum` (see fixture provenance).

pub(super) fn retail(payload: &[u8]) -> [u8; 16] {
    let mut state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let blocks = payload.chunks_exact(64);
    let rest = blocks.remainder();
    for block in blocks {
        compress(&mut state, block.try_into().unwrap());
    }
    let mut last = [0; 64];
    if rest.len() >= 56 {
        last[..rest.len()].copy_from_slice(rest);
        last[rest.len()] = 0x80;
        compress(&mut state, &last);
        last.fill(0);
    } else {
        last[4..4 + rest.len()].copy_from_slice(rest);
        last[4 + rest.len()] = 0x80;
    }
    let length = payload.len() as u32;
    last[..4].copy_from_slice(&(length << 3).to_le_bytes());
    last[60..].copy_from_slice(&((length << 1) | 1).to_le_bytes());
    compress(&mut state, &last);
    let mut result = [0; 16];
    for (slot, word) in result.chunks_exact_mut(4).zip(state) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    result
}

fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    const SHIFTS: [[u32; 4]; 4] = [
        [7, 12, 17, 22],
        [5, 9, 14, 20],
        [4, 11, 16, 23],
        [6, 10, 15, 21],
    ];
    // floor(2^32 * abs(sin(i + 1))) for round i (zero indexed).
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];
    let mut words = [0; 16];
    for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for (i, k) in K.into_iter().enumerate() {
        let round = i / 16;
        let (f, g) = match round {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let next_b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(k)
                .wrapping_add(words[g])
                .rotate_left(SHIFTS[round][i % 4]),
        );
        [a, b, c, d] = [d, next_b, b, c];
    }
    for (slot, word) in state.iter_mut().zip([a, b, c, d]) {
        *slot = slot.wrapping_add(word);
    }
}

//! Bounded D3D12 root signature 1.1 serialization. The wire format is
//! desktop DXBC/RTS0, not a claim about the Xbox graphics contract.

mod checksum;
#[cfg(target_arch = "x86_64")]
pub mod win64;

pub const VERSION_1_1: u32 = 2;
pub const MAX_PARAMETERS: usize = 64;
pub const MAX_DESCRIPTOR_RANGES: usize = 1024;
pub const MAX_STATIC_SAMPLERS: usize = 2032;

#[derive(Clone, Copy, Debug)]
pub struct RootSignature<'a> {
    pub flags: u32,
    pub parameters: &'a [Parameter<'a>],
    pub samplers: &'a [StaticSampler],
}

#[derive(Clone, Copy, Debug)]
pub struct Parameter<'a> {
    pub visibility: u32,
    pub kind: ParameterKind<'a>,
}

#[derive(Clone, Copy, Debug)]
pub enum ParameterKind<'a> {
    Table(&'a [DescriptorRange]),
    Constants {
        register: u32,
        space: u32,
        count: u32,
    },
    Descriptor {
        kind: DescriptorKind,
        register: u32,
        space: u32,
        flags: u32,
    },
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum DescriptorKind {
    Cbv = 2,
    Srv = 3,
    Uav = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DescriptorRange {
    pub kind: u32,
    pub count: u32,
    pub register: u32,
    pub space: u32,
    pub flags: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StaticSampler {
    pub filter: u32,
    pub address_u: u32,
    pub address_v: u32,
    pub address_w: u32,
    pub mip_lod_bias: f32,
    pub max_anisotropy: u32,
    pub comparison_func: u32,
    pub border_color: u32,
    pub min_lod: f32,
    pub max_lod: f32,
    pub register: u32,
    pub space: u32,
    pub visibility: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Limit(&'static str),
    OutOfMemory,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) | Self::Limit(reason) => f.write_str(reason),
            Self::OutOfMemory => f.write_str("root signature allocation failed"),
        }
    }
}

impl std::error::Error for Error {}

struct Binding {
    kind: u32,
    space: u32,
    visibility: u32,
    start: u32,
    end: u32, // inclusive
}

fn bind(
    bindings: &mut Vec<Binding>,
    kind: u32,
    space: u32,
    visibility: u32,
    start: u32,
    count: u32,
) -> Result<(), Error> {
    if space >= 0xffff_fff0 {
        return Err(Error::Invalid("reserved shader register space"));
    }
    let end = if count == u32::MAX {
        u32::MAX
    } else {
        start
            .checked_add(count - 1)
            .ok_or(Error::Invalid("shader register range overflow"))?
    };
    if bindings.iter().any(|b| {
        b.kind == kind
            && b.space == space
            && (visibility == 0 || b.visibility == 0 || b.visibility == visibility)
            && b.start <= end
            && start <= b.end
    }) {
        return Err(Error::Invalid("overlapping shader register bindings"));
    }
    bindings.push(Binding {
        kind,
        space,
        visibility,
        start,
        end,
    });
    Ok(())
}

fn validate(desc: &RootSignature<'_>) -> Result<usize, Error> {
    if desc.parameters.len() > MAX_PARAMETERS || desc.samplers.len() > MAX_STATIC_SAMPLERS {
        return Err(Error::Limit("too many root parameters or static samplers"));
    }
    if desc.flags & !0xfff != 0 || (desc.flags & 0x80 != 0 && desc.flags != 0x80) {
        return Err(Error::Invalid("invalid root signature flags"));
    }
    let mut range_count = 0;
    for p in desc.parameters {
        if let ParameterKind::Table(ranges) = p.kind {
            if ranges.len() > MAX_DESCRIPTOR_RANGES - range_count {
                return Err(Error::Limit("too many descriptor ranges"));
            }
            range_count += ranges.len();
        }
    }
    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(desc.parameters.len() + range_count + desc.samplers.len())
        .map_err(|_| Error::OutOfMemory)?;
    let mut dwords = 6 + 3 * desc.parameters.len() + 13 * desc.samplers.len();
    let mut cost = 0u32;
    for p in desc.parameters {
        if p.visibility > 7 {
            return Err(Error::Invalid("invalid shader visibility"));
        }
        let parameter_cost = match p.kind {
            ParameterKind::Table(ranges) => {
                dwords += 2 + 6 * ranges.len();
                let mut append_at = 0u64;
                for r in ranges {
                    if r.kind > 3 || r.count == 0 || (r.kind == 3) != (ranges[0].kind == 3) {
                        return Err(Error::Invalid(
                            "invalid descriptor range or mixed sampler/resource table",
                        ));
                    }
                    let data_flags = r.flags & 0xe;
                    if r.flags & !0x1000f != 0
                        || data_flags.count_ones() > 1
                        || (r.kind == 3 && r.flags & !1 != 0)
                        || (r.flags & 1 != 0 && r.flags & 0x10008 != 0)
                    {
                        return Err(Error::Invalid("invalid descriptor range flags"));
                    }
                    let start = if r.offset == u32::MAX {
                        append_at
                    } else {
                        u64::from(r.offset)
                    };
                    let end = if r.count == u32::MAX {
                        1u64 << 32
                    } else {
                        start + u64::from(r.count)
                    };
                    if start > u64::from(u32::MAX) || end > (1u64 << 32) {
                        return Err(Error::Invalid("descriptor table offset overflow"));
                    }
                    append_at = end;
                    bind(
                        &mut bindings,
                        r.kind,
                        r.space,
                        p.visibility,
                        r.register,
                        r.count,
                    )?;
                }
                1
            }
            ParameterKind::Constants {
                register,
                space,
                count,
            } => {
                if count == 0 {
                    return Err(Error::Invalid("empty root constants"));
                }
                dwords += 3;
                bind(&mut bindings, 2, space, p.visibility, register, 1)?;
                count
            }
            ParameterKind::Descriptor {
                kind,
                register,
                space,
                flags,
            } => {
                if flags & !0xe != 0 || flags.count_ones() > 1 {
                    return Err(Error::Invalid("invalid root descriptor flags"));
                }
                dwords += 3;
                let range_kind = match kind {
                    DescriptorKind::Cbv => 2,
                    DescriptorKind::Srv => 0,
                    DescriptorKind::Uav => 1,
                };
                bind(&mut bindings, range_kind, space, p.visibility, register, 1)?;
                2
            }
        };
        cost = cost.saturating_add(parameter_cost);
        if cost > 64 {
            return Err(Error::Limit("root parameter cost exceeds 64 DWORDs"));
        }
    }
    for s in desc.samplers {
        let filter = s.filter & !0x180;
        if s.visibility > 7
            || s.border_color > 4
            || !(filter == 0x55 || filter & !0x15 == 0)
            || ![s.address_u, s.address_v, s.address_w]
                .iter()
                .all(|a| (1..=5).contains(a))
            || !(-16.0..=15.99).contains(&s.mip_lod_bias)
            || s.max_anisotropy > 16
            || (s.filter & 0x180 == 0x80 && !(1..=8).contains(&s.comparison_func))
            || s.min_lod.is_nan()
            || s.max_lod.is_nan()
        {
            return Err(Error::Invalid("invalid static sampler"));
        }
        bind(&mut bindings, 3, s.space, s.visibility, s.register, 1)?;
    }
    Ok(dwords)
}

/// Serialize a bounded 1.1 definition to a checksummed, single-chunk DXBC.
/// This does not validate a device's capabilities or a particular shader/PSO.
pub fn serialize_1_1(desc: &RootSignature<'_>) -> Result<Vec<u8>, Error> {
    // Microsoft DXC's DxilRootSignatureSerializer and vkd3d-proton's dxbc.c
    // describe this layout. Wire offsets are relative to the RTS0 payload.
    const PAYLOAD: usize = 44;
    fn write(bytes: &mut Vec<u8>, words: &[u32]) {
        for word in words {
            bytes.extend(word.to_le_bytes());
        }
    }
    fn set(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    let payload_size = 4 * validate(desc)?;
    let size = PAYLOAD + payload_size;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::OutOfMemory)?;
    bytes.extend(b"DXBC");
    bytes.resize(20, 0); // retail checksum, filled last
    write(&mut bytes, &[1, size as u32, 1, 36]);
    bytes.extend(b"RTS0");
    write(&mut bytes, &[payload_size as u32]);
    write(
        &mut bytes,
        &[
            VERSION_1_1,
            desc.parameters.len() as u32,
            24,
            desc.samplers.len() as u32,
            0,
            desc.flags,
        ],
    );
    let parameter_headers = bytes.len();
    bytes.resize(parameter_headers + 12 * desc.parameters.len(), 0);
    for (i, p) in desc.parameters.iter().enumerate() {
        let header = parameter_headers + 12 * i;
        let offset = (bytes.len() - PAYLOAD) as u32;
        set(&mut bytes, header + 4, p.visibility);
        set(&mut bytes, header + 8, offset);
        let tag = match p.kind {
            ParameterKind::Table(ranges) => {
                write(&mut bytes, &[ranges.len() as u32, offset + 8]);
                for r in ranges {
                    write(
                        &mut bytes,
                        &[r.kind, r.count, r.register, r.space, r.flags, r.offset],
                    );
                }
                0
            }
            ParameterKind::Constants {
                register,
                space,
                count,
            } => {
                write(&mut bytes, &[register, space, count]);
                1
            }
            ParameterKind::Descriptor {
                kind,
                register,
                space,
                flags,
            } => {
                write(&mut bytes, &[register, space, flags]);
                kind as u32
            }
        };
        set(&mut bytes, header, tag);
    }
    let sampler_offset = (bytes.len() - PAYLOAD) as u32;
    set(&mut bytes, PAYLOAD + 16, sampler_offset);
    for s in desc.samplers {
        write(
            &mut bytes,
            &[
                s.filter,
                s.address_u,
                s.address_v,
                s.address_w,
                s.mip_lod_bias.to_bits(),
                s.max_anisotropy,
                s.comparison_func,
                s.border_color,
                s.min_lod.to_bits(),
                s.max_lod.to_bits(),
                s.register,
                s.space,
                s.visibility,
            ],
        );
    }
    debug_assert_eq!(bytes.len(), size);
    let checksum = checksum::retail(&bytes[20..]);
    bytes[4..20].copy_from_slice(&checksum);
    Ok(bytes)
}

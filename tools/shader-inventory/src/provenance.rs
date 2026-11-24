//! Bounded operand provenance for the straight-line, single-raw-store shortlist.
//! Uses explicit LLVM spelling as a measurement, not as an executable IR.
use crate::llvm::Disassembler;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    Entry(u8),
    Zero,
    Load { site: u8, lane: u8, source: Source },
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    ZeroExtendedUserData,
    UserDataPair,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResultClass {
    Known(Source),
    Unsupported,
}

fn scalar(s: &str) -> Option<usize> {
    s.strip_prefix('s')?
        .parse::<usize>()
        .ok()
        .filter(|&i| i < 104)
}
fn span(s: &str, len: usize) -> Option<usize> {
    let (lo, hi) = s.strip_prefix("s[")?.strip_suffix(']')?.split_once(':')?;
    let lo = lo.parse::<usize>().ok()?;
    let hi = hi.parse::<usize>().ok()?;
    (hi < 104 && lo.checked_add(len - 1)? == hi).then_some(lo)
}
fn immediate(s: &str) -> bool {
    matches!(s, "0" | "null")
        || s.strip_prefix("0x")
            .is_some_and(|hex| u32::from_str_radix(hex, 16).is_ok())
}

struct Probe {
    values: [Value; 104],
    site: u8,
    waited_until: u8,
    store: Option<Source>,
}
impl Probe {
    fn new(user_count: usize) -> Self {
        let values = std::array::from_fn(|i| {
            if i < user_count {
                Value::Entry(i as u8)
            } else {
                Value::Unknown
            }
        });
        Self {
            values,
            site: 0,
            waited_until: 0,
            store: None,
        }
    }
    fn step(&mut self, line: &str) -> Option<()> {
        let (op, args) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        // Every recognized non-scalar opcode is known not to write ordinary SGPRs.
        match op {
            "s_inst_prefetch" | "v_mov_b32_e32" | "buffer_load_format_x" => (),
            "s_mov_b32" => {
                let (dst, src) = args.trim().split_once(',')?;
                let dst = scalar(dst.trim())?;
                let src = src.trim();
                self.values[dst] = if src == "0" || src == "0x0" {
                    Value::Zero
                } else {
                    self.values[scalar(src)?]
                };
            }
            "s_load_dwordx4" => {
                let mut args = args.split(',').map(str::trim);
                let dest = span(args.next()?, 4)?;
                let base = span(args.next()?, 2)?;
                if !immediate(args.next()?) || args.next().is_some() {
                    return None;
                }
                let source = match (self.values[base], self.values[base + 1]) {
                    (Value::Entry(_), Value::Zero) => Source::ZeroExtendedUserData,
                    (Value::Entry(lo), Value::Entry(hi)) if lo + 1 == hi => Source::UserDataPair,
                    _ => Source::Other,
                };
                self.site = self.site.checked_add(1)?;
                for i in 0..4 {
                    self.values[dest + i] = Value::Load {
                        site: self.site,
                        lane: i as u8,
                        source,
                    };
                }
            }
            "s_waitcnt" => match args.trim() {
                "lgkmcnt(0)" => self.waited_until = self.site,
                "vmcnt(0)" => (),
                _ => return None,
            },
            "buffer_store_dword"
            | "buffer_store_dwordx2"
            | "buffer_store_dwordx3"
            | "buffer_store_dwordx4" => {
                let mut args = args.split(',').map(str::trim);
                args.next()?;
                if args.next()? != "off" {
                    return None;
                }
                let desc = span(args.next()?, 4)?;
                let mut tail = args.next()?.split_ascii_whitespace();
                if !matches!(tail.next()?, "0" | "0x0") || args.next().is_some() {
                    return None;
                }
                if let Some(offset) = tail.next() {
                    offset
                        .strip_prefix("offset:")?
                        .parse::<u16>()
                        .ok()
                        .filter(|&n| n < 4096)?;
                }
                if tail.next().is_some() || self.store.is_some() {
                    return None;
                }
                let Value::Load {
                    site,
                    lane: 0,
                    source,
                } = self.values[desc]
                else {
                    return None;
                };
                if site > self.waited_until
                    || (1..4).any(|i| {
                        self.values[desc + i]
                            != (Value::Load {
                                site,
                                lane: i as u8,
                                source,
                            })
                    })
                {
                    return None;
                }
                self.store = Some(source);
            }
            _ => return None,
        }
        Some(())
    }
}

pub fn classify(
    dis: &mut Disassembler,
    bytes: &[u8],
    nodes: usize,
    user_count: usize,
) -> ResultClass {
    fn walk(
        dis: &mut Disassembler,
        bytes: &[u8],
        nodes: usize,
        user_count: usize,
    ) -> Option<Source> {
        if nodes > 64 {
            return None;
        }
        let mut model = Probe::new(user_count);
        let mut pc = 0;
        let mut text = [0; 1024];
        for step in 0..nodes {
            let (size, line) = dis.one(bytes.get(pc..)?, pc, &mut text)?;
            pc += size;
            if line == "s_endpgm" {
                return (step + 1 == nodes && pc == bytes.len())
                    .then_some(model.store)
                    .flatten();
            }
            model.step(line)?;
        }
        None
    }
    walk(dis, bytes, nodes, user_count).map_or(ResultClass::Unsupported, ResultClass::Known)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tracks_scalar_moves_load_before_self_clobber_and_wait() {
        let mut p = Probe::new(4);
        for line in [
            "s_mov_b32 s12, s2",
            "s_mov_b32 s13, 0",
            "s_load_dwordx4 s[12:15], s[12:13], 0x10",
        ] {
            p.step(line).unwrap();
        }
        let store = "buffer_store_dwordx2 v[2:3], off, s[12:15], 0 offset:16";
        assert!(p.step(store).is_none());
        p.step("s_waitcnt lgkmcnt(0)").unwrap();
        assert!(p.step(&store.replace("off", "v1")).is_none());
        p.step(store).unwrap();
        assert_eq!(p.store, Some(Source::ZeroExtendedUserData));
        p.store = None;
        p.step("s_mov_b32 s15, 0").unwrap();
        assert!(p.step(store).is_none());
        assert!(p.step("s_add_u32 s2, s2, 1").is_none());
    }
}

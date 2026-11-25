//! Local register-read witnesses in a closed reference mesh projection, not scheduling or lowering.
use crate::cfg::{Flow, relative};
use std::collections::BTreeMap;

type Regs = (bool, u32, u32); // vector file?, first register, dword count

enum Effect {
    Wait(bool), // vector counter?
    Load(Regs),
    Other,
}

pub(super) struct Node {
    name: &'static str,
    width: usize,
    flow: Flow,
    effect: Effect,
    reads: [Option<Regs>; 3],
}

impl Node {
    pub(super) fn new(name: &str, [a, b]: [u32; 2], len: usize, flow: Flow) -> Self {
        let s = |r| (r < 106).then_some((false, r, 1));
        let v = |r| (r >= 256).then(|| (true, r - 256, 1));
        let mut out = Self {
            name: "unclassified",
            width: len / 4,
            flow,
            effect: Effect::Other,
            reads: [None; 3],
        };
        let smem = match (name, len, a >> 18) {
            ("s_load_dword", 8, 0x3d00) => Some(("s_load_dword", 1, false)),
            ("s_load_dwordx2", 8, 0x3d01) => Some(("s_load_dwordx2", 2, false)),
            ("s_load_dwordx4", 8, 0x3d02) => Some(("s_load_dwordx4", 4, false)),
            ("s_load_dwordx8", 8, 0x3d03) => Some(("s_load_dwordx8", 8, false)),
            ("s_load_dwordx16", 8, 0x3d04) => Some(("s_load_dwordx16", 16, false)),
            ("s_buffer_load_dword", 8, 0x3d08) => Some(("s_buffer_load_dword", 1, true)),
            ("s_buffer_load_dwordx2", 8, 0x3d09) => Some(("s_buffer_load_dwordx2", 2, true)),
            ("s_buffer_load_dwordx4", 8, 0x3d0a) => Some(("s_buffer_load_dwordx4", 4, true)),
            ("s_buffer_load_dwordx8", 8, 0x3d0b) => Some(("s_buffer_load_dwordx8", 8, true)),
            ("s_buffer_load_dwordx16", 8, 0x3d0c) => Some(("s_buffer_load_dwordx16", 16, true)),
            _ => None,
        };
        if let Some((name, count, buffer)) = smem {
            let dst = (a >> 6) & 127;
            let base = (a & 63) * 2;
            let base_count = if buffer { 4 } else { 2 };
            out.name = name;
            if dst + count <= 106 {
                out.effect = Effect::Load((false, dst, count));
            }
            if base + base_count <= 106 && base % base_count == 0 {
                out.reads[0] = Some((false, base, base_count));
            }
            out.reads[1] = s(b >> 25);
            return out;
        }
        let mubuf = match (name, len, a & 0xfffc_0000) {
            ("buffer_load_format_x", 8, 0xe000_0000) => Some(("buffer_load_format_x", 1)),
            ("buffer_load_format_xy", 8, 0xe004_0000) => Some(("buffer_load_format_xy", 2)),
            ("buffer_load_format_xyz", 8, 0xe008_0000) => Some(("buffer_load_format_xyz", 3)),
            ("buffer_load_format_xyzw", 8, 0xe00c_0000) => Some(("buffer_load_format_xyzw", 4)),
            ("buffer_load_dword", 8, 0xe030_0000) => Some(("buffer_load_dword", 1)),
            _ => None,
        };
        if let Some((name, count)) = mubuf {
            let dst = (b >> 8) & 255;
            out.name = name;
            // Exclude LDS routing (no VGPR result).
            if a & (1 << 16) == 0 && dst + count <= 256 {
                out.effect = Effect::Load((true, dst, count));
            }
            // Bind the guaranteed four-word resource read, not optional address operands.
            let base = ((b >> 16) & 31) * 4;
            if base + 4 <= 106 {
                out.reads[0] = Some((false, base, 4));
            }
            out.reads[1] = s(b >> 24);
            return out;
        }
        match (name, len, a) {
            ("s_waitcnt", 4, 0xbf8c_c07f) => out.effect = Effect::Wait(false),
            ("s_waitcnt", 4, 0xbf8c_3f70) => out.effect = Effect::Wait(true),
            _ => {
                let sop2 = match (name, len, a >> 23) {
                    ("s_and_b32", 4 | 8, 0x10e) => Some("s_and_b32"),
                    ("s_lshr_b32", 4 | 8, 0x120) => Some("s_lshr_b32"),
                    ("s_pack_hh_b32_b16", 4 | 8, 0x134) => Some("s_pack_hh_b32_b16"),
                    _ => None,
                };
                if let Some(name) = sop2 {
                    out.name = name;
                    out.reads = [s(a & 255), s((a >> 8) & 255), None];
                } else if name == "v_readfirstlane_b32"
                    && len == 4
                    && a & 0xfe01_fe00 == 0x7e00_0400
                {
                    out.name = "v_readfirstlane_b32";
                    out.reads[0] = v(a & 511);
                } else if name == "v_bfe_u32"
                    && matches!(len, 8 | 12)
                    && a & 0xffff_0000 == 0xd548_0000
                {
                    out.name = "v_bfe_u32";
                    out.reads = [v(b & 511), v((b >> 9) & 511), v((b >> 18) & 511)];
                } else if name == "v_and_b32_e32"
                    && matches!(len, 4 | 8)
                    && a & 0xfe00_0000 == 0x3600_0000
                {
                    out.name = "v_and_b32_e32";
                    out.reads = [v(a & 511), Some((true, (a >> 9) & 255, 1)), None];
                }
            }
        }
        out
    }
}

pub(super) fn audit(nodes: &BTreeMap<usize, Node>) -> BTreeMap<String, usize> {
    let mut incoming = BTreeMap::<usize, usize>::new();
    for (&pc, node) in nodes {
        let next = pc + node.width;
        // Dedup a fork whose taken edge equals fallthrough.
        let target = match node.flow {
            Flow::Jump(d) | Flow::Fork(d) => relative(next, d),
            _ => None,
        };
        if let Some(target) = target {
            *incoming.entry(target).or_default() += 1;
        }
        if matches!(node.flow, Flow::Next | Flow::Fork(_)) && target != Some(next) {
            *incoming.entry(next).or_default() += 1;
        }
    }
    let mut out = BTreeMap::new();
    for (&pc, wait) in nodes {
        let Effect::Wait(vector) = wait.effect else {
            continue;
        };
        let next = pc + wait.width;
        let classify = || -> Result<String, &'static str> {
            let Some((&prior, producer)) = nodes.range(..pc).next_back() else {
                return Err("no-linear-predecessor");
            };
            if prior + producer.width != pc
                || producer.flow != Flow::Next
                || incoming.get(&pc) != Some(&1)
            {
                return Err("no-linear-predecessor");
            }
            let Effect::Load((file, first, count)) = producer.effect else {
                return Err("no-adjacent-checked-load");
            };
            if file != vector {
                return Err("no-adjacent-checked-load");
            }
            if wait.flow != Flow::Next || incoming.get(&next) != Some(&1) {
                return Err("checked-load/nonlinear-consumer");
            }
            let consumer = nodes.get(&next).ok_or("checked-load/nonlinear-consumer")?;
            if !consumer
                .reads
                .iter()
                .flatten()
                .any(|&(f, r, n)| f == file && r < first + count && first < r + n)
            {
                return Err("checked-load/no-adjacent-proven-read");
            }
            Ok(format!("{}->{}", producer.name, consumer.name))
        };
        let status = classify().unwrap_or_else(str::to_owned);
        let wait_name = if vector { "vmcnt(0)" } else { "lgkmcnt(0)" };
        *out.entry(format!("{wait_name}/{status}")).or_default() += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, a: u32, b: u32, len: usize) -> Node {
        Node::new(name, [a, b], len, Flow::Next)
    }

    // Owned encodings independently assembled by LLVM MC gfx1013 and gfx1030.
    #[test]
    fn scalar_quad_is_read_by_buffer_descriptor_not_destination() {
        let mut graph = BTreeMap::from([
            (0, node("s_load_dwordx4", 0xf4080201, 0xfa000000, 8)),
            (2, node("s_waitcnt", 0xbf8cc07f, 0, 4)),
            (3, node("s_buffer_load_dword", 0xf4200304, 0xfa000000, 8)),
        ]);
        assert_eq!(
            audit(&graph)["lgkmcnt(0)/s_load_dwordx4->s_buffer_load_dword"],
            1
        );
        // Same register as a producer destination, but solely as the consumer's destination.
        graph.insert(3, node("s_buffer_load_dword", 0xf4200208, 0xfa000000, 8));
        assert_eq!(
            audit(&graph)["lgkmcnt(0)/checked-load/no-adjacent-proven-read"],
            1
        );
        graph.insert(2, node("s_waitcnt", 0xbf8cc17f, 0, 4));
        assert!(audit(&graph).is_empty());
    }

    #[test]
    fn vector_witness_rejects_a_bypass_edge_and_routing_to_lds() {
        let mut graph = BTreeMap::from([
            (1, node("buffer_load_format_x", 0xe0001000, 0x80020401, 8)),
            (3, node("s_waitcnt", 0xbf8c3f70, 0, 4)),
            (4, node("v_readfirstlane_b32", 0x7e180504, 0, 4)),
        ]);
        assert_eq!(
            audit(&graph)["vmcnt(0)/buffer_load_format_x->v_readfirstlane_b32"],
            1
        );
        graph.insert(0, Node::new("s_cbranch_execz", [0; 2], 4, Flow::Fork(3)));
        assert_eq!(audit(&graph)["vmcnt(0)/checked-load/nonlinear-consumer"], 1);
        graph.insert(0, Node::new("s_cbranch_execz", [0; 2], 4, Flow::Fork(2)));
        assert_eq!(audit(&graph)["vmcnt(0)/no-linear-predecessor"], 1);
        graph.remove(&0);
        graph.insert(1, node("buffer_load_format_x", 0xe0011000, 0x80020401, 8));
        assert_eq!(audit(&graph)["vmcnt(0)/no-adjacent-checked-load"], 1);
    }
}

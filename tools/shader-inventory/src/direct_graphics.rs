//! Direct checked library-span hypotheses; no source families, native files, or entry selection.
use crate::{
    ARCHIVE_LIMIT, BLOB_LIMIT,
    graphics_reachability::{
        DirectGaps, DirectResult as ResultClass, direct_gaps, direct_result, exact_semantics,
    },
    llvm::{Cpu, Llvm},
    wrapped_library::library_to_final_marker,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::File,
    io::Read,
    path::Path,
};
use xsxemu::pipeline_library::PipelineLibrary;

const STARTS: [usize; 4] = [0, 24, 36, 40];
const WINDOWS: usize = 2 * STARTS.len();
const THRESHOLDS: [ResultClass; 4] = [
    ResultClass::ClosedNoStageExport,
    ResultClass::ClosedStageExport,
    ResultClass::EncodingComplete,
    ResultClass::OutputBindingOnly,
];
const STAGES: [&str; 3] = ["PS", "VS", "MS"];
type Results = [[ResultClass; 2]; WINDOWS];

fn windows(span: &[u8]) -> [Option<&[u8]>; WINDOWS] {
    let ends = [Some(span), library_to_final_marker(span)];
    std::array::from_fn(|i| {
        let end = ends[i / STARTS.len()]?;
        let window = end.get(STARTS[i % STARTS.len()]..)?;
        (!window.is_empty() && window.len().is_multiple_of(4) && window.len() <= BLOB_LIMIT)
            .then_some(window)
    })
}

fn projections(r: &Results) -> [[usize; 3]; THRESHOLDS.len()] {
    THRESHOLDS.map(|threshold| {
        let mut starts = [0u8; 3];
        for (i, [w64, w32]) in r.iter().enumerate() {
            for (mask, yes) in starts.iter_mut().zip([
                *w64 >= threshold,
                *w32 >= threshold,
                (*w64).min(*w32) >= threshold,
            ]) {
                if yes {
                    *mask |= 1 << (i % STARTS.len());
                }
            }
        }
        starts.map(|mask| mask.count_ones() as usize)
    })
}

#[derive(Default)]
struct StageCounts {
    total: usize,
    windows: BTreeMap<(usize, usize, ResultClass), usize>,
    per_tier: [[usize; 3]; THRESHOLDS.len()],
    multiple_starts: [[usize; 3]; THRESHOLDS.len()],
}

impl StageCounts {
    fn note(&mut self, r: &Results) {
        self.total += 1;
        for (i, window) in r.iter().enumerate() {
            for (wave, &result) in window.iter().enumerate() {
                *self.windows.entry((i, wave, result)).or_default() += 1;
            }
        }
        for (t, counts) in projections(r).iter().enumerate() {
            for (w, &n) in counts.iter().enumerate() {
                self.per_tier[t][w] += usize::from(n > 0);
                self.multiple_starts[t][w] += usize::from(n > 1);
            }
        }
    }
}

fn read_library(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(ARCHIVE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ARCHIVE_LIMIT {
        return Err("pipeline library exceeds bound".into());
    }
    Ok(bytes)
}

pub(super) fn run(path: &Path, reference: &OsStr, cpu: Cpu) -> Result<(), Box<dyn Error>> {
    let bytes = read_library(path)?;
    let lib = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(reference)?;
    let (major, minor, patch) = llvm.version;
    println!(
        "Direct stored graphics spans: LLVM {major}.{minor}.{patch} {}",
        cpu.name()
    );
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut cache = HashMap::new();
    let mut unknown = 0;
    let mut stage: [StageCounts; 3] = Default::default();
    let mut occurrences = [0; 3];
    let mut pairs = 0;
    let mut pair_keys = HashSet::new();
    // [tier][wave/hypothesis intersection][neither, VS only, PS only, both]
    let mut pair_counts = [[[0; 4]; 3]; THRESHOLDS.len()];
    for row in lib.graphics() {
        let mut row_results = [None; 3];
        for (slot, reference) in row.slots.into_iter().enumerate() {
            let Some(reference) = reference else { continue };
            if slot >= STAGES.len() {
                unknown += 1;
                continue;
            }
            occurrences[slot] += 1;
            let key = (slot, reference.program);
            let projected = if let Some(&cached) = cache.get(&key) {
                cached
            } else {
                let span = lib
                    .program(reference.program)
                    .ok_or("missing checked program span")?;
                let w = windows(span);
                let mut r = [[ResultClass::NoWindow; 2]; WINDOWS];
                for (i, window) in w.into_iter().enumerate() {
                    if let Some(window) = window {
                        r[i] = if i >= STARTS.len() && Some(window) == w[i - STARTS.len()] {
                            r[i - STARTS.len()]
                        } else {
                            waves
                                .each_mut()
                                .map(|wave| direct_result(wave, window, slot))
                        };
                    }
                }
                stage[slot].note(&r);
                let p = projections(&r);
                cache.insert(key, p);
                p
            };
            row_results[slot] = Some(projected);
        }
        let [Some(ps), Some(vs), None, None, None, None, None] = row.slots else {
            continue;
        };
        pair_keys.insert(((vs.program, vs.metadata), (ps.program, ps.metadata)));
        pairs += 1;
        let [Some(p), Some(v), _] = row_results else {
            unreachable!()
        };
        for t in 0..THRESHOLDS.len() {
            for w in 0..3 {
                let pattern = usize::from(v[t][w] > 0) | (usize::from(p[t][w] > 0) << 1);
                pair_counts[t][w][pattern] += 1;
            }
        }
    }
    println!("  unclassified slot occurrences excluded={unknown}");
    for (i, s) in stage.into_iter().enumerate() {
        println!(
            "  {}: distinct stage/programs={}, slot occurrences={}",
            STAGES[i], s.total, occurrences[i]
        );
        for t in 0..THRESHOLDS.len() {
            println!(
                "    {:?}: eligible={:?}, multiple starts={:?} (wave64 / wave32 / same window)",
                THRESHOLDS[t], s.per_tier[t], s.multiple_starts[t]
            );
        }
        for ((window, wave, outcome), count) in s.windows {
            let end = if window < STARTS.len() {
                "stored"
            } else {
                "last marker"
            };
            let wave = [64, 32][wave];
            println!(
                "    +{}, {end}, wave{wave}, {outcome:?}: {count}",
                STARTS[window % STARTS.len()]
            );
        }
    }
    println!(
        "  exact VS+PS occurrences={pairs}, distinct program/metadata pairs={}",
        pair_keys.len()
    );
    for (tier, counts) in THRESHOLDS.into_iter().zip(pair_counts) {
        println!(
            "    {tier:?}: {counts:?} (rows: wave64 / wave32 / same window per stage; columns: neither / VS only / PS only / both)"
        );
    }
    Ok(())
}

#[derive(Default)]
struct GapCounts {
    eligible: usize,
    exact: usize,
    ordinary_mul: (usize, usize),
    ordinary_add: (usize, usize),
    packed_cleared: [usize; 2],
    interp_sole: BTreeMap<(usize, Option<(u8, u8, u8)>), usize>,
    packed_requirements: [BTreeMap<crate::graphics_semantics::Outcome, usize>; 2],
    linear_sole: BTreeMap<String, usize>,
    distances: BTreeMap<usize, usize>,
    forms: BTreeMap<String, (usize, usize)>,
    sole_forms: BTreeMap<String, (usize, usize)>,
}

impl GapCounts {
    fn note(&mut self, gaps: &DirectGaps) {
        self.ordinary_add.0 += gaps.ordinary_vgpr_add;
        self.ordinary_add.1 += usize::from(gaps.ordinary_vgpr_add > 0);
        self.ordinary_mul.0 += gaps.ordinary_vgpr_mul;
        self.ordinary_mul.1 += usize::from(gaps.ordinary_vgpr_mul > 0);
        let contiguous = gaps.contiguous;
        let gaps = &gaps.missing;
        self.eligible += 1;
        self.exact += usize::from(gaps.is_empty());
        if !gaps.is_empty() {
            *self.distances.entry(gaps.values().sum()).or_default() += 1;
        }
        if gaps.len() == 1 {
            let (name, &sites) = gaps.first_key_value().unwrap();
            let rank = self.sole_forms.entry(name.clone()).or_default();
            rank.0 += 1;
            rank.1 += sites;
            if contiguous {
                *self.linear_sole.entry(name.clone()).or_default() += 1;
            }
        }
        for (name, &sites) in gaps {
            let form = self.forms.entry(name.clone()).or_default();
            form.0 += sites;
            form.1 += 1;
        }
    }

    fn report(self, stage: &str, start: usize, wave: usize) {
        println!(
            "  {stage} +{start} stored wave{wave}: qualified={}, no encoding gaps={}",
            self.eligible, self.exact
        );
        println!(
            "    exact two-VGPR v_mul_f32_e32: {} sites in {} windows",
            self.ordinary_mul.0, self.ordinary_mul.1
        );
        println!(
            "    exact two-VGPR v_add_f32_e32: {} sites in {} windows",
            self.ordinary_add.0, self.ordinary_add.1
        );
        if stage == "PS" {
            println!(
                "    sole prior packed-selector blocker (RG / RGBA): {:?} windows",
                self.packed_cleared
            );
        }
        for (kind, requirements) in ["RG", "RGBA"].into_iter().zip(self.packed_requirements) {
            for (outcome, count) in requirements {
                println!(
                    "      {kind}: {count} windows, local gaps={:?}, unresolved predicates={:?}",
                    outcome.gaps, outcome.needs
                );
            }
        }
        if !self.interp_sole.is_empty() {
            println!(
                "    sole interp MOV form sites by (gaps in window, (selector, attribute, channel)): {:?}",
                self.interp_sole
            );
        }
        let distances: Vec<_> = self.distances.into_iter().take(3).collect();
        println!("    nearest (unsupported sites, windows): {distances:?}");
        let mut leverage: Vec<_> = self.sole_forms.into_iter().collect();
        leverage.sort_unstable_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
        for (form, (windows, sites)) in leverage {
            println!(
                "    sole gap bucket {form}: {windows} windows, {sites} sites, {} contiguous",
                self.linear_sole.get(&form).copied().unwrap_or(0)
            );
        }
        let mut rows: Vec<_> = self.forms.into_iter().collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (form, (sites, windows)) in rows.into_iter().take(16) {
            println!("    {form}: {sites} sites in {windows} windows");
        }
    }
}

pub(super) fn run_gaps(path: &Path, reference: &OsStr, cpu: Cpu) -> Result<(), Box<dyn Error>> {
    let bytes = read_library(path)?;
    let lib = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(reference)?;
    let (major, minor, patch) = llvm.version;
    println!(
        "Direct graphics encoding gaps: LLVM {major}.{minor}.{patch} {}",
        cpu.name()
    );
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut distinct = HashSet::new();
    let mut interp_spans = HashSet::new();
    let mut packed_spans = [HashSet::new(), HashSet::new()];
    let mut counts: [[[GapCounts; 2]; STARTS.len()]; 2] = Default::default();
    for row in lib.graphics() {
        for (slot, reference) in row.slots.into_iter().take(2).enumerate() {
            let Some(reference) = reference else { continue };
            if !distinct.insert((slot, reference.program)) {
                continue;
            }
            let span = lib
                .program(reference.program)
                .ok_or("missing checked program span")?;
            for (i, window) in STARTS.iter().enumerate() {
                let Some(window) = span.get(*window..) else {
                    continue;
                };
                if window.is_empty() || !window.len().is_multiple_of(4) || window.len() > BLOB_LIMIT
                {
                    continue;
                }
                for (w, wave) in waves.iter_mut().enumerate() {
                    if let Some(gaps) = direct_gaps(wave, window, slot) {
                        counts[slot][i][w].note(&gaps);
                        if slot == 0
                            && gaps.contiguous
                            && gaps.missing.len() == 1
                            && let Some(&sites) = gaps
                                .missing
                                .get(super::graphics_reachability::INTERP_MOV_GAP)
                        {
                            interp_spans.insert(reference.program);
                            for (&shape, &count) in &gaps.interp_mov {
                                *counts[slot][i][w]
                                    .interp_sole
                                    .entry((sites, shape))
                                    .or_default() += count;
                            }
                        }
                        if slot == 0 && gaps.contiguous && gaps.missing.is_empty() {
                            for (form, only_one) in [[1, 0], [0, 1]].into_iter().enumerate() {
                                if gaps.packed_mrt0_noncanonical == only_one {
                                    counts[slot][i][w].packed_cleared[form] += 1;
                                    packed_spans[form].insert(reference.program);
                                    if let Some(outcome) = exact_semantics(wave, window, false) {
                                        *counts[slot][i][w].packed_requirements[form]
                                            .entry(outcome)
                                            .or_default() += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "  Distinct PS spans with sole interp MOV gap bucket across hypotheses: {}",
        interp_spans.len()
    );
    println!(
        "  Distinct PS spans with sole prior packed-selector blocker across hypotheses (RG / RGBA): {:?}",
        packed_spans.map(|spans| spans.len())
    );
    for (s, stage) in counts.into_iter().enumerate() {
        for (i, start) in stage.into_iter().enumerate() {
            for (w, wave) in start.into_iter().enumerate() {
                wave.report(STAGES[s], STARTS[i], [64, 32][w]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_operand_is_not_a_reached_end_and_slot_controls_export_evidence() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let llvm = Llvm::load(&path).unwrap();
        let mut wave = llvm.context(Cpu::Gfx1030, true).unwrap();
        let owned = |words: &[u32]| {
            words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let literal = owned(&[0x7e0002ff, 0xbf810000]);
        assert_ne!(
            direct_result(&mut wave, &literal, 0),
            ResultClass::ClosedNoStageExport
        );
        let end_only = owned(&[0xbf810000]);
        assert_eq!(
            direct_result(&mut wave, &end_only, 0),
            ResultClass::ClosedNoStageExport
        );
        let pixel = owned(&[0x7e000280, 0xf8001c0f, 0, 0xbf810000]);
        assert_eq!(
            direct_result(&mut wave, &pixel, 0),
            ResultClass::OutputBindingOnly
        );
        assert_eq!(
            direct_result(&mut wave, &pixel, 1),
            ResultClass::ClosedNoStageExport
        );
    }

    #[test]
    fn gap_rank_requires_closed_stage_export_and_checks_exact_width() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let llvm = Llvm::load(&path).unwrap();
        let mut wave = llvm.context(Cpu::Gfx1030, false).unwrap();
        let bytes = |words: &[u32]| {
            words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let ps = [
            0x1004_0300,
            0x1006_0200,
            0xf800_080f,
            0x0202_0202,
            0xbf81_0000,
        ];
        let gaps = direct_gaps(&mut wave, &bytes(&ps), 0).unwrap();
        assert_eq!(gaps.ordinary_vgpr_mul, 1);
        assert_eq!(
            gaps.missing,
            BTreeMap::from([("v_mul_f32_e32/SGPR/4B".into(), 1)])
        );
        assert!(direct_gaps(&mut wave, &bytes(&ps), 1).is_none());
        assert!(direct_gaps(&mut wave, &bytes(&ps[..4]), 0).is_none());
    }

    #[test]
    fn same_window_requires_both_waves_not_merely_matching_start() {
        let mut r = [[ResultClass::NoWindow; 2]; WINDOWS];
        r[0][0] = ResultClass::EncodingComplete;
        r[4][1] = ResultClass::EncodingComplete;
        assert_eq!(projections(&r)[2], [1, 1, 0]);
        r[0][1] = ResultClass::EncodingComplete;
        assert_eq!(projections(&r)[2], [1, 1, 1]);
        r[4][0] = ResultClass::EncodingComplete;
        assert_eq!(projections(&r)[2], [1, 1, 1]);
        r[1] = [ResultClass::EncodingComplete; 2];
        assert_eq!(projections(&r)[2], [2, 2, 2]);
    }
}

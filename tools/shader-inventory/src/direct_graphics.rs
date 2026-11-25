//! Direct checked library-span hypotheses; no source families, native files, or entry selection.
use crate::{
    ARCHIVE_LIMIT, BLOB_LIMIT,
    graphics_reachability::{
        DirectGaps, DirectResult as ResultClass, SETPRIO3_FORM, SetprioProjection, direct_gaps,
        direct_result, exact_semantics, project_sole_setprio3,
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

type FormPair = (String, String);
type SiteCounts = (usize, usize);

fn two_forms(missing: &BTreeMap<String, usize>) -> Option<(FormPair, SiteCounts)> {
    if missing.len() != 2 {
        return None;
    }
    let mut forms = missing.iter();
    let (a, &n) = forms.next()?;
    let (b, &m) = forms.next()?;
    Some(((a.clone(), b.clone()), (n, m)))
}

#[derive(Default)]
struct PairCounts {
    sites: BTreeMap<SiteCounts, usize>,
    contiguous: usize,
    details: BTreeMap<Vec<(String, usize)>, usize>,
}

#[derive(Default)]
struct GapCounts {
    eligible: usize,
    exact: usize,
    ordinary_mul: (usize, usize),
    ordinary_add: (usize, usize),
    signed_convert: (usize, usize),
    inline_first_fma: [(usize, usize); 2], // (sites, windows), positive/negative pair
    partial_param0: [usize; 3],
    bfrev_depth: BTreeMap<[usize; 7], usize>,
    packed_cleared: [usize; 2],
    interp_sole: BTreeMap<(usize, Option<(u8, u8, u8)>), usize>,
    packed_requirements: [BTreeMap<crate::graphics_semantics::Outcome, usize>; 2],
    linear_sole: BTreeMap<String, usize>,
    distances: BTreeMap<usize, usize>,
    forms: BTreeMap<String, (usize, usize)>,
    sole_forms: BTreeMap<String, (usize, usize)>,
    pairs: BTreeMap<FormPair, PairCounts>,
    refined_pairs: BTreeMap<FormPair, PairCounts>,
}

impl GapCounts {
    fn note(&mut self, gaps: &DirectGaps) {
        self.ordinary_add.0 += gaps.ordinary_vgpr_add;
        self.ordinary_add.1 += usize::from(gaps.ordinary_vgpr_add > 0);
        self.partial_param0[0] += gaps.partial_param0;
        self.partial_param0[1] += usize::from(gaps.partial_param0 > 0);
        self.partial_param0[2] += gaps.partial_param0_noncanonical;
        self.signed_convert.0 += gaps.signed_vgpr_convert;
        self.signed_convert.1 += usize::from(gaps.signed_vgpr_convert > 0);
        for (total, n) in self.inline_first_fma.iter_mut().zip(gaps.inline_first_fma) {
            total.0 += n;
            total.1 += usize::from(n > 0);
        }
        self.ordinary_mul.0 += gaps.ordinary_vgpr_mul;
        self.ordinary_mul.1 += usize::from(gaps.ordinary_vgpr_mul > 0);
        let contiguous = gaps.contiguous;
        let missing = &gaps.missing;
        self.eligible += 1;
        self.exact += usize::from(missing.is_empty());
        if contiguous
            && gaps.inline_bfrev_sites != 0
            && gaps.scalar_depth_noncanonical != 0
            && missing.values().sum::<usize>() <= 2
        {
            *self
                .bfrev_depth
                .entry([
                    gaps.inline_bfrev_sites,
                    gaps.scalar_depth_noncanonical,
                    gaps.adjacent_bfrev_depth,
                    gaps.same_prior_bfrev_depth,
                    gaps.prior_bfrev_color,
                    gaps.prior_bfrev_ba,
                    gaps.depth_before_bfrev,
                ])
                .or_default() += 1;
        }
        if !missing.is_empty() {
            *self.distances.entry(missing.values().sum()).or_default() += 1;
        }
        if missing.len() == 1 {
            let (name, &sites) = missing.first_key_value().unwrap();
            let rank = self.sole_forms.entry(name.clone()).or_default();
            rank.0 += 1;
            rank.1 += sites;
            if contiguous {
                *self.linear_sole.entry(name.clone()).or_default() += 1;
            }
        }
        if let Some((pair, sites)) = two_forms(missing) {
            let row = self.pairs.entry(pair).or_default();
            *row.sites.entry(sites).or_default() += 1;
            row.contiguous += usize::from(contiguous);
            *row.details
                .entry(
                    gaps.operand_forms
                        .iter()
                        .map(|(name, &n)| (name.clone(), n))
                        .collect(),
                )
                .or_default() += 1;
        }
        if let Some((pair, sites)) = two_forms(&gaps.operand_forms) {
            let row = self.refined_pairs.entry(pair).or_default();
            *row.sites.entry(sites).or_default() += 1;
            row.contiguous += usize::from(contiguous);
        }
        for (name, &sites) in missing {
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
        println!(
            "    exact signed VGPR e32 conversion: {} sites in {} windows",
            self.signed_convert.0, self.signed_convert.1
        );
        println!(
            "    exact inline-first VOP3 FMA (sites, windows) for (+2,v,-1) / (-2,v,+1): {:?}",
            self.inline_first_fma
        );
        if stage == "VS" {
            println!(
                "    exact partial PARAM0 EN3 (sites, windows, sites with nonzero disabled selectors): {:?}",
                self.partial_param0
            );
        }
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
        if !self.bfrev_depth.is_empty() {
            println!(
                "    near BFREV+MRTZ windows by (inline-60 sites, noncanonical scalar depth sites, adjacent BFREV→depth, matching prior BFREV dst/depth src, matching prior BFREV dst/packed color src, matching prior BFREV dst/BA, depth before BFREV): {:?}",
                self.bfrev_depth
            );
        }
        Self::report_pairs("gap buckets", self.pairs);
        Self::report_pairs("operand forms", self.refined_pairs);
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

    fn report_pairs(label: &str, rows: BTreeMap<FormPair, PairCounts>) {
        let mut pairs: Vec<_> = rows.into_iter().collect();
        pairs.sort_unstable_by(|a, b| {
            let total = |row: &PairCounts| row.sites.values().sum::<usize>();
            total(&b.1).cmp(&total(&a.1)).then_with(|| a.0.cmp(&b.0))
        });
        for ((a, b), row) in pairs {
            let total: usize = row.sites.values().sum();
            let two_sites = row.sites.get(&(1, 1)).copied().unwrap_or(0);
            println!(
                "    two {label} {a} + {b}: {total} windows, {two_sites} exactly two sites, {} contiguous, site multiplicities {:?}",
                row.contiguous, row.sites
            );
            for (shape, count) in row.details {
                println!("      {count} windows with operand pattern {shape:?}");
            }
        }
    }
}

struct PairSpans<K> {
    pairs: BTreeMap<FormPair, HashMap<K, bool>>,
}

impl<K: Copy + Eq + std::hash::Hash> PairSpans<K> {
    fn new() -> Self {
        Self {
            pairs: BTreeMap::new(),
        }
    }

    fn note(&mut self, span: K, missing: &BTreeMap<String, usize>) {
        if let Some((pair, sites)) = two_forms(missing) {
            *self.pairs.entry(pair).or_default().entry(span).or_default() |= sites == (1, 1);
        }
    }

    fn report(self, stage: &str, label: &str) {
        let union: HashSet<_> = self.pairs.values().flat_map(|spans| spans.keys()).collect();
        println!(
            "  {stage} two {label}: {} distinct spans in the union across starts/waves",
            union.len()
        );
        let mut pairs: Vec<_> = self.pairs.into_iter().collect();
        pairs.sort_unstable_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
        for ((a, b), spans) in pairs {
            let two_sites = spans.values().filter(|&&two| two).count();
            println!(
                "    {a} + {b}: {} distinct spans across starts/waves, {two_sites} with exactly two sites in at least one hypothesis",
                spans.len()
            );
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
    let mut partial_param_spans = HashSet::new();
    let mut inline_first_fma_spans = [HashSet::new(), HashSet::new()];
    let mut setprio_spans = HashSet::new();
    let mut setprio: [[BTreeMap<Option<SetprioProjection>, usize>; 2]; STARTS.len()] =
        Default::default();
    let mut packed_spans = [HashSet::new(), HashSet::new()];
    let mut vs_sets = BTreeMap::<Vec<String>, HashMap<_, (usize, u8)>>::new();
    let mut pair_spans = [PairSpans::new(), PairSpans::new()];
    let mut refined_spans = [PairSpans::new(), PairSpans::new()];
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
                        if gaps.inline_first_fma != [0, 0] {
                            inline_first_fma_spans[slot].insert(reference.program);
                        }
                        if slot == 1 && gaps.partial_param0 != 0 {
                            partial_param_spans.insert(reference.program);
                        }
                        if slot == 1
                            && gaps.operand_forms.len() == 1
                            && gaps.operand_forms.get(SETPRIO3_FORM) == Some(&1)
                        {
                            setprio_spans.insert(reference.program);
                            *setprio[i][w]
                                .entry(project_sole_setprio3(wave, window))
                                .or_default() += 1;
                        }
                        if slot == 1 && !gaps.operand_forms.is_empty() {
                            let key = gaps.operand_forms.keys().cloned().collect();
                            let sites = gaps.operand_forms.values().sum();
                            let row = vs_sets
                                .entry(key)
                                .or_default()
                                .entry(reference.program)
                                .or_insert((sites, 0));
                            row.0 = row.0.min(sites);
                            row.1 |= 1 << (i * 2 + w);
                        }
                        pair_spans[slot].note(reference.program, &gaps.missing);
                        refined_spans[slot].note(reference.program, &gaps.operand_forms);
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
    for (stage, (buckets, operands)) in STAGES
        .into_iter()
        .zip(pair_spans.into_iter().zip(refined_spans))
    {
        buckets.report(stage, "gap buckets");
        operands.report(stage, "operand forms");
    }
    println!(
        "  Distinct VS spans with exact partial PARAM0 EN3 across hypotheses: {}",
        partial_param_spans.len()
    );
    println!(
        "  Distinct spans with either exact inline-first VOP3 FMA across hypotheses (PS / VS): {:?}",
        inline_first_fma_spans.map(|spans| spans.len())
    );
    println!(
        "  Sole one-site SETPRIO imm3: {} distinct VS spans across hypotheses",
        setprio_spans.len()
    );
    for (start, waves) in STARTS.into_iter().zip(setprio) {
        for (wave, projections) in [64, 32].into_iter().zip(waves) {
            for (projection, n) in projections {
                println!(
                    "    +{start} wave{wave}: {n} windows; SETPRIO dataflow-only projection (not encoding coverage): {projection:?}"
                );
            }
        }
    }
    let mut vs_sets: Vec<_> = vs_sets.into_iter().collect();
    vs_sets.sort_unstable_by(|(a, x), (b, y)| {
        a.len()
            .cmp(&b.len())
            .then_with(|| y.len().cmp(&x.len()))
            .then_with(|| a.cmp(b))
    });
    for (forms, spans) in vs_sets.into_iter().take(12) {
        let profiles: [usize; 8] = std::array::from_fn(|i| {
            spans
                .values()
                .filter(|(_, mask)| mask & (1 << i) != 0)
                .count()
        });
        let min_sites = spans.values().map(|(n, _)| *n).min().unwrap();
        println!(
            "  VS blocker set: {} forms, min {min_sites} sites, {} distinct spans, profiles +0/+24/+36/+40 (wave64 then wave32) {profiles:?}: {forms:?}",
            forms.len(),
            spans.len()
        );
    }
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
    fn pair_counts_distinguish_sites_forms_and_duplicate_hypotheses() {
        let shape = |n, m| BTreeMap::from([("a".into(), n), ("b".into(), m)]);
        let mut spans = PairSpans::new();
        let repeated = shape(2, 1);
        assert_eq!(two_forms(&repeated).unwrap().1, (2, 1));
        assert!(two_forms(&BTreeMap::from([("a".into(), 2)])).is_none());
        spans.note(0, &repeated);
        spans.note(0, &shape(1, 1));
        spans.note(0, &repeated);
        spans.note(1, &repeated);
        assert_eq!(spans.pairs.len(), 1);
        assert_eq!(
            spans.pairs.values().next(),
            Some(&HashMap::from([(0, true), (1, false)]))
        );
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

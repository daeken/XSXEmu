//! Exact matched-window VS+PS cohort census; no bindings or bake admission.
use crate::graphics_semantics::{Need, Outcome};
use std::{
    collections::{BTreeMap, HashMap},
    rc::Rc,
};
use xsx_shader_inventory::source_families::{SourceKey, graphics_items};
use xsxemu::pipeline_library::ProgramId;

#[derive(Default)]
pub(super) struct Cohorts {
    windows: HashMap<(SourceKey, ProgramId), BTreeMap<usize, [Option<Rc<Outcome>>; 2]>>,
    wrapped: HashMap<SourceKey, [usize; 2]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Cohort {
    NoExactWindow,
    MultipleWindows,
    NoSharedProjection,
    LocalGap,
    EntryRegisters,
    FpOrDomain,
    BindingMinimal,
}

fn classify(
    windows: Option<&BTreeMap<usize, [Option<Rc<Outcome>>; 2]>>,
) -> (Cohort, Option<&Outcome>) {
    use Cohort::*;
    let Some(windows) = windows else {
        return (NoExactWindow, None);
    };
    if windows.len() != 1 {
        return (MultipleWindows, None);
    }
    classify_outcomes(&windows.first_key_value().unwrap().1)
}

fn classify_outcomes(outcomes: &[Option<Rc<Outcome>>; 2]) -> (Cohort, Option<&Outcome>) {
    use Cohort::*;
    use Need::*;
    let [Some(a), Some(b)] = outcomes else {
        return (NoSharedProjection, None);
    };
    if a != b {
        return (NoSharedProjection, None);
    }
    let cohort = if !a.gaps.is_empty() {
        LocalGap
    } else if a
        .needs
        .iter()
        .any(|n| matches!(n, EntryVgpr | EntryVcc | EntrySgpr | EntryM0))
    {
        EntryRegisters
    } else if a.needs.iter().any(|n| {
        matches!(
            n,
            F32ArithmeticMode | UintConversionRounding | PackedRtzDomain
        )
    }) {
        FpOrDomain
    } else {
        BindingMinimal
    };
    (cohort, Some(a))
}

impl Cohorts {
    pub(super) fn note_wrapper_payload(
        &mut self,
        key: SourceKey,
        outcomes: &[Option<Rc<Outcome>>; 2],
    ) {
        let count = self.wrapped.entry(key).or_default();
        count[0] += 1;
        count[1] += usize::from(classify_outcomes(outcomes).0 == Cohort::BindingMinimal);
    }

    pub(super) fn note(
        &mut self,
        key: SourceKey,
        id: ProgramId,
        start: usize,
        outcomes: &[Option<Rc<Outcome>>; 2],
    ) {
        self.windows
            .entry((key, id))
            .or_default()
            .entry(start)
            .or_insert_with(|| outcomes.clone());
    }

    pub(super) fn report(
        &self,
        library: &xsxemu::pipeline_library::PipelineLibrary<'_>,
        keys: &HashMap<(usize, xsxemu::pipeline_library::BlobId), SourceKey>,
        source_count: impl Fn(SourceKey) -> usize,
    ) {
        let mut pairs = BTreeMap::new();
        let mut distinct_pairs = std::collections::HashSet::new();
        let mut needs = BTreeMap::new();
        let mut no_items = [0; 3];
        let mut minimal = [0; 4];
        let mut total = 0;
        let mut wrapped = [0; 6];
        let mut missing = 0;
        for row in library.graphics() {
            let [Some(ps), Some(vs), None, None, None, None, None] = row.slots else {
                continue;
            };
            total += 1;
            let (Some(ps_blob), Some(vs_blob)) = (ps.metadata, vs.metadata) else {
                missing += 1;
                continue;
            };
            let (Some(&ps_key), Some(&vs_key)) = (keys.get(&(0, ps_blob)), keys.get(&(1, vs_blob)))
            else {
                missing += 1;
                continue;
            };
            distinct_pairs.insert(((vs.program, vs_blob), (ps.program, ps_blob)));
            let (vc, vo) = classify(self.windows.get(&(vs_key, vs.program)));
            let (pc, po) = classify(self.windows.get(&(ps_key, ps.program)));
            *pairs.entry((vc, pc)).or_insert(0usize) += 1;
            if let (Some(v), Some(p)) = (vo, po) {
                for n in v.needs.union(&p.needs) {
                    *needs.entry(*n).or_insert(0usize) += 1;
                }
            }
            let empty = |blob| {
                library
                    .blob(blob)
                    .and_then(graphics_items)
                    .is_some_and(|items| items.is_empty())
            };
            let (v_empty, p_empty) = (empty(vs_blob), empty(ps_blob));
            no_items[0] += usize::from(v_empty);
            no_items[1] += usize::from(p_empty);
            no_items[2] += usize::from(v_empty && p_empty);
            let both = vc == Cohort::BindingMinimal && pc == Cohort::BindingMinimal;
            let single = source_count(ps_key) == 1 && source_count(vs_key) == 1;
            let counts = |key| self.wrapped.get(&key).copied().unwrap_or_default();
            let [v_total, v_min] = counts(vs_key);
            let [p_total, p_min] = counts(ps_key);
            wrapped[0] += usize::from(v_min != 0);
            wrapped[1] += usize::from(p_min != 0);
            wrapped[2] += usize::from(v_min != 0 && p_min != 0);
            wrapped[3] +=
                usize::from(v_min == 1 && p_min == 1 && v_total == 1 && p_total == 1 && single);
            wrapped[4] += usize::from(v_min != 0 && p_min != 0 && v_empty && p_empty);
            wrapped[5] += usize::from(v_min != 0 && p_min != 0 && single);
            minimal[0] += usize::from(both);
            minimal[1] += usize::from(both && single);
            minimal[2] += usize::from(both && v_empty && p_empty);
            minimal[3] += usize::from(both && single && v_empty && p_empty);
        }
        println!(
            "Exact-window VS+PS semantic intersection: rows={total}, distinct (VS program/metadata, PS program/metadata) pairs={}",
            distinct_pairs.len()
        );
        println!("  missing checked stage metadata keys: {missing}");
        println!(
            "  wrapped-family-only hypotheses, >=1 minimal payload (VS / PS / both / unique payload+wrapper both / empty item lists both / unique wrapper both): {wrapped:?}"
        );
        for ((vs, ps), count) in pairs {
            println!("  VS={vs:?}, PS={ps:?}: {count}");
        }
        println!("  no stage metadata item records (VS / PS / both): {no_items:?}");
        println!(
            "  both binding-minimal (all / one wrapper per stage / empty item lists / both restrictions): {minimal:?}"
        );
        println!("  unresolved needs on paired shared projections (overlap): {needs:?}; ready=0");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classification_does_not_merge_multiple_windows_or_one_wave() {
        use Cohort::*;
        let outcome = || Some(Rc::new(Outcome::default()));
        assert_eq!(classify(None).0, NoExactWindow);
        let mut m = BTreeMap::from([(0, [outcome(), None])]);
        assert_eq!(classify(Some(&m)).0, NoSharedProjection);
        m.insert(0, [outcome(), outcome()]);
        assert_eq!(classify(Some(&m)).0, BindingMinimal);
        for item in m.get_mut(&0).unwrap() {
            Rc::get_mut(item.as_mut().unwrap())
                .unwrap()
                .needs
                .insert(Need::EntryVgpr);
        }
        assert_eq!(classify(Some(&m)).0, EntryRegisters);
        m.insert(24, [outcome(), outcome()]);
        assert_eq!(classify(Some(&m)).0, MultipleWindows);
    }
}

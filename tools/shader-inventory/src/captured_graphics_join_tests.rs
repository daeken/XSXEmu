//! Owned contract model only: not compiled into the planner or a capture reader.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scope {
    executable: [u8; 32],
    library: [u8; 32],
    producer: [u8; 32], // identifies the verified schema/consumer implementation
    session: u64,
    creation: u64, // occurrence, not a reusable address or handle
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    ordinal: usize,
    refs: GraphicsPso,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stage<'a> {
    start: usize,
    body: &'a [u8],
    wave: Wave,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wave {
    W32,
    W64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Color {
    format: u32,
    mask: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attachment {
    color: [Option<Color>; 8], // authenticated unbound slot, not unread/missing
    samples: (u32, u32),
    depth: Option<(u32, bool, u8)>, // owned format, write enable, comparison
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundViews {
    draw: u64,               // within the same session and creation above
    color: [Option<u32>; 8], // owned view generations, not native pointer identity
    depth: Option<u32>,
}

#[derive(Clone, Copy)]
struct Observation<'a> {
    scope: Scope,
    row: Row,
    stages: [Option<Stage<'a>>; 7],
    attachment: Option<Attachment>,
    views: Option<BoundViews>,
}

// This is the result of an external trusted verification path, mocked only
// by the owned fixture. Equality with untrusted fields cannot create it.
struct Verified<'a>(Observation<'a>);

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    MissingProof,
    Context,
    Row,
    Stage,
    Attachment,
    Draw,
}

#[derive(Debug, PartialEq, Eq)]
enum Joined {
    CreationOnly,
    CreationAndBoundViews,
}

fn join(
    bytes: &[u8],
    proof: Option<&Verified<'_>>,
    candidate: &Observation<'_>,
) -> Result<Joined, Failure> {
    let trusted = proof.ok_or(Failure::MissingProof)?.0;
    if trusted.scope != candidate.scope {
        return Err(Failure::Context);
    }
    let plan = Plan::pinned(bytes, trusted.scope.library).map_err(|_| Failure::Context)?;
    let row = candidate.row;
    if row != trusted.row || plan.library.graphics().nth(row.ordinal) != Some(row.refs) {
        return Err(Failure::Row);
    }
    let slot_mask = row
        .refs
        .slots
        .iter()
        .enumerate()
        .fold(0, |m, (i, s)| m | (u8::from(s.is_some()) << i));
    if !matches!(slot_mask, 3 | 5) || candidate.stages != trusted.stages {
        return Err(Failure::Stage);
    }
    for (stage, reference) in candidate.stages.into_iter().zip(row.refs.slots) {
        match (stage, reference) {
            (None, None) => (),
            (Some(s), Some(r))
                if r.metadata.is_some()
                    && s.start % 4 == 0
                    && !s.body.is_empty()
                    && s.body.len() % 4 == 0 =>
            {
                let span = plan.library.program(r.program).ok_or(Failure::Stage)?;
                let end = s.start.checked_add(s.body.len()).ok_or(Failure::Stage)?;
                if span.get(s.start..end) != Some(s.body) {
                    return Err(Failure::Stage);
                }
            }
            _ => return Err(Failure::Stage),
        }
    }
    let desc = candidate.attachment.ok_or(Failure::Attachment)?;
    if trusted.attachment != Some(desc)
        || desc.samples.0 == 0
        || desc
            .color
            .into_iter()
            .flatten()
            .any(|c| c.format == 0 || c.mask & !15 != 0)
        || desc.depth.is_some_and(|(format, _, _)| format == 0)
    {
        return Err(Failure::Attachment);
    }
    if candidate.views != trusted.views {
        // Never downgrade a contradictory draw claim to a successful creation join.
        return Err(Failure::Draw);
    }
    Ok(if candidate.views.is_some() {
        Joined::CreationAndBoundViews
    } else {
        Joined::CreationOnly
    })
}

fn owned(bytes: &[u8]) -> Observation<'_> {
    let lib = PipelineLibrary::parse(bytes).unwrap();
    let refs = lib.graphics().next().unwrap();
    let stage = Stage {
        start: 0,
        body: lib.program(refs.slots[1].unwrap().program).unwrap(),
        wave: Wave::W32,
    };
    Observation {
        scope: Scope {
            executable: [1; 32],
            library: Sha256::digest(bytes).into(),
            producer: [2; 32],
            session: 3,
            creation: 4,
        },
        row: Row { ordinal: 0, refs },
        stages: [Some(stage), Some(stage), None, None, None, None, None],
        attachment: Some(Attachment {
            color: [
                Some(Color {
                    format: 1,
                    mask: 12,
                }),
                None,
                Some(Color {
                    format: 2,
                    mask: 15,
                }),
                None,
                None,
                None,
                None,
                None,
            ],
            samples: (4, 0),
            depth: Some((3, true, 1)),
        }),
        views: None,
    }
}

fn owned_bytes() -> Vec<u8> {
    let mut b = fixture();
    for n in 0..2 {
        put(&mut b, G + 112 * n + 56, 0); // PS, same cloned row at a different ordinal
        put(&mut b, G + 112 * n + 60, 0);
    }
    b
}

#[test]
fn creation_is_an_exact_row_occurrence_and_never_a_draw() {
    let b = owned_bytes();
    let p = plan(&b);
    let good = owned(&b);
    let verified = Verified(good);
    assert_eq!(join(&b, Some(&verified), &good), Ok(Joined::CreationOnly));
    assert_eq!(join(&b, None, &good), Err(Failure::MissingProof));
    let mut other_library = b.clone();
    *other_library.last_mut().unwrap() ^= 1;
    assert_eq!(
        join(&other_library, Some(&verified), &good),
        Err(Failure::Context)
    );
    let mut x = good;
    x.row.ordinal = 1;
    assert_eq!(p.library.graphics().nth(1), Some(good.row.refs));
    assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Row));
    x = good;
    x.row.refs.state = xsxemu::pipeline_library::BlobId(1);
    assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Row));
    for change in [
        |s: &mut Scope| s.executable[0] ^= 1,
        |s: &mut Scope| s.library[0] ^= 1,
        |s: &mut Scope| s.producer[0] ^= 1,
        |s: &mut Scope| s.session += 1,
        |s: &mut Scope| s.creation += 1,
    ] {
        x = good;
        change(&mut x.scope);
        assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Context));
    }
}

#[test]
fn stage_entry_wave_and_bytes_cannot_be_substituted() {
    let b = owned_bytes();
    let good = owned(&b);
    let verified = Verified(good);
    for change in [
        |s: &mut Stage<'_>| s.start += 4,
        |s: &mut Stage<'_>| s.wave = Wave::W64,
        |s: &mut Stage<'_>| s.body = &[1, 0, 0, 0],
    ] {
        let mut x = good;
        change(x.stages[0].as_mut().unwrap());
        assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Stage));
    }
    let mut x = good;
    x.stages[1] = None;
    assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Stage));
    x = good;
    x.stages[0].as_mut().unwrap().start = usize::MAX & !3;
    assert_eq!(join(&b, Some(&Verified(x)), &x), Err(Failure::Stage));
}

#[test]
fn missing_reordered_or_conflicting_attachment_state_fails_closed() {
    let b = owned_bytes();
    let good = owned(&b);
    let verified = Verified(good);
    let mut x = good;
    x.attachment = None;
    assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Attachment));
    for change in [
        |a: &mut Attachment| a.color.swap(0, 2),
        |a: &mut Attachment| a.color.swap(1, 2),
        |a: &mut Attachment| a.color[0].as_mut().unwrap().mask = 15,
        |a: &mut Attachment| a.color[0].as_mut().unwrap().format += 1,
        |a: &mut Attachment| a.samples.0 = 1,
        |a: &mut Attachment| a.samples.1 = 1,
        |a: &mut Attachment| a.depth = None,
        |a: &mut Attachment| a.depth.as_mut().unwrap().1 = false,
    ] {
        x = good;
        change(x.attachment.as_mut().unwrap());
        assert_eq!(join(&b, Some(&verified), &x), Err(Failure::Attachment));
    }
}

#[test]
fn draw_evidence_is_not_borrowed_from_another_observation() {
    let b = owned_bytes();
    let p = plan(&b);
    let creation = owned(&b);
    let mut draw = creation;
    draw.views = Some(BoundViews {
        draw: 5,
        color: [Some(7), None, Some(8), None, None, None, None, None],
        depth: Some(9),
    });
    assert_eq!(
        join(&b, Some(&Verified(creation)), &draw),
        Err(Failure::Draw)
    );
    assert_eq!(
        join(&b, Some(&Verified(draw)), &draw),
        Ok(Joined::CreationAndBoundViews)
    );
    let mut x = draw;
    x.views.as_mut().unwrap().draw += 1;
    assert_eq!(join(&b, Some(&Verified(draw)), &x), Err(Failure::Draw));
    x = draw;
    x.views.as_mut().unwrap().color.swap(0, 2);
    assert_eq!(join(&b, Some(&Verified(draw)), &x), Err(Failure::Draw));
    assert!(p.summarize().contains("ready=0"));
}

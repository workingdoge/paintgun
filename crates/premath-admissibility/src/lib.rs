use std::collections::{BTreeMap, HashMap, HashSet};

pub type Context = BTreeMap<String, String>;

#[derive(Clone, Debug)]
pub struct PartialAssignment<E> {
    pub token_path: String,
    /// contextKey -> authored entry
    pub entries: HashMap<String, E>,
}

pub trait EntryOps<V, S> {
    fn value_key(&self) -> V;
    fn source_key(&self) -> S;
}

#[derive(Clone, Debug)]
pub enum KanDiag<E, V> {
    Gap,
    Consistent { value: V, sources: Vec<String> },
    Conflict { candidates: Vec<(String, E)> },
}

#[derive(Clone, Debug)]
pub struct BcViolation<V, S> {
    pub token_path: String,
    pub axis_a: String,
    pub value_a: String,
    pub axis_b: String,
    pub value_b: String,
    pub left: V,
    pub right: V,
    pub left_source: S,
    pub right_source: S,
}

#[derive(Clone, Debug)]
pub enum StabilityFailureKind {
    CompositionNonCommutative,
}

impl StabilityFailureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StabilityFailureKind::CompositionNonCommutative => "composition_non_commutative",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StabilityFailure<S> {
    pub token_path: String,
    pub context: String,
    pub axis_a: String,
    pub value_a: String,
    pub axis_b: String,
    pub value_b: String,
    pub kind: StabilityFailureKind,
    pub sources: Vec<S>,
}

#[derive(Clone, Debug)]
pub enum LocalityFailureKind {
    RestrictionMissing,
    RestrictionAmbiguous,
}

impl LocalityFailureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            LocalityFailureKind::RestrictionMissing => "restriction_missing",
            LocalityFailureKind::RestrictionAmbiguous => "restriction_ambiguous",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalityFailure<S> {
    pub token_path: String,
    pub context: String,
    pub restricted_context: String,
    pub kind: LocalityFailureKind,
    pub sources: Vec<S>,
}

#[derive(Clone, Debug)]
pub struct OrthogonalityOverlap {
    pub axis_a: String,
    pub axis_b: String,
    pub overlap_paths: Vec<String>,
}

pub fn context_key(input: &Context) -> String {
    if input.is_empty() {
        return "(base)".to_string();
    }

    let mut entries: Vec<(&String, &String)> = input.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    entries
        .into_iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn parse_context_key(key: &str) -> Context {
    if key == "(base)" {
        return BTreeMap::new();
    }
    let mut out = BTreeMap::new();
    for pair in key.split(',') {
        if let Some((k, v)) = pair.split_once(':') {
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

fn is_subcontext(ctx: &Context, target: &Context) -> bool {
    ctx.iter().all(|(k, v)| target.get(k) == Some(v))
}

fn dedup_preserving_order<T: Eq + Clone>(values: Vec<T>) -> Vec<T> {
    let mut out = Vec::new();
    for value in values {
        if !out.iter().any(|existing| existing == &value) {
            out.push(value);
        }
    }
    out
}

/// Witness-producing Kan completion over a context poset.
pub fn kan_diag<E, V, S>(entries: &HashMap<String, E>, target: &Context) -> KanDiag<E, V>
where
    E: EntryOps<V, S> + Clone,
    V: Clone + Eq,
{
    let mut best_size: i32 = -1;
    let mut candidates: Vec<(String, E)> = Vec::new();

    for (ctx_key, entry) in entries {
        let ctx = parse_context_key(ctx_key);
        if !is_subcontext(&ctx, target) {
            continue;
        }

        let size = ctx.len() as i32;
        if size > best_size {
            best_size = size;
            candidates.clear();
            candidates.push((ctx_key.clone(), entry.clone()));
        } else if size == best_size {
            candidates.push((ctx_key.clone(), entry.clone()));
        }
    }

    if best_size < 0 {
        return KanDiag::Gap;
    }

    candidates.sort_by(|(a, _), (b, _)| a.cmp(b));
    let value0 = candidates[0].1.value_key();
    let all_same = candidates
        .iter()
        .all(|(_, entry)| entry.value_key() == value0);

    if all_same {
        return KanDiag::Consistent {
            value: value0,
            sources: candidates.into_iter().map(|(k, _)| k).collect(),
        };
    }

    KanDiag::Conflict { candidates }
}

/// Beck-Chevalley violations over base + single-axis authored contexts.
pub fn bc_violations<E, V, S>(
    assignments: &[PartialAssignment<E>],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<BcViolation<V, S>>
where
    E: EntryOps<V, S>,
    V: Clone + Eq,
    S: Clone,
{
    let axis_names: Vec<String> = axes.keys().cloned().collect();
    let mut out: Vec<BcViolation<V, S>> = Vec::new();

    for i in 0..axis_names.len() {
        for j in (i + 1)..axis_names.len() {
            let a = &axis_names[i];
            let b = &axis_names[j];
            let vals_a = &axes[a];
            let vals_b = &axes[b];

            for asn in assignments {
                for va in vals_a {
                    for vb in vals_b {
                        let mut ctx_a = BTreeMap::new();
                        ctx_a.insert(a.clone(), va.clone());
                        let k_a = context_key(&ctx_a);

                        let mut ctx_b = BTreeMap::new();
                        ctx_b.insert(b.clone(), vb.clone());
                        let k_b = context_key(&ctx_b);

                        let mut ctx_ab = BTreeMap::new();
                        ctx_ab.insert(a.clone(), va.clone());
                        ctx_ab.insert(b.clone(), vb.clone());
                        let k_ab = context_key(&ctx_ab);

                        let Some(left) = asn.entries.get(&k_a) else {
                            continue;
                        };
                        let Some(right) = asn.entries.get(&k_b) else {
                            continue;
                        };

                        let left_v = left.value_key();
                        let right_v = right.value_key();

                        if left_v != right_v && !asn.entries.contains_key(&k_ab) {
                            out.push(BcViolation {
                                token_path: asn.token_path.clone(),
                                axis_a: a.clone(),
                                value_a: va.clone(),
                                axis_b: b.clone(),
                                value_b: vb.clone(),
                                left: left_v,
                                right: right_v,
                                left_source: left.source_key(),
                                right_source: right.source_key(),
                            });
                        }
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.axis_a.cmp(&b.axis_a))
            .then(a.value_a.cmp(&b.value_a))
            .then(a.axis_b.cmp(&b.axis_b))
            .then(a.value_b.cmp(&b.value_b))
    });
    out
}

pub fn stability_failures<E, V, S>(
    assignments: &[PartialAssignment<E>],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<StabilityFailure<S>>
where
    E: EntryOps<V, S>,
    V: Clone + Eq,
    S: Clone + Eq,
{
    let mut out = Vec::new();
    for bc in bc_violations(assignments, axes) {
        out.push(StabilityFailure {
            token_path: bc.token_path,
            context: format!("{}:{},{}:{}", bc.axis_a, bc.value_a, bc.axis_b, bc.value_b),
            axis_a: bc.axis_a,
            value_a: bc.value_a,
            axis_b: bc.axis_b,
            value_b: bc.value_b,
            kind: StabilityFailureKind::CompositionNonCommutative,
            sources: dedup_preserving_order(vec![bc.left_source, bc.right_source]),
        });
    }

    out.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.context.cmp(&b.context))
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });
    out
}

fn immediate_restrictions(ctx: &Context) -> Vec<Context> {
    let mut axes: Vec<String> = ctx.keys().cloned().collect();
    axes.sort();
    let mut out = Vec::new();
    for axis in axes {
        let mut next = ctx.clone();
        next.remove(&axis);
        out.push(next);
    }
    out
}

pub fn locality_failures<E, V, S>(
    assignments: &[PartialAssignment<E>],
    contexts: &[Context],
) -> Vec<LocalityFailure<S>>
where
    E: EntryOps<V, S> + Clone,
    V: Clone + Eq,
    S: Clone + Eq,
{
    let mut out = Vec::new();

    for asn in assignments {
        for ctx in contexts {
            if ctx.is_empty() {
                continue;
            }

            let KanDiag::Consistent { sources, .. } = kan_diag::<E, V, S>(&asn.entries, ctx) else {
                continue;
            };

            let ctx_key = context_key(ctx);
            let target_sources = dedup_preserving_order(
                sources
                    .iter()
                    .filter_map(|k| asn.entries.get(k).map(|entry| entry.source_key()))
                    .collect(),
            );

            for restricted in immediate_restrictions(ctx) {
                let restricted_key = context_key(&restricted);
                match kan_diag::<E, V, S>(&asn.entries, &restricted) {
                    KanDiag::Consistent { .. } => {}
                    KanDiag::Gap => out.push(LocalityFailure {
                        token_path: asn.token_path.clone(),
                        context: ctx_key.clone(),
                        restricted_context: restricted_key,
                        kind: LocalityFailureKind::RestrictionMissing,
                        sources: target_sources.clone(),
                    }),
                    KanDiag::Conflict { candidates } => {
                        let sources = dedup_preserving_order(
                            candidates
                                .into_iter()
                                .map(|(_, entry)| entry.source_key())
                                .collect(),
                        );
                        out.push(LocalityFailure {
                            token_path: asn.token_path.clone(),
                            context: ctx_key.clone(),
                            restricted_context: restricted_key,
                            kind: LocalityFailureKind::RestrictionAmbiguous,
                            sources,
                        });
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.context.cmp(&b.context))
            .then(a.restricted_context.cmp(&b.restricted_context))
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });
    out
}

pub fn orthogonality_overlaps<E>(
    assignments: &[PartialAssignment<E>],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<OrthogonalityOverlap> {
    let axis_names: Vec<String> = axes.keys().cloned().collect();
    let mut touched: HashMap<String, HashSet<String>> = HashMap::new();
    for axis in &axis_names {
        touched.insert(axis.clone(), HashSet::new());
    }

    for asn in assignments {
        for ctx_key in asn.entries.keys() {
            let ctx = parse_context_key(ctx_key);
            for axis in &axis_names {
                if ctx.contains_key(axis) {
                    touched
                        .get_mut(axis)
                        .expect("axis initialized")
                        .insert(asn.token_path.clone());
                }
            }
        }
    }

    let mut out = Vec::new();
    for i in 0..axis_names.len() {
        for j in (i + 1)..axis_names.len() {
            let axis_a = &axis_names[i];
            let axis_b = &axis_names[j];
            let set_a = &touched[axis_a];
            let set_b = &touched[axis_b];
            let mut overlap_paths: Vec<String> = set_a.intersection(set_b).cloned().collect();
            overlap_paths.sort();
            out.push(OrthogonalityOverlap {
                axis_a: axis_a.clone(),
                axis_b: axis_b.clone(),
                overlap_paths,
            });
        }
    }

    out
}

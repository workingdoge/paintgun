use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepShape {
    pub sort: u8,
    pub opcode: u8,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniquePred {
    #[serde(default)]
    pub sort: Option<u8>,
    #[serde(default)]
    pub opcode: Option<u8>,
    #[serde(rename = "metaEq", default)]
    pub meta_eq: BTreeMap<String, String>,
}

impl UniquePred {
    pub fn matches(&self, dep: &DepShape) -> bool {
        if self.sort.is_some() && self.sort != Some(dep.sort) {
            return false;
        }
        if self.opcode.is_some() && self.opcode != Some(dep.opcode) {
            return false;
        }
        for (k, v) in &self.meta_eq {
            if dep.meta.get(k) != Some(v) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UniquePos {
    First,
    Last,
    Index(usize),
    Anywhere,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniqueMatch {
    pub matched_index: usize,
    pub matched: DepShape,
    pub remaining: Vec<DepShape>,
}

/// Match a minimal UniqueSpec slice over dependency shapes.
///
/// This follows the `raw/DSL` UniqueSpec semantics for:
/// - `pos`: first | last | integer | anywhere
/// - `optional`: true/false
pub fn match_unique_spec(
    deps: &[DepShape],
    pred: &UniquePred,
    pos: UniquePos,
    optional: bool,
) -> Result<Option<UniqueMatch>, String> {
    let choose_index = match pos {
        UniquePos::First => {
            if deps.is_empty() {
                None
            } else if pred.matches(&deps[0]) {
                Some(0usize)
            } else {
                return Err("UniqueSpec(first) predicate failed on first dependency".to_string());
            }
        }
        UniquePos::Last => {
            if deps.is_empty() {
                None
            } else {
                let idx = deps.len() - 1;
                if pred.matches(&deps[idx]) {
                    Some(idx)
                } else {
                    return Err("UniqueSpec(last) predicate failed on last dependency".to_string());
                }
            }
        }
        UniquePos::Index(i) => {
            if i >= deps.len() {
                return Err(format!(
                    "UniqueSpec(index={i}) is out of bounds for {} dependencies",
                    deps.len()
                ));
            }
            if pred.matches(&deps[i]) {
                Some(i)
            } else {
                return Err(format!(
                    "UniqueSpec(index={i}) predicate failed on dependency at index {i}"
                ));
            }
        }
        UniquePos::Anywhere => {
            let mut hits: Vec<usize> = deps
                .iter()
                .enumerate()
                .filter_map(|(i, d)| if pred.matches(d) { Some(i) } else { None })
                .collect();
            if hits.is_empty() {
                None
            } else if hits.len() == 1 {
                Some(hits.remove(0))
            } else {
                return Err(format!(
                    "UniqueSpec(anywhere) is ambiguous: matched {} dependencies",
                    hits.len()
                ));
            }
        }
    };

    match choose_index {
        Some(idx) => {
            let mut remaining = Vec::with_capacity(deps.len().saturating_sub(1));
            for (i, dep) in deps.iter().enumerate() {
                if i != idx {
                    remaining.push(dep.clone());
                }
            }
            Ok(Some(UniqueMatch {
                matched_index: idx,
                matched: deps[idx].clone(),
                remaining,
            }))
        }
        None if optional => Ok(None),
        None => Err("UniqueSpec required match missing".to_string()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BagMode {
    Ordered,
    Unordered,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySelector {
    Sort,
    Opcode,
    Meta(String),
}

impl KeySelector {
    pub fn key_of(&self, dep: &DepShape) -> Option<String> {
        match self {
            Self::Sort => Some(dep.sort.to_string()),
            Self::Opcode => Some(dep.opcode.to_string()),
            Self::Meta(field) => dep.meta.get(field).cloned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedKeysSpec {
    Literal(Vec<String>),
    FromBinding {
        binding: String,
        key_selector: KeySelector,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BagMatch {
    pub matched_indices: Vec<usize>,
    pub matched: Vec<DepShape>,
    pub remaining: Vec<DepShape>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BagRule {
    pub name: String,
    pub expected_keys: ExpectedKeysSpec,
    pub key_selector: KeySelector,
    pub pred: UniquePred,
    pub mode: BagMode,
    pub pos: UniquePos,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolK {
    Count(usize),
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BagBinding {
    pub name: String,
    pub matched: Vec<DepShape>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiBagMatch {
    pub pool_indices: Vec<usize>,
    pub matched_indices: Vec<usize>,
    pub bindings: Vec<BagBinding>,
    pub remaining: Vec<DepShape>,
}

pub fn bindings_map(bindings: &[BagBinding]) -> Result<BTreeMap<String, Vec<DepShape>>, String> {
    let mut out = BTreeMap::new();
    for binding in bindings {
        if binding.name.is_empty() {
            return Err("binding name must be non-empty".to_string());
        }
        if out
            .insert(binding.name.clone(), binding.matched.clone())
            .is_some()
        {
            return Err(format!("duplicate binding name {:?}", binding.name));
        }
    }
    Ok(out)
}

pub fn resolve_expected_keys(
    expected_keys: &ExpectedKeysSpec,
    bindings: &BTreeMap<String, Vec<DepShape>>,
) -> Result<Vec<String>, String> {
    match expected_keys {
        ExpectedKeysSpec::Literal(keys) => Ok(keys.clone()),
        ExpectedKeysSpec::FromBinding {
            binding,
            key_selector,
        } => {
            let deps = bindings
                .get(binding)
                .ok_or_else(|| format!("expected_keys(binding={binding:?}) not found"))?;
            let mut keys = Vec::with_capacity(deps.len());
            for (idx, dep) in deps.iter().enumerate() {
                let key = key_selector.key_of(dep).ok_or_else(|| {
                    format!(
                        "expected_keys(binding={binding:?}) key_of failed at matched index {idx}"
                    )
                })?;
                keys.push(key);
            }
            Ok(keys)
        }
    }
}

/// Match a BagSpec slice.
///
/// This supports:
/// - `mode`: ordered | unordered
/// - `pos`: first | last | integer | anywhere
/// - key matching via `key_selector`
/// - strict ambiguity rejection for `anywhere` selection
pub fn match_bag_spec(
    deps: &[DepShape],
    pred: &UniquePred,
    key_selector: &KeySelector,
    expected_keys: &[String],
    mode: BagMode,
    pos: UniquePos,
) -> Result<BagMatch, String> {
    match_bag_spec_resolved(deps, pred, key_selector, expected_keys, mode, pos)
}

pub fn match_bag_spec_with_bindings(
    deps: &[DepShape],
    pred: &UniquePred,
    key_selector: &KeySelector,
    expected_keys: &ExpectedKeysSpec,
    mode: BagMode,
    pos: UniquePos,
    bindings: &BTreeMap<String, Vec<DepShape>>,
) -> Result<BagMatch, String> {
    let resolved = resolve_expected_keys(expected_keys, bindings)?;
    match_bag_spec_resolved(deps, pred, key_selector, &resolved, mode, pos)
}

fn match_bag_spec_resolved(
    deps: &[DepShape],
    pred: &UniquePred,
    key_selector: &KeySelector,
    expected_keys: &[String],
    mode: BagMode,
    pos: UniquePos,
) -> Result<BagMatch, String> {
    let selected_indices: Vec<usize> = match pos {
        UniquePos::Anywhere => match mode {
            BagMode::Ordered => {
                let mut solutions = Vec::new();
                let mut current = Vec::new();
                search_ordered_subsequence_solutions(
                    deps,
                    pred,
                    key_selector,
                    expected_keys,
                    0,
                    0,
                    &mut current,
                    &mut solutions,
                    2,
                );
                if solutions.is_empty() {
                    return Err(
                        "BagSpec(anywhere,ordered) found no subsequence matching expected keys"
                            .to_string(),
                    );
                }
                if solutions.len() > 1 {
                    return Err(
                        "BagSpec(anywhere,ordered) is ambiguous: multiple subsequences match"
                            .to_string(),
                    );
                }
                solutions.remove(0)
            }
            BagMode::Unordered => {
                let expected_counts = counts(expected_keys);
                let mut indices_by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
                for (idx, dep) in deps.iter().enumerate() {
                    if !pred.matches(dep) {
                        continue;
                    }
                    let Some(key) = key_selector.key_of(dep) else {
                        continue;
                    };
                    if expected_counts.contains_key(&key) {
                        indices_by_key.entry(key).or_default().push(idx);
                    }
                }

                for (key, need) in &expected_counts {
                    let have = indices_by_key.get(key).map_or(0usize, Vec::len);
                    if have < *need {
                        return Err(format!(
                            "BagSpec(anywhere,unordered) missing key {key:?}: expected {need}, found {have}"
                        ));
                    }
                    if have > *need {
                        return Err(format!(
                            "BagSpec(anywhere,unordered) is ambiguous for key {key:?}: expected {need}, found {have} candidates"
                        ));
                    }
                }

                let mut used_per_key: BTreeMap<String, usize> = BTreeMap::new();
                let mut selected = Vec::with_capacity(expected_keys.len());
                for key in expected_keys {
                    let key_indices = indices_by_key.get(key).expect("present from count check");
                    let used = used_per_key.entry(key.clone()).or_insert(0);
                    if *used >= key_indices.len() {
                        return Err(format!(
                            "BagSpec(anywhere,unordered) missing canonical occurrence for key {key:?}"
                        ));
                    }
                    selected.push(key_indices[*used]);
                    *used += 1;
                }
                selected
            }
        },
        _ => {
            let slice = select_indices_for_pos(deps.len(), &pos, expected_keys.len(), "BagSpec")?;
            let mut slice_keys: Vec<String> = Vec::with_capacity(slice.len());
            for dep_idx in &slice {
                let dep = &deps[*dep_idx];
                if !pred.matches(dep) {
                    return Err(format!(
                        "BagSpec({pos:?}) predicate failed at dependency index {dep_idx}"
                    ));
                }
                let key = key_selector.key_of(dep).ok_or_else(|| {
                    format!("BagSpec key_of produced no key at dependency index {dep_idx}")
                })?;
                slice_keys.push(key);
            }

            match mode {
                BagMode::Ordered => {
                    for (i, key) in slice_keys.iter().enumerate() {
                        if key != &expected_keys[i] {
                            return Err(format!(
                                "BagSpec({pos:?},ordered) key mismatch at position {i}: expected {:?}, found {:?}",
                                expected_keys[i], key
                            ));
                        }
                    }
                    slice
                }
                BagMode::Unordered => {
                    let expected_counts = counts(expected_keys);
                    let actual_counts = counts(&slice_keys);
                    if expected_counts != actual_counts {
                        return Err(format!(
                            "BagSpec({pos:?},unordered) key multiset mismatch: expected {:?}, found {:?}",
                            expected_counts, actual_counts
                        ));
                    }
                    let mut by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
                    for (idx, key) in slice.iter().copied().zip(slice_keys.into_iter()) {
                        by_key.entry(key).or_default().push(idx);
                    }
                    let mut used_per_key: BTreeMap<String, usize> = BTreeMap::new();
                    let mut selected = Vec::with_capacity(expected_keys.len());
                    for key in expected_keys {
                        let key_indices = by_key.get(key).expect("present from count check");
                        let used = used_per_key.entry(key.clone()).or_insert(0);
                        if *used >= key_indices.len() {
                            return Err(format!(
                                "BagSpec({pos:?},unordered) missing canonical occurrence for key {key:?}"
                            ));
                        }
                        selected.push(key_indices[*used]);
                        *used += 1;
                    }
                    selected
                }
            }
        }
    };

    let matched = selected_indices
        .iter()
        .map(|idx| deps[*idx].clone())
        .collect::<Vec<_>>();
    let selected_set: BTreeSet<usize> = selected_indices.iter().copied().collect();
    let remaining = remaining_without_indices(deps, &selected_set);

    Ok(BagMatch {
        matched_indices: selected_indices,
        matched,
        remaining,
    })
}

/// Match a MultiBagSpec slice using exact slot matching.
///
/// This supports:
/// - bag partitioning with exact slot fill
/// - ambiguity rejection (multiple valid bipartite matchings)
/// - `consume_all` enforcement on the selected pool
pub fn match_multibag_spec(
    deps: &[DepShape],
    bags: &[BagRule],
    pool_pred: Option<&UniquePred>,
    pos: UniquePos,
    pool_k: Option<PoolK>,
    consume_all: bool,
    domain_pred: Option<&UniquePred>,
    seed_bindings: Option<&BTreeMap<String, Vec<DepShape>>>,
) -> Result<MultiBagMatch, String> {
    let mut names = BTreeSet::new();
    for bag in bags {
        if bag.name.is_empty() {
            return Err("MultiBagSpec bag name must be non-empty".to_string());
        }
        if !names.insert(bag.name.clone()) {
            return Err(format!("MultiBagSpec duplicate bag name {:?}", bag.name));
        }
        if bag.mode != BagMode::Unordered {
            return Err(format!(
                "MultiBagSpec bag {:?} must use mode=unordered",
                bag.name
            ));
        }
        if bag.pos != UniquePos::Anywhere {
            return Err(format!(
                "MultiBagSpec bag {:?} must use pos=anywhere",
                bag.name
            ));
        }
    }

    let seed_bindings = seed_bindings.cloned().unwrap_or_default();
    let mut resolved_expected_by_bag = Vec::with_capacity(bags.len());
    for bag in bags {
        let resolved = resolve_expected_keys(&bag.expected_keys, &seed_bindings).map_err(|e| {
            format!(
                "MultiBagSpec bag {:?} expected_keys resolution failed: {e}",
                bag.name
            )
        })?;
        resolved_expected_by_bag.push(resolved);
    }

    let filtered: Vec<usize> = deps
        .iter()
        .enumerate()
        .filter_map(|(idx, dep)| {
            let keep = pool_pred.map(|p| p.matches(dep)).unwrap_or(true);
            if keep {
                Some(idx)
            } else {
                None
            }
        })
        .collect();

    let pool_indices: Vec<usize> = match pos {
        UniquePos::Anywhere => filtered.clone(),
        _ => {
            let n_slots = resolved_expected_by_bag
                .iter()
                .map(std::vec::Vec::len)
                .sum::<usize>();
            let k = match pool_k {
                Some(PoolK::Count(n)) => n,
                Some(PoolK::All) => match &pos {
                    UniquePos::First | UniquePos::Last => filtered.len(),
                    UniquePos::Index(start) => {
                        if *start > filtered.len() {
                            return Err(format!(
                                "MultiBagSpec pool_k=all start index {start} out of bounds for filtered length {}",
                                filtered.len()
                            ));
                        }
                        filtered.len() - start
                    }
                    UniquePos::Anywhere => filtered.len(),
                },
                None => n_slots,
            };
            let rel = select_indices_for_pos(filtered.len(), &pos, k, "MultiBagSpec pool")?;
            rel.into_iter().map(|idx| filtered[idx]).collect()
        }
    };

    #[derive(Clone)]
    struct Slot {
        bag_idx: usize,
        key: String,
    }

    let mut slots: Vec<Slot> = Vec::new();
    for (bag_idx, keys) in resolved_expected_by_bag.iter().enumerate() {
        for key in keys {
            slots.push(Slot {
                bag_idx,
                key: key.clone(),
            });
        }
    }

    let assignment: Vec<usize> = if slots.is_empty() {
        Vec::new()
    } else {
        let mut slot_candidates: Vec<Vec<usize>> = Vec::with_capacity(slots.len());
        for (slot_idx, slot) in slots.iter().enumerate() {
            let bag = &bags[slot.bag_idx];
            let mut candidates = Vec::new();
            for (pool_pos, dep_idx) in pool_indices.iter().enumerate() {
                let dep = &deps[*dep_idx];
                if !bag.pred.matches(dep) {
                    continue;
                }
                let Some(key) = bag.key_selector.key_of(dep) else {
                    continue;
                };
                if key == slot.key {
                    candidates.push(pool_pos);
                }
            }
            if candidates.is_empty() {
                return Err(format!(
                    "MultiBagSpec missing candidates for bag {:?} slot {} key {:?}",
                    bag.name, slot_idx, slot.key
                ));
            }
            slot_candidates.push(candidates);
        }
        solve_unique_slot_matching(&slot_candidates)?
    };

    let mut bindings = bags
        .iter()
        .map(|bag| BagBinding {
            name: bag.name.clone(),
            matched: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut matched_pool_positions = BTreeSet::new();
    let mut matched_indices = Vec::with_capacity(assignment.len());

    for (slot_idx, pool_pos) in assignment.iter().enumerate() {
        let slot = &slots[slot_idx];
        let dep_idx = pool_indices[*pool_pos];
        matched_indices.push(dep_idx);
        matched_pool_positions.insert(*pool_pos);
        bindings[slot.bag_idx].matched.push(deps[dep_idx].clone());
    }

    if consume_all {
        for (pool_pos, dep_idx) in pool_indices.iter().enumerate() {
            if matched_pool_positions.contains(&pool_pos) {
                continue;
            }
            let dep = &deps[*dep_idx];
            let in_domain = if let Some(domain) = domain_pred {
                domain.matches(dep)
            } else {
                bags.iter().any(|bag| bag.pred.matches(dep))
            };
            if in_domain {
                return Err(format!(
                    "MultiBagSpec(consume_all) rejected unused in-domain dep at pool index {pool_pos} (dep index {dep_idx})"
                ));
            }
        }
    }

    let selected_set: BTreeSet<usize> = matched_indices.iter().copied().collect();
    let remaining = remaining_without_indices(deps, &selected_set);

    Ok(MultiBagMatch {
        pool_indices,
        matched_indices,
        bindings,
        remaining,
    })
}

fn select_indices_for_pos(
    len: usize,
    pos: &UniquePos,
    k: usize,
    label: &str,
) -> Result<Vec<usize>, String> {
    match pos {
        UniquePos::First => {
            if k > len {
                return Err(format!(
                    "{label}(first) requires {k} deps but only {len} available"
                ));
            }
            Ok((0..k).collect())
        }
        UniquePos::Last => {
            if k > len {
                return Err(format!(
                    "{label}(last) requires {k} deps but only {len} available"
                ));
            }
            Ok(((len - k)..len).collect())
        }
        UniquePos::Index(start) => {
            if *start > len {
                return Err(format!(
                    "{label}(index={start}) out of bounds for length {len}"
                ));
            }
            let end = start.saturating_add(k);
            if end > len {
                return Err(format!(
                    "{label}(index={start}) with len={k} exceeds available length {len}"
                ));
            }
            Ok((*start..end).collect())
        }
        UniquePos::Anywhere => Err(format!(
            "{label}(anywhere) is not a slice position for fixed-length selection"
        )),
    }
}

fn remaining_without_indices(deps: &[DepShape], selected: &BTreeSet<usize>) -> Vec<DepShape> {
    let mut remaining = Vec::with_capacity(deps.len().saturating_sub(selected.len()));
    for (idx, dep) in deps.iter().enumerate() {
        if !selected.contains(&idx) {
            remaining.push(dep.clone());
        }
    }
    remaining
}

fn counts(values: &[String]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for value in values {
        *out.entry(value.clone()).or_insert(0usize) += 1;
    }
    out
}

fn search_ordered_subsequence_solutions(
    deps: &[DepShape],
    pred: &UniquePred,
    key_selector: &KeySelector,
    expected_keys: &[String],
    start_dep: usize,
    key_idx: usize,
    current: &mut Vec<usize>,
    solutions: &mut Vec<Vec<usize>>,
    max_solutions: usize,
) {
    if solutions.len() >= max_solutions {
        return;
    }
    if key_idx >= expected_keys.len() {
        solutions.push(current.clone());
        return;
    }
    let needle = &expected_keys[key_idx];
    for dep_idx in start_dep..deps.len() {
        if !pred.matches(&deps[dep_idx]) {
            continue;
        }
        let Some(key) = key_selector.key_of(&deps[dep_idx]) else {
            continue;
        };
        if &key != needle {
            continue;
        }
        current.push(dep_idx);
        search_ordered_subsequence_solutions(
            deps,
            pred,
            key_selector,
            expected_keys,
            dep_idx + 1,
            key_idx + 1,
            current,
            solutions,
            max_solutions,
        );
        current.pop();
        if solutions.len() >= max_solutions {
            return;
        }
    }
}

fn solve_unique_slot_matching(slot_candidates: &[Vec<usize>]) -> Result<Vec<usize>, String> {
    let mut assignment: Vec<Option<usize>> = vec![None; slot_candidates.len()];
    let mut used = BTreeSet::new();
    let mut solutions: Vec<Vec<usize>> = Vec::new();
    search_slot_matching(
        slot_candidates,
        &mut assignment,
        &mut used,
        &mut solutions,
        2,
    );

    if solutions.is_empty() {
        return Err("MultiBagSpec could not satisfy required slot matching".to_string());
    }
    if solutions.len() > 1 {
        return Err("MultiBagSpec is ambiguous: multiple exact matchings exist".to_string());
    }
    Ok(solutions.remove(0))
}

fn search_slot_matching(
    slot_candidates: &[Vec<usize>],
    assignment: &mut [Option<usize>],
    used: &mut BTreeSet<usize>,
    solutions: &mut Vec<Vec<usize>>,
    max_solutions: usize,
) {
    if solutions.len() >= max_solutions {
        return;
    }

    let mut best_slot: Option<usize> = None;
    let mut best_available: Vec<usize> = Vec::new();

    for slot_idx in 0..assignment.len() {
        if assignment[slot_idx].is_some() {
            continue;
        }
        let available: Vec<usize> = slot_candidates[slot_idx]
            .iter()
            .copied()
            .filter(|dep| !used.contains(dep))
            .collect();
        if available.is_empty() {
            return;
        }
        if best_slot
            .map(|_| available.len() < best_available.len())
            .unwrap_or(true)
        {
            best_slot = Some(slot_idx);
            best_available = available;
            if best_available.len() == 1 {
                break;
            }
        }
    }

    let Some(slot_idx) = best_slot else {
        let solution = assignment
            .iter()
            .map(|v| v.expect("all slots assigned"))
            .collect::<Vec<_>>();
        solutions.push(solution);
        return;
    };

    for dep in best_available {
        assignment[slot_idx] = Some(dep);
        used.insert(dep);
        search_slot_matching(slot_candidates, assignment, used, solutions, max_solutions);
        used.remove(&dep);
        assignment[slot_idx] = None;
        if solutions.len() >= max_solutions {
            return;
        }
    }
}

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::resolver::{context_key, Input};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextMode {
    FullOnly,
    Partial,
    FromContracts,
}

fn dedup_and_sort(mut inputs: Vec<Input>) -> Vec<Input> {
    let mut seen = HashSet::new();
    inputs.retain(|i| seen.insert(context_key(i)));
    inputs.sort_by_key(context_key);
    inputs
}

pub fn full_inputs(axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
    let axis_names: Vec<String> = axes.keys().cloned().collect();
    let mut out: Vec<Input> = Vec::new();

    fn go(
        depth: usize,
        axis_names: &[String],
        axes: &BTreeMap<String, Vec<String>>,
        cur: &mut Input,
        out: &mut Vec<Input>,
    ) {
        if depth == axis_names.len() {
            out.push(cur.clone());
            return;
        }
        let axis = &axis_names[depth];
        if let Some(vals) = axes.get(axis) {
            for v in vals {
                cur.insert(axis.clone(), v.clone());
                go(depth + 1, axis_names, axes, cur, out);
                cur.remove(axis);
            }
        }
    }

    go(0, &axis_names, axes, &mut Input::new(), &mut out);
    dedup_and_sort(out)
}

pub fn partial_inputs(axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
    let axis_names: Vec<String> = axes.keys().cloned().collect();
    let mut out: Vec<Input> = Vec::new();

    fn go(
        depth: usize,
        axis_names: &[String],
        axes: &BTreeMap<String, Vec<String>>,
        cur: &mut Input,
        out: &mut Vec<Input>,
    ) {
        if depth == axis_names.len() {
            out.push(cur.clone());
            return;
        }
        let axis = &axis_names[depth];
        // Axis absent.
        go(depth + 1, axis_names, axes, cur, out);
        // Axis present.
        if let Some(vals) = axes.get(axis) {
            for v in vals {
                cur.insert(axis.clone(), v.clone());
                go(depth + 1, axis_names, axes, cur, out);
                cur.remove(axis);
            }
        }
    }

    go(0, &axis_names, axes, &mut Input::new(), &mut out);
    dedup_and_sort(out)
}

pub fn layered_inputs(
    axes: &BTreeMap<String, Vec<String>>,
    relevant_axes: Option<&BTreeSet<String>>,
) -> Vec<Input> {
    let mut selected_axes: Vec<String> = match relevant_axes {
        Some(sel) => sel
            .iter()
            .filter(|a| axes.contains_key(*a))
            .cloned()
            .collect(),
        None => axes.keys().cloned().collect(),
    };
    selected_axes.sort();

    let mut out: Vec<Input> = vec![Input::new()]; // base

    for axis in &selected_axes {
        if let Some(vals) = axes.get(axis) {
            for v in vals {
                let mut input = Input::new();
                input.insert(axis.clone(), v.clone());
                out.push(input);
            }
        }
    }

    for i in 0..selected_axes.len() {
        for j in (i + 1)..selected_axes.len() {
            let a = &selected_axes[i];
            let b = &selected_axes[j];
            let vals_a = axes.get(a).cloned().unwrap_or_default();
            let vals_b = axes.get(b).cloned().unwrap_or_default();
            for va in &vals_a {
                for vb in &vals_b {
                    let mut input = Input::new();
                    input.insert(a.clone(), va.clone());
                    input.insert(b.clone(), vb.clone());
                    out.push(input);
                }
            }
        }
    }

    dedup_and_sort(out)
}

pub fn plan_inputs(
    mode: ContextMode,
    axes: &BTreeMap<String, Vec<String>>,
    relevant_axes: Option<&BTreeSet<String>>,
) -> Vec<Input> {
    match mode {
        ContextMode::FullOnly => full_inputs(axes),
        ContextMode::Partial => partial_inputs(axes),
        ContextMode::FromContracts => layered_inputs(axes, relevant_axes),
    }
}

use std::collections::BTreeSet;

use crate::cert::CtcWitnesses;
use crate::compose::ComposeWitnesses;
use crate::ids::WitnessId;
use crate::provenance::TokenProvenance;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ExplainLocation {
    pack: Option<String>,
    file_path: String,
    json_pointer: String,
}

fn loc_from_provenance(p: &TokenProvenance) -> Option<ExplainLocation> {
    let file_path = p.file_path.clone()?;
    let json_pointer = p.json_pointer.clone()?;
    Some(ExplainLocation {
        pack: p.pack_id.clone(),
        file_path,
        json_pointer,
    })
}

fn render_locations(locations: Vec<ExplainLocation>) -> String {
    if locations.is_empty() {
        return "Primary location: (none)\n".to_string();
    }
    let mut uniq: BTreeSet<ExplainLocation> = BTreeSet::new();
    for l in locations {
        uniq.insert(l);
    }
    let mut out = String::new();
    let first = uniq.iter().next().expect("non-empty");
    out.push_str("Primary location:\n");
    out.push_str(&format!("  {} {}\n", first.file_path, first.json_pointer));
    if let Some(pack) = &first.pack {
        out.push_str(&format!("  pack: {pack}\n"));
    }
    if uniq.len() > 1 {
        out.push_str("Other candidate locations:\n");
        for l in uniq.iter().skip(1).take(5) {
            out.push_str(&format!("  {} {}\n", l.file_path, l.json_pointer));
        }
        if uniq.len() > 6 {
            out.push_str(&format!("  ... {} more\n", uniq.len() - 6));
        }
    }
    out
}

pub fn explain_ctc_witness(
    witnesses: &CtcWitnesses,
    witness_id: &WitnessId,
    witness_file: &str,
) -> Option<String> {
    for w in &witnesses.gaps {
        if w.witness_id == witness_id.as_str() {
            let mut locs = Vec::new();
            for s in &w.authored_sources {
                locs.push(ExplainLocation {
                    pack: Some(s.pack_id.clone()),
                    file_path: s.file_path.clone(),
                    json_pointer: s.json_pointer.clone(),
                });
            }
            let mut out = String::new();
            out.push_str(&format!(
                "Witness: {}\nType: gap\nSource: {}\n\n",
                w.witness_id, witness_file
            ));
            out.push_str(&format!(
                "Summary: Kan gap for `{}` at `{}`.\n\n",
                w.token_path, w.target
            ));
            out.push_str(&render_locations(locs));
            out.push('\n');
            out.push_str("Fix recipe:\n");
            out.push_str(&format!(
                "  Add an explicit value for `{}` at `{}` in the intended winning layer.\n",
                w.token_path, w.target
            ));
            return Some(out);
        }
    }

    for w in &witnesses.conflicts {
        if w.witness_id == witness_id.as_str() {
            let mut locs = Vec::new();
            for c in &w.candidates {
                locs.push(ExplainLocation {
                    pack: Some(c.pack_id.clone()),
                    file_path: c.file_path.clone(),
                    json_pointer: c.json_pointer.clone(),
                });
            }
            let mut out = String::new();
            out.push_str(&format!(
                "Witness: {}\nType: conflict\nSource: {}\n\n",
                w.witness_id, witness_file
            ));
            out.push_str(&format!(
                "Summary: Kan conflict for `{}` at `{}`.\n\n",
                w.token_path, w.target
            ));
            out.push_str(&render_locations(locs));
            out.push('\n');
            out.push_str("Fix recipe:\n");
            out.push_str(&format!(
                "  Add an explicit override for `{}` at `{}` to remove tie-break ambiguity.\n",
                w.token_path, w.target
            ));
            return Some(out);
        }
    }

    for w in &witnesses.inherited {
        if w.witness_id == witness_id.as_str() {
            let mut locs = Vec::new();
            for s in &w.sources {
                locs.push(ExplainLocation {
                    pack: Some(s.pack_id.clone()),
                    file_path: s.file_path.clone(),
                    json_pointer: s.json_pointer.clone(),
                });
            }
            let mut out = String::new();
            out.push_str(&format!(
                "Witness: {}\nType: inherited\nSource: {}\n\n",
                w.witness_id, witness_file
            ));
            out.push_str(&format!(
                "Summary: `{}` at `{}` is inherited from `{}`.\n\n",
                w.token_path,
                w.target,
                w.inherited_from.join(", ")
            ));
            out.push_str(&render_locations(locs));
            out.push('\n');
            out.push_str("Fix recipe:\n");
            out.push_str(&format!(
                "  Keep inheritance if intended, or author `{}` explicitly at `{}`.\n",
                w.token_path, w.target
            ));
            return Some(out);
        }
    }

    for w in &witnesses.bc_violations {
        if w.witness_id == witness_id.as_str() {
            let mut locs = Vec::new();
            if let Some(p) = &w.left_source {
                if let Some(l) = loc_from_provenance(p) {
                    locs.push(l);
                }
            }
            if let Some(p) = &w.right_source {
                if let Some(l) = loc_from_provenance(p) {
                    locs.push(l);
                }
            }
            let mut out = String::new();
            out.push_str(&format!(
                "Witness: {}\nType: bcViolation\nSource: {}\n\n",
                w.witness_id, witness_file
            ));
            out.push_str(&format!(
                "Summary: Beck-Chevalley violation for `{}` at `{}:{}, {}:{}`.\n\n",
                w.token_path, w.axis_a, w.value_a, w.axis_b, w.value_b
            ));
            out.push_str(&render_locations(locs));
            out.push('\n');
            out.push_str("Fix recipe:\n");
            out.push_str(&format!("  {}\n", w.fix));
            return Some(out);
        }
    }

    for w in &witnesses.orthogonality {
        if w.witness_id == witness_id.as_str() {
            let mut out = String::new();
            out.push_str(&format!(
                "Witness: {}\nType: orthogonality\nSource: {}\n\n",
                w.witness_id, witness_file
            ));
            out.push_str(&format!(
                "Summary: Axes `{}` and `{}` overlap on {} token paths.\n\n",
                w.axis_a,
                w.axis_b,
                w.overlap_token_paths.len()
            ));
            out.push_str("Primary location: (none)\n\n");
            out.push_str("Fix recipe:\n");
            out.push_str(
                "  Partition token ownership so each overlapping path is authored by one axis.\n",
            );
            return Some(out);
        }
    }

    None
}

pub fn explain_compose_witness(
    witnesses: &ComposeWitnesses,
    witness_id: &WitnessId,
    witness_file: &str,
) -> Option<String> {
    for w in &witnesses.conflicts {
        if w.witness_id != *witness_id {
            continue;
        }
        let mut locs = Vec::new();
        for c in &w.candidates {
            for s in &c.sources {
                if let Some(l) = loc_from_provenance(&s.provenance) {
                    locs.push(l);
                }
            }
        }
        let mut out = String::new();
        out.push_str(&format!(
            "Witness: {}\nType: composeConflict\nSource: {}\n\n",
            w.witness_id, witness_file
        ));
        out.push_str(&format!(
            "Summary: Cross-pack conflict for `{}` at `{}` (winner: `{}`).\n\n",
            w.token_path, w.context, w.winner_pack
        ));
        out.push_str(&render_locations(locs));
        out.push('\n');
        out.push_str("Fix recipe:\n");
        out.push_str(&format!(
            "  Author `{}` explicitly at `{}` in the intended winner pack, or remove competing definitions in lower-priority packs.\n",
            w.token_path, w.context
        ));
        return Some(out);
    }
    None
}

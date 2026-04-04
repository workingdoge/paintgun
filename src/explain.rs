use std::collections::BTreeSet;

use crate::cert::CtcWitnesses;
use crate::compose::ComposeWitnesses;
use crate::finding_presentation::{presentation_for_kind, FindingPresentation};
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

fn explain_header(
    witness_id: &str,
    witness_file: &str,
    presentation: FindingPresentation,
    summary: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Finding: {}\nTechnical kind: {}\nSeverity: {}\nFixability: {}\nWitness: {}\nSource: {}\n\n",
        presentation.family_label,
        presentation.technical_kind,
        presentation.severity,
        presentation.fixability,
        witness_id,
        witness_file
    ));
    out.push_str("What it means:\n");
    out.push_str(&format!("  {}\n\n", presentation.meaning));
    out.push_str(&format!("Summary: {summary}\n\n"));
    out
}

fn explain_footer(out: &mut String, cause: &str, next_action: &str) {
    out.push('\n');
    out.push_str("Why this happened:\n");
    out.push_str(&format!("  {cause}\n\n"));
    out.push_str("Next action:\n");
    out.push_str(&format!("  {next_action}\n"));
}

pub fn explain_ctc_witness(
    witnesses: &CtcWitnesses,
    witness_id: &WitnessId,
    witness_file: &str,
) -> Option<String> {
    for w in &witnesses.gaps {
        if w.witness_id == witness_id.as_str() {
            let presentation = presentation_for_kind("gap").expect("gap presentation");
            let mut locs = Vec::new();
            for s in &w.authored_sources {
                locs.push(ExplainLocation {
                    pack: Some(s.pack_id.clone()),
                    file_path: s.file_path.clone(),
                    json_pointer: s.json_pointer.clone(),
                });
            }
            let mut out = explain_header(
                &w.witness_id,
                witness_file,
                presentation,
                &format!(
                    "No explicit winning value exists for `{}` at `{}`.",
                    w.token_path, w.target
                ),
            );
            out.push_str(&render_locations(locs));
            explain_footer(
                &mut out,
                &format!(
                    "Paint walked the available authored layers for `{}` at `{}` and found no explicit winner there.",
                    w.token_path, w.target
                ),
                &format!(
                    "Add an explicit value for `{}` at `{}` in the intended winning layer.",
                    w.token_path, w.target
                ),
            );
            return Some(out);
        }
    }

    for w in &witnesses.conflicts {
        if w.witness_id == witness_id.as_str() {
            let presentation = presentation_for_kind("conflict").expect("conflict presentation");
            let mut locs = Vec::new();
            for c in &w.candidates {
                locs.push(ExplainLocation {
                    pack: Some(c.pack_id.clone()),
                    file_path: c.file_path.clone(),
                    json_pointer: c.json_pointer.clone(),
                });
            }
            let mut out = explain_header(
                &w.witness_id,
                witness_file,
                presentation,
                &format!(
                    "Multiple authored definitions compete for `{}` at `{}`.",
                    w.token_path, w.target
                ),
            );
            out.push_str(&render_locations(locs));
            explain_footer(
                &mut out,
                &format!(
                    "More than one explicit candidate can win for `{}` at `{}`, so the result is not a clean authored choice.",
                    w.token_path, w.target
                ),
                &format!(
                    "Add an explicit override for `{}` at `{}` to make the intended winner unambiguous.",
                    w.token_path, w.target
                ),
            );
            return Some(out);
        }
    }

    for w in &witnesses.inherited {
        if w.witness_id == witness_id.as_str() {
            let presentation = presentation_for_kind("inherited").expect("inherited presentation");
            let mut locs = Vec::new();
            for s in &w.sources {
                locs.push(ExplainLocation {
                    pack: Some(s.pack_id.clone()),
                    file_path: s.file_path.clone(),
                    json_pointer: s.json_pointer.clone(),
                });
            }
            let mut out = explain_header(
                &w.witness_id,
                witness_file,
                presentation,
                &format!(
                    "`{}` at `{}` inherits its value from `{}`.",
                    w.token_path,
                    w.target,
                    w.inherited_from.join(", ")
                ),
            );
            out.push_str(&render_locations(locs));
            explain_footer(
                &mut out,
                &format!(
                    "No explicit authored value wins at `{}`, so Paint traces the resolved value back to `{}`.",
                    w.target,
                    w.inherited_from.join(", ")
                ),
                &format!(
                    "Keep the inheritance if it is intended, or author `{}` explicitly at `{}`.",
                    w.token_path, w.target
                ),
            );
            return Some(out);
        }
    }

    for w in &witnesses.bc_violations {
        if w.witness_id == witness_id.as_str() {
            let presentation =
                presentation_for_kind("bcViolation").expect("bc violation presentation");
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
            let mut out = explain_header(
                &w.witness_id,
                witness_file,
                presentation,
                &format!(
                    "Evaluation order changes the resolved value for `{}` at `{}:{}, {}:{}`.",
                    w.token_path, w.axis_a, w.value_a, w.axis_b, w.value_b
                ),
            );
            out.push_str(&render_locations(locs));
            explain_footer(
                &mut out,
                &format!(
                    "Resolving `{}` through {} -> {} does not match resolving it through {} -> {}.",
                    w.token_path, w.axis_a, w.axis_b, w.axis_b, w.axis_a
                ),
                &w.fix,
            );
            return Some(out);
        }
    }

    for w in &witnesses.orthogonality {
        if w.witness_id == witness_id.as_str() {
            let presentation =
                presentation_for_kind("orthogonality").expect("orthogonality presentation");
            let mut out = explain_header(
                &w.witness_id,
                witness_file,
                presentation,
                &format!(
                    "Axes `{}` and `{}` overlap on {} token paths.",
                    w.axis_a,
                    w.axis_b,
                    w.overlap_token_paths.len()
                ),
            );
            out.push_str("Primary location: (none)\n\n");
            explain_footer(
                &mut out,
                &format!(
                    "Both axes appear to claim responsibility for the same token paths, which creates governance ambiguity even if the build still resolves.",
                ),
                "Partition token ownership so each overlapping path is authored by one axis.",
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
        let presentation =
            presentation_for_kind("composeConflict").expect("compose conflict presentation");
        let mut locs = Vec::new();
        for c in &w.candidates {
            for s in &c.sources {
                if let Some(l) = loc_from_provenance(&s.provenance) {
                    locs.push(l);
                }
            }
        }
        let mut out = explain_header(
            w.witness_id.as_str(),
            witness_file,
            presentation,
            &format!(
                "Multiple packs compete for `{}` at `{}` (current winner: `{}`).",
                w.token_path, w.context, w.winner_pack
            ),
        );
        out.push_str(&render_locations(locs));
        explain_footer(
            &mut out,
            &format!(
                "Pack order is currently deciding the winner for `{}` at `{}`, which means the composed result is not a clean cross-pack contract.",
                w.token_path, w.context
            ),
            &format!(
                "Author `{}` explicitly at `{}` in the intended winner pack, or remove competing definitions in lower-priority packs.",
                w.token_path, w.context
            ),
        );
        return Some(out);
    }
    None
}

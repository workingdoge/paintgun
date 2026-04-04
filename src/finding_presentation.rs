#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingPresentation {
    pub family_id: &'static str,
    pub family_label: &'static str,
    pub technical_kind: &'static str,
    pub severity: &'static str,
    pub fixability: &'static str,
    pub meaning: &'static str,
    pub next_action: &'static str,
}

pub fn presentation_for_kind(kind: &str) -> Option<FindingPresentation> {
    match kind {
        "gap" => Some(FindingPresentation {
            family_id: "missing-definition",
            family_label: "Missing definition",
            technical_kind: "gap",
            severity: "error",
            fixability: "direct",
            meaning: "Paint expected a winning value at this context, but no explicit definition wins here.",
            next_action: "Author an explicit value in the intended winning layer or context.",
        }),
        "conflict" => Some(FindingPresentation {
            family_id: "ambiguous-definition",
            family_label: "Ambiguous definition",
            technical_kind: "conflict",
            severity: "error",
            fixability: "direct",
            meaning: "Multiple authored definitions compete for the same token/context.",
            next_action: "Make the intended winner explicit, or remove/narrow the competing definitions.",
        }),
        "composeConflict" => Some(FindingPresentation {
            family_id: "ambiguous-definition",
            family_label: "Ambiguous definition (cross-pack)",
            technical_kind: "composeConflict",
            severity: "error",
            fixability: "direct",
            meaning: "Multiple packs compete to define the same token/context.",
            next_action: "Author the value explicitly in the intended winner pack, or remove competing definitions in lower-priority packs.",
        }),
        "bcViolation" => Some(FindingPresentation {
            family_id: "order-dependent-resolution",
            family_label: "Order-dependent resolution",
            technical_kind: "bcViolation",
            severity: "error",
            fixability: "guided",
            meaning: "The resolved result changes depending on evaluation order.",
            next_action: "Normalize the authoring so the same result is produced regardless of traversal or composition order.",
        }),
        "orthogonality" => Some(FindingPresentation {
            family_id: "ownership-overlap",
            family_label: "Ownership overlap",
            technical_kind: "orthogonality",
            severity: "warn",
            fixability: "review",
            meaning: "Multiple axes or domains appear to own the same token paths.",
            next_action: "Partition ownership, or make the overlap intentional and documented.",
        }),
        "inherited" => Some(FindingPresentation {
            family_id: "inherited-value",
            family_label: "Inherited value",
            technical_kind: "inherited",
            severity: "info",
            fixability: "trace",
            meaning: "The value here is inherited rather than authored explicitly at this location.",
            next_action: "Keep the inheritance if it is intended, or author the value explicitly here.",
        }),
        _ => None,
    }
}

pub fn severity_heading(severity: &str) -> &'static str {
    match severity {
        "error" => "Errors requiring action",
        "warn" => "Warnings to review",
        _ => "Informational traces",
    }
}

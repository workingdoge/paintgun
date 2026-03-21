use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use crate::analysis::PartialAssignment;
use crate::cert::{
    analyze_composability_with_mode_and_contexts, build_assignments, build_explicit_index,
    ConflictMode, CtcAnalysis,
};
use crate::contexts::{plan_inputs, ContextMode};
use crate::gate::{evaluate_from_analysis, GateWitnesses};
use crate::ids::TokenPathId;
use crate::policy::Policy;
use crate::provenance::TokenProvenance;
use crate::resolver::{parse_context_key, Input, ResolverDoc, ResolverError, TokenStore};

/// Request for a typed full-profile pipeline execution.
pub struct FullProfilePipelineRequest<'a> {
    pub doc: &'a ResolverDoc,
    pub store: &'a TokenStore,
    pub resolver_path: &'a Path,
    pub conflict_mode: ConflictMode,
    pub policy: &'a Policy,
    pub context_mode: ContextMode,
    pub contract_tokens: Option<&'a BTreeSet<TokenPathId>>,
}

/// Resolve stage output (authored surface index over a resolved token store).
pub struct ResolveStage<'a> {
    pub store: &'a TokenStore,
    pub explicit: HashMap<String, HashMap<String, TokenProvenance>>,
}

/// Bidirectional stage output (authored assignments + planned checking contexts).
pub struct BidirStage {
    pub assignments: Vec<PartialAssignment>,
    pub contexts: Vec<Input>,
}

/// Admissibility stage output (composability analysis + full-profile witnesses).
pub struct AdmissibilityStage {
    pub analysis: CtcAnalysis,
    pub witnesses: GateWitnesses,
}

/// Typed full-profile execution pipeline result.
pub struct FullProfilePipeline<'a> {
    pub resolve: ResolveStage<'a>,
    pub bidir: BidirStage,
    pub admissibility: AdmissibilityStage,
}

fn filter_assignments_for_contract_tokens(
    assignments: &mut Vec<PartialAssignment>,
    contract_tokens: Option<&BTreeSet<TokenPathId>>,
) {
    if let Some(tokens) = contract_tokens {
        assignments.retain(|a| tokens.contains(a.token_path.as_str()));
    }
}

fn relevant_axes_from_assignments(assignments: &[PartialAssignment]) -> Option<BTreeSet<String>> {
    let mut axes = BTreeSet::new();
    for asn in assignments {
        for ctx_key in asn.entries.keys() {
            let ctx = parse_context_key(ctx_key);
            for axis in ctx.keys() {
                axes.insert(axis.clone());
            }
        }
    }
    if axes.is_empty() {
        None
    } else {
        Some(axes)
    }
}

/// Execute the full-profile typed pipeline:
/// resolve index -> bidirectional authored/checking split -> admissibility.
///
/// This is an architecture seam that keeps stage boundaries explicit while
/// preserving existing runtime semantics.
pub fn run_full_profile_pipeline(
    req: FullProfilePipelineRequest<'_>,
) -> Result<FullProfilePipeline<'_>, ResolverError> {
    let explicit = build_explicit_index(req.doc, req.store, req.resolver_path)?;

    let mut assignments = build_assignments(req.store, &explicit);
    filter_assignments_for_contract_tokens(&mut assignments, req.contract_tokens);

    let relevant_axes = if req.context_mode == ContextMode::FromContracts {
        relevant_axes_from_assignments(&assignments)
    } else {
        None
    };
    let contexts = plan_inputs(req.context_mode, &req.store.axes, relevant_axes.as_ref());
    let contract_token_strings = req.contract_tokens.map(|tokens| {
        tokens
            .iter()
            .map(|t| t.as_str().to_string())
            .collect::<BTreeSet<_>>()
    });

    let analysis = analyze_composability_with_mode_and_contexts(
        req.doc,
        req.store,
        req.resolver_path,
        req.conflict_mode,
        req.policy,
        req.context_mode,
        contract_token_strings.as_ref(),
    )?;
    let witnesses = evaluate_from_analysis(&analysis, &assignments, &req.store.axes, &contexts);

    Ok(FullProfilePipeline {
        resolve: ResolveStage {
            store: req.store,
            explicit,
        },
        bidir: BidirStage {
            assignments,
            contexts,
        },
        admissibility: AdmissibilityStage {
            analysis,
            witnesses,
        },
    })
}

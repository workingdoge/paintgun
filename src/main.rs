use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use paintgun::allowlist::{
    generate_allowlist, Allowlist, AllowlistMatcherMode, DEFAULT_ALLOWLIST_REASON_TEMPLATE,
};
use paintgun::annotations::{build_github_annotations, read_report};
use paintgun::artifact::write_resolved_json;
use paintgun::backend::{
    resolve_target_backend, supported_target_names, BackendArtifact, BackendArtifactKind,
    BackendEmission, BackendRequest, BackendSource, LegacyTargetSlot, TargetBackend,
};
use paintgun::cache::{
    check_stage_cache, current_executable_fingerprint, fingerprint_file, write_stage_cache,
    ExecutableFingerprint, FileFingerprint, StageCacheStatus,
};
use paintgun::cert::{
    analyze_composability_with_mode_and_contexts, build_assignments, build_authored_export,
    build_ctc_manifest, build_explicit_index, build_manifest_rel, render_validation_report,
    required_artifact_binding, BackendArtifactDescriptor, BackendArtifactDescriptorKind,
    ConflictMode, CtcManifest, ManifestEntry, NativeApiVersions, RequiredArtifactKind,
    NORMALIZER_VERSION,
};
use paintgun::compose::{
    analyze_cross_pack_conflicts_with_mode_and_contexts, build_compose_manifest_with_context_count,
    compose_store_with_context_mode, load_pack, relevant_axes_for_contract_tokens,
    render_compose_report, union_axes, verify_compose_with_signing, ComposeManifest,
};
use paintgun::diagnostics::build_editor_diagnostics_projection_json;
use paintgun::emit::Contract;
use paintgun::explain::{explain_compose_witness, explain_ctc_witness};
use paintgun::gate::GateResult;
use paintgun::ids::{TokenPathId, WitnessId};
use paintgun::kcir_v2::{
    kcir_profile_binding_for_scheme_and_wire, KcirProfileBinding, ProfileAnchors, HASH_SCHEME_ID,
};
use paintgun::pipeline::{run_full_profile_pipeline, FullProfilePipelineRequest};
use paintgun::policy::Policy;
use paintgun::resolver::{
    axes_from_doc, axes_relevant_to_tokens, build_token_store_for_inputs, context_key,
    read_json_file, supporting_inputs_for_selection, Input, ResolverDoc, ResolverError,
};
use paintgun::signing::sign_manifest_file;
use paintgun::specpub::{build_spec_pack, verify_spec_pack};
use paintgun::verify::{verify_ctc_with_options, CtcVerifyOptions, VerifyProfile};

#[derive(Debug)]
struct CliError(String);

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

type CliResult<T> = Result<T, CliError>;

#[derive(serde::Serialize)]
struct BuildStageFingerprint {
    executable: ExecutableFingerprint,
    backend_id: String,
    conflict_mode: String,
    format: String,
    context_mode: String,
    planner_trace: bool,
    profile: String,
    kcir_wire_format_id: String,
    resolver: FileFingerprint,
    external_sources: Vec<FileFingerprint>,
    contracts: Option<FileFingerprint>,
    policy: Option<FileFingerprint>,
}

#[derive(serde::Serialize)]
struct ComposePackFingerprint {
    dir: String,
    manifest: FileFingerprint,
    witnesses: FileFingerprint,
    resolved: FileFingerprint,
    authored: Option<FileFingerprint>,
}

#[derive(serde::Serialize)]
struct ComposeStageFingerprint {
    executable: ExecutableFingerprint,
    backend_id: String,
    conflict_mode: String,
    format: String,
    context_mode: String,
    planner_trace: bool,
    verify_packs: bool,
    require_packs_composable: bool,
    require_composable: bool,
    contracts: Option<FileFingerprint>,
    policy: Option<FileFingerprint>,
    packs: Vec<ComposePackFingerprint>,
}

#[derive(Parser, Debug)]
#[command(name = "paint", version)]
#[command(about = "DTCG 2025.10 resolver + composability certificates", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliConflictMode {
    Semantic,
    Normalized,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliContexts {
    FullOnly,
    Partial,
    FromContracts,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliProfile {
    Core,
    Full,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliAllowlistMatcher {
    WitnessId,
    Selector,
}

impl From<CliConflictMode> for ConflictMode {
    fn from(value: CliConflictMode) -> Self {
        match value {
            CliConflictMode::Semantic => ConflictMode::Semantic,
            CliConflictMode::Normalized => ConflictMode::Normalized,
        }
    }
}

impl From<CliContexts> for paintgun::contexts::ContextMode {
    fn from(value: CliContexts) -> Self {
        match value {
            CliContexts::FullOnly => paintgun::contexts::ContextMode::FullOnly,
            CliContexts::Partial => paintgun::contexts::ContextMode::Partial,
            CliContexts::FromContracts => paintgun::contexts::ContextMode::FromContracts,
        }
    }
}

impl From<CliProfile> for VerifyProfile {
    fn from(value: CliProfile) -> Self {
        match value {
            CliProfile::Core => VerifyProfile::Core,
            CliProfile::Full => VerifyProfile::Full,
        }
    }
}

impl From<CliAllowlistMatcher> for AllowlistMatcherMode {
    fn from(value: CliAllowlistMatcher) -> Self {
        match value {
            CliAllowlistMatcher::WitnessId => AllowlistMatcherMode::WitnessId,
            CliAllowlistMatcher::Selector => AllowlistMatcherMode::Selector,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Package site-owned specs into a Paintgun spec publication pack.
    SpecPack {
        /// Path to an atlas.spec-publication.v1 manifest.
        manifest: PathBuf,

        /// Output directory for spec.index.json, spec.pack.json, and copied sources.
        #[arg(short, long, default_value = "dist-spec")]
        out: PathBuf,
    },

    /// Verify a Paintgun spec publication pack.
    VerifySpecPack {
        /// Path to spec.pack.json.
        manifest: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = CliFormat::Text)]
        format: CliFormat,
    },

    /// Build a single token pack: resolve, emit, and produce the per-pack CTC.
    Build {
        /// Path to *.resolver.json
        resolver: PathBuf,

        /// Path to component-contracts.json (required for --target web-css-vars or alias css)
        #[arg(long)]
        contracts: Option<PathBuf>,

        /// Output directory
        #[arg(short, long, default_value = "dist")]
        out: PathBuf,

        /// Target backend (built-ins: web-css-vars | swift-tokens | android-compose-tokens | web-tokens-ts; aliases: css | swift | kotlin)
        #[arg(long, default_value = "web-css-vars")]
        target: String,

        /// Optional policy JSON (normalization + emission preferences)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Conflict comparator mode for certificates: semantic intent vs normalized observable output.
        #[arg(long, value_enum, default_value_t = CliConflictMode::Semantic)]
        conflict_mode: CliConflictMode,

        /// Output report format.
        #[arg(long, value_enum, default_value_t = CliFormat::Text)]
        format: CliFormat,

        /// Context evaluation scope: full intersections, full partial lattice, or contract-bounded layering contexts.
        #[arg(long, value_enum, default_value_t = CliContexts::FullOnly)]
        contexts: CliContexts,

        /// Include planner trace in JSON report output (`validation.json`).
        #[arg(long, default_value_t = false)]
        planner_trace: bool,

        /// Conformance profile to emit for this build.
        #[arg(long, value_enum, default_value_t = CliProfile::Core)]
        profile: CliProfile,

        /// KCIR wire format id recorded in `ctc.manifest.json` profile binding.
        #[arg(long, default_value = "kcir.wire.legacy-fixed32.v1")]
        kcir_wire_format_id: String,
    },

    /// Verify a per-pack CTC (`ctc.manifest.json`).
    Verify {
        /// Path to ctc.manifest.json
        manifest: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = CliFormat::Text)]
        format: CliFormat,

        /// Optional explicit witnesses path (defaults to sibling `ctc.witnesses.json`).
        #[arg(long)]
        witnesses: Option<PathBuf>,

        /// Require the pack to be composable (no gaps/conflicts/BC violations).
        #[arg(long, default_value_t = false)]
        require_composable: bool,

        /// Optional allowlist JSON for acknowledged conflicts / BC violations.
        #[arg(long)]
        allowlist: Option<PathBuf>,

        /// Optional policy JSON; when provided, verify checks `policyDigest` against it.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Optional expected conflict comparator mode in manifest semantics.
        #[arg(long, value_enum)]
        conflict_mode: Option<CliConflictMode>,

        /// Require a valid detached signature and signed trust metadata.
        #[arg(long, default_value_t = false)]
        require_signed: bool,

        /// Conformance profile to enforce in verification.
        #[arg(long, value_enum, default_value_t = CliProfile::Core)]
        profile: CliProfile,

        /// Explicit full-profile admissibility witnesses path (defaults to sibling `admissibility.witnesses.json`).
        #[arg(long)]
        admissibility_witnesses: Option<PathBuf>,

        /// Optional expected KCIR anchor root commitment (hex, 0xhex, or sha256:hex).
        #[arg(long)]
        anchor_root_commitment: Option<String>,

        /// Optional expected KCIR anchor tree epoch.
        #[arg(long)]
        anchor_tree_epoch: Option<u64>,
    },

    /// Verify a compose meta-certificate (`compose.manifest.json`).
    VerifyCompose {
        /// Path to compose.manifest.json
        manifest: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = CliFormat::Text)]
        format: CliFormat,

        /// Optional explicit witnesses path (defaults to sibling `compose.witnesses.json`).
        #[arg(long)]
        witnesses: Option<PathBuf>,

        /// Verify each referenced pack certificate while verifying the compose manifest.
        #[arg(long, default_value_t = true)]
        verify_packs: bool,

        /// When verifying packs, require them individually composable.
        #[arg(long, default_value_t = false)]
        require_packs_composable: bool,

        /// Optional policy JSON; when provided, verify checks `policyDigest` against it.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Optional expected conflict comparator mode in manifest semantics.
        #[arg(long, value_enum)]
        conflict_mode: Option<CliConflictMode>,

        /// Require compose manifest to be signed.
        #[arg(long, default_value_t = false)]
        require_signed: bool,

        /// When verifying packs, require each referenced pack manifest to be signed.
        #[arg(long, default_value_t = false)]
        require_packs_signed: bool,

        /// Conformance profile to enforce when verifying each referenced pack.
        #[arg(long, value_enum, default_value_t = CliProfile::Core)]
        pack_profile: CliProfile,
    },

    /// Sign a CTC or compose manifest with detached claims-hash signature metadata.
    Sign {
        /// Path to ctc.manifest.json or compose.manifest.json
        manifest: PathBuf,

        /// Optional output path for detached signature JSON (defaults beside manifest).
        #[arg(long)]
        out: Option<PathBuf>,

        /// Optional signer id recorded in trust metadata/signature.
        #[arg(long)]
        signer: Option<String>,
    },

    /// Generate a reviewable allowlist stub from current conflict / BC witnesses.
    FixAllowlist {
        /// Path to ctc.manifest.json
        manifest: PathBuf,

        /// Optional explicit witnesses path (defaults to sibling `ctc.witnesses.json`).
        #[arg(long)]
        witnesses: Option<PathBuf>,

        /// Matcher style for generated entries.
        #[arg(long, value_enum, default_value_t = CliAllowlistMatcher::WitnessId)]
        matcher: CliAllowlistMatcher,

        /// Restrict generation to the given witness id(s). Repeat to select multiple.
        #[arg(long = "witness-id")]
        witness_ids: Vec<String>,

        /// Reason text inserted into each generated entry. Review and replace before use.
        #[arg(long, default_value = DEFAULT_ALLOWLIST_REASON_TEMPLATE)]
        reason_template: String,

        /// Optional output path. Prints JSON to stdout when omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Explain a witness by id and print the shortest fix recipe.
    Explain {
        /// Witness id (e.g. conflict-..., bc-..., compose-conflict-...)
        witness_id: String,

        /// Witness file(s) to search. Can be passed multiple times.
        #[arg(long = "witnesses")]
        witnesses: Vec<PathBuf>,
    },

    /// Convert report JSON into GitHub Actions annotations.
    AnnotateReport {
        /// Path to validation.json or compose.report.json
        report: PathBuf,

        /// Root directory used to resolve relative file paths in findings.
        #[arg(long, default_value = ".")]
        file_root: PathBuf,

        /// Maximum number of annotations to emit.
        #[arg(long, default_value_t = 200)]
        max: usize,
    },

    /// Compose multiple built packs into a single output + meta-certificate.
    Compose {
        /// Pack output directories (each must contain resolved.json + ctc.*)
        #[arg(required = true)]
        packs: Vec<PathBuf>,

        /// Output directory
        #[arg(short, long, default_value = "dist-compose")]
        out: PathBuf,

        /// Target backend (built-ins: web-css-vars | swift-tokens | android-compose-tokens | web-tokens-ts; aliases: css | swift | kotlin)
        #[arg(long, default_value = "web-css-vars")]
        target: String,

        /// Component contracts (required for --target web-css-vars or alias css)
        #[arg(long)]
        contracts: Option<PathBuf>,

        /// Optional policy JSON (normalization + emission preferences)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Conflict comparator mode for compose meta-certs: semantic intent vs normalized observable output.
        #[arg(long, value_enum, default_value_t = CliConflictMode::Semantic)]
        conflict_mode: CliConflictMode,

        /// Output report format.
        #[arg(long, value_enum, default_value_t = CliFormat::Text)]
        format: CliFormat,

        /// Context evaluation scope: full intersections, full partial lattice, or contract-bounded layering contexts.
        #[arg(long, value_enum, default_value_t = CliContexts::Partial)]
        contexts: CliContexts,

        /// Include planner trace in JSON report output (`compose.report.json`).
        #[arg(long, default_value_t = false)]
        planner_trace: bool,

        /// Verify each input pack's certificate before composing.
        #[arg(long, default_value_t = true)]
        verify_packs: bool,

        /// When verifying packs, require them individually composable.
        #[arg(long, default_value_t = false)]
        require_packs_composable: bool,

        /// Fail the compose command if there are any cross-pack conflicts.
        #[arg(long, default_value_t = false)]
        require_composable: bool,
    },
}

fn map_read_json_error(path: &Path, label: &str, err: ResolverError) -> CliError {
    match err {
        ResolverError::ReadFile { cause, .. } => CliError::new(format!(
            "failed to read {label} {}: {cause}",
            path.display()
        )),
        ResolverError::ParseJson { cause, .. } => CliError::new(format!(
            "failed to parse {label} {}: {cause}",
            path.display()
        )),
        other => CliError::new(format!(
            "failed to load {label} {}: {other}",
            path.display()
        )),
    }
}

fn read_json_arg<T: for<'de> serde::Deserialize<'de>>(path: &Path, label: &str) -> CliResult<T> {
    read_json_file(path).map_err(|e| map_read_json_error(path, label, e))
}

fn create_dir(path: &Path, label: &str) -> CliResult<()> {
    fs::create_dir_all(path)
        .map_err(|e| CliError::new(format!("failed to create {label} {}: {e}", path.display())))
}

fn write_bytes(path: &Path, label: &str, bytes: impl AsRef<[u8]>) -> CliResult<()> {
    fs::write(path, bytes)
        .map_err(|e| CliError::new(format!("failed to write {label} {}: {e}", path.display())))
}

fn json_bytes(value: &impl serde::Serialize, label: &str) -> CliResult<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|e| CliError::new(format!("failed to serialize {label}: {e}")))
}

fn write_json(path: &Path, label: &str, value: &impl serde::Serialize) -> CliResult<()> {
    let bytes = json_bytes(value, label)?;
    write_bytes(path, label, bytes)
}

fn collect_external_source_refs(doc: &ResolverDoc) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for set in doc.sets.values() {
        for src in &set.sources {
            if let Some(r) = &src.r#ref {
                if !r.starts_with("#/") {
                    out.insert(r.clone());
                }
            }
        }
    }
    for modifier in doc.modifiers.values() {
        for sources in modifier.contexts.values() {
            for src in sources {
                if let Some(r) = &src.r#ref {
                    if !r.starts_with("#/") {
                        out.insert(r.clone());
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

fn portable_input_relative_paths(
    doc: &ResolverDoc,
    resolver_path: &Path,
) -> Result<Vec<PathBuf>, String> {
    let resolver_name = resolver_path
        .file_name()
        .ok_or_else(|| format!("resolver path {} has no file name", resolver_path.display()))?;
    let mut out = vec![PathBuf::from("inputs").join(resolver_name)];
    for raw in collect_external_source_refs(doc) {
        let rel = paintgun::path_safety::validate_relative_path(&raw)
            .map_err(|e| format!("invalid source ref {raw}: {e}"))?;
        out.push(PathBuf::from("inputs").join(rel));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn artifact_relative_paths(artifacts: &[BackendArtifact]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = artifacts
        .iter()
        .map(|artifact| artifact.relative_path.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn build_expected_outputs(
    backend: &dyn TargetBackend,
    doc: &ResolverDoc,
    resolver_path: &Path,
    format: CliFormat,
    profile: CliProfile,
) -> Result<Vec<PathBuf>, String> {
    let mut out = vec![
        PathBuf::from("resolved.json"),
        PathBuf::from("manifest.json"),
        PathBuf::from("validation.txt"),
        PathBuf::from("authored.json"),
        PathBuf::from("ctc.witnesses.json"),
        PathBuf::from("diagnostics.pack.json"),
        PathBuf::from("ctc.manifest.json"),
    ];
    if matches!(format, CliFormat::Json) {
        out.push(PathBuf::from("validation.json"));
    }
    if matches!(profile, CliProfile::Full) {
        out.push(PathBuf::from("admissibility.witnesses.json"));
    }
    out.extend(artifact_relative_paths(&backend.planned_artifacts()));
    out.extend(portable_input_relative_paths(doc, resolver_path)?);
    out.sort();
    out.dedup();
    Ok(out)
}

fn compose_expected_outputs(backend: &dyn TargetBackend, format: CliFormat) -> Vec<PathBuf> {
    let mut out = vec![
        PathBuf::from("resolved.json"),
        PathBuf::from("compose.witnesses.json"),
        PathBuf::from("compose.manifest.json"),
        PathBuf::from("compose.report.txt"),
        PathBuf::from("diagnostics.compose.json"),
    ];
    if matches!(format, CliFormat::Json) {
        out.push(PathBuf::from("compose.report.json"));
    }
    out.extend(artifact_relative_paths(&backend.planned_artifacts()));
    out.sort();
    out.dedup();
    out
}

fn build_stage_fingerprint(
    backend: &dyn TargetBackend,
    resolver_path: &Path,
    doc: &ResolverDoc,
    contracts: Option<&Path>,
    policy: Option<&Path>,
    conflict_mode: CliConflictMode,
    format: CliFormat,
    contexts: CliContexts,
    planner_trace: bool,
    profile: CliProfile,
    kcir_wire_format_id: &str,
) -> CliResult<BuildStageFingerprint> {
    let resolver = fingerprint_file(resolver_path).map_err(CliError::new)?;
    let resolver_dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    let mut external_sources = Vec::new();
    for raw in collect_external_source_refs(doc) {
        let rel = paintgun::path_safety::validate_relative_path(&raw)
            .map_err(|e| CliError::new(format!("invalid source ref {raw}: {e}")))?;
        external_sources.push(fingerprint_file(&resolver_dir.join(rel)).map_err(CliError::new)?);
    }
    external_sources.sort_by(|lhs, rhs| lhs.file.cmp(&rhs.file));

    Ok(BuildStageFingerprint {
        executable: current_executable_fingerprint().map_err(CliError::new)?,
        backend_id: backend.spec().id.to_string(),
        conflict_mode: format!("{conflict_mode:?}"),
        format: format!("{format:?}"),
        context_mode: format!("{contexts:?}"),
        planner_trace,
        profile: format!("{profile:?}"),
        kcir_wire_format_id: kcir_wire_format_id.to_string(),
        resolver,
        external_sources,
        contracts: contracts
            .map(fingerprint_file)
            .transpose()
            .map_err(CliError::new)?,
        policy: policy
            .map(fingerprint_file)
            .transpose()
            .map_err(CliError::new)?,
    })
}

fn compose_stage_fingerprint(
    backend: &dyn TargetBackend,
    pack_dirs: &[PathBuf],
    contracts: Option<&Path>,
    policy: Option<&Path>,
    conflict_mode: CliConflictMode,
    format: CliFormat,
    contexts: CliContexts,
    planner_trace: bool,
    verify_packs: bool,
    require_packs_composable: bool,
    require_composable: bool,
) -> CliResult<ComposeStageFingerprint> {
    let mut packs = Vec::new();
    for dir in pack_dirs {
        let manifest = fingerprint_file(&dir.join("ctc.manifest.json")).map_err(CliError::new)?;
        let witnesses = fingerprint_file(&dir.join("ctc.witnesses.json")).map_err(CliError::new)?;
        let resolved = fingerprint_file(&dir.join("resolved.json")).map_err(CliError::new)?;
        let authored_path = dir.join("authored.json");
        let authored = if authored_path.exists() {
            Some(fingerprint_file(&authored_path).map_err(CliError::new)?)
        } else {
            None
        };
        packs.push(ComposePackFingerprint {
            dir: dir.display().to_string(),
            manifest,
            witnesses,
            resolved,
            authored,
        });
    }
    packs.sort_by(|lhs, rhs| lhs.dir.cmp(&rhs.dir));

    Ok(ComposeStageFingerprint {
        executable: current_executable_fingerprint().map_err(CliError::new)?,
        backend_id: backend.spec().id.to_string(),
        conflict_mode: format!("{conflict_mode:?}"),
        format: format!("{format:?}"),
        context_mode: format!("{contexts:?}"),
        planner_trace,
        verify_packs,
        require_packs_composable,
        require_composable,
        contracts: contracts
            .map(fingerprint_file)
            .transpose()
            .map_err(CliError::new)?,
        policy: policy
            .map(fingerprint_file)
            .transpose()
            .map_err(CliError::new)?,
        packs,
    })
}

fn copy_file_into_bundle(src: &Path, dest: &Path) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| format!("missing parent directory for {}", dest.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    fs::copy(src, dest).map_err(|e| {
        format!(
            "failed to copy {} -> {}: {e}",
            src.display(),
            dest.display()
        )
    })?;
    Ok(())
}

fn stage_portable_inputs(
    doc: &ResolverDoc,
    resolver_path: &Path,
    out_dir: &Path,
) -> Result<PathBuf, String> {
    let bundle_root = out_dir.join("inputs");
    let resolver_name = resolver_path
        .file_name()
        .ok_or_else(|| format!("resolver path {} has no file name", resolver_path.display()))?;
    let staged_resolver = bundle_root.join(resolver_name);
    copy_file_into_bundle(resolver_path, &staged_resolver)?;

    let resolver_dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    for raw in collect_external_source_refs(doc) {
        let rel = paintgun::path_safety::validate_relative_path(&raw)
            .map_err(|e| format!("invalid source ref {raw}: {e}"))?;
        let src = resolver_dir.join(&rel);
        let dest = bundle_root.join(&rel);
        copy_file_into_bundle(&src, &dest)?;
    }

    Ok(staged_resolver)
}

fn load_contracts(path: &Path) -> CliResult<Vec<Contract>> {
    let v: serde_json::Value = read_json_arg(path, "contracts JSON")?;
    let obj = v.as_object().ok_or_else(|| {
        CliError::new(format!(
            "invalid contracts JSON {}: top-level JSON value must be an object",
            path.display()
        ))
    })?;
    let mut out = Vec::new();
    for (k, vv) in obj {
        if k.starts_with('$') {
            continue;
        }
        let c: Contract = serde_json::from_value(vv.clone()).map_err(|e| {
            CliError::new(format!(
                "invalid contract entry {}.{}: {e}",
                path.display(),
                k
            ))
        })?;
        out.push(c);
    }
    Ok(out)
}

fn contract_token_set(contracts: &[Contract]) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for c in contracts {
        for slot in c.slots.values() {
            out.insert(slot.token.clone());
        }
    }
    out
}

fn merge_planned_inputs(mut planned: Vec<Input>, mut required: Vec<Input>) -> Vec<Input> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for input in planned.drain(..).chain(required.drain(..)) {
        let key = context_key(&input);
        if seen.insert(key) {
            out.push(input);
        }
    }
    out.sort_by_key(context_key);
    out
}

fn resolve_backend(target: &str) -> CliResult<&'static dyn TargetBackend> {
    resolve_target_backend(target).ok_or_else(|| {
        CliError::new(format!(
            "unknown --target {target}. Supported: {}",
            supported_target_names().join(" | ")
        ))
    })
}

fn emission_path(
    out_dir: &Path,
    emission: &BackendEmission,
    kind: BackendArtifactKind,
) -> Option<PathBuf> {
    emission
        .artifact(kind)
        .map(|artifact| out_dir.join(&artifact.relative_path))
}

fn primary_emission_path(out_dir: &Path, emission: &BackendEmission) -> CliResult<PathBuf> {
    emission
        .primary_output()
        .map(|artifact| out_dir.join(&artifact.relative_path))
        .ok_or_else(|| CliError::new("backend emission missing primary output artifact"))
}

fn manifest_backend_artifact_kind(kind: BackendArtifactKind) -> BackendArtifactDescriptorKind {
    match kind {
        BackendArtifactKind::PrimaryTokenOutput => {
            BackendArtifactDescriptorKind::PrimaryTokenOutput
        }
        BackendArtifactKind::TokenStylesheet => BackendArtifactDescriptorKind::TokenStylesheet,
        BackendArtifactKind::SystemStylesheet => BackendArtifactDescriptorKind::SystemStylesheet,
        BackendArtifactKind::TypeDeclarations => BackendArtifactDescriptorKind::TypeDeclarations,
        BackendArtifactKind::PackageManifest => BackendArtifactDescriptorKind::PackageManifest,
        BackendArtifactKind::PackageSettings => BackendArtifactDescriptorKind::PackageSettings,
        BackendArtifactKind::PackageBuildScript => {
            BackendArtifactDescriptorKind::PackageBuildScript
        }
        BackendArtifactKind::PackageSource => BackendArtifactDescriptorKind::PackageSource,
        BackendArtifactKind::PackageTest => BackendArtifactDescriptorKind::PackageTest,
    }
}

fn manifest_entry_for_backend_artifact(
    out_dir: &Path,
    relative_path: &Path,
) -> CliResult<ManifestEntry> {
    let full_path = out_dir.join(relative_path);
    let bytes = fs::read(&full_path).map_err(|e| {
        CliError::new(format!(
            "failed to read emitted backend artifact {}: {e}",
            full_path.display()
        ))
    })?;
    Ok(ManifestEntry {
        file: relative_path.display().to_string(),
        sha256: format!("sha256:{}", paintgun::util::sha256_hex(&bytes)),
        size: bytes.len() as u64,
    })
}

fn build_backend_artifact_descriptors(
    emission: &BackendEmission,
    out_dir: &Path,
) -> CliResult<Vec<BackendArtifactDescriptor>> {
    let mut descriptors = Vec::new();
    for artifact in &emission.artifacts {
        descriptors.push(BackendArtifactDescriptor {
            backend_id: emission.backend_id.to_string(),
            kind: manifest_backend_artifact_kind(artifact.kind),
            entry: manifest_entry_for_backend_artifact(out_dir, &artifact.relative_path)?,
            api_version: artifact.api_version.map(str::to_string),
        });
    }
    descriptors.sort_by(|lhs, rhs| {
        lhs.backend_id
            .cmp(&rhs.backend_id)
            .then(lhs.kind.as_str().cmp(rhs.kind.as_str()))
            .then(lhs.entry.file.cmp(&rhs.entry.file))
    });
    Ok(descriptors)
}

fn insert_backend_artifacts_field(
    report_json: &mut serde_json::Value,
    backend_artifacts: &[BackendArtifactDescriptor],
) -> CliResult<()> {
    if backend_artifacts.is_empty() {
        return Ok(());
    }
    let obj = report_json
        .as_object_mut()
        .ok_or_else(|| CliError::new("internal error: report JSON must be an object"))?;
    obj.insert(
        "backendArtifacts".to_string(),
        serde_json::to_value(backend_artifacts)
            .map_err(|e| CliError::new(format!("failed to serialize backendArtifacts: {e}")))?,
    );
    Ok(())
}

fn native_versions_for_backend(backend: &dyn TargetBackend) -> Option<NativeApiVersions> {
    match backend.spec().legacy_slot {
        Some(LegacyTargetSlot::Css) | None => None,
        Some(LegacyTargetSlot::Swift) => Some(NativeApiVersions {
            swift: backend.spec().api_version.map(str::to_string),
            kotlin: None,
        }),
        Some(LegacyTargetSlot::AndroidCompose) => Some(NativeApiVersions {
            swift: None,
            kotlin: backend.spec().api_version.map(str::to_string),
        }),
    }
}

fn trace_mode_name(mode: CliContexts) -> &'static str {
    match mode {
        CliContexts::FullOnly => "full-only",
        CliContexts::Partial => "partial",
        CliContexts::FromContracts => "from-contracts",
    }
}

fn make_trace_entries(keys: Vec<String>, rule: &str, source: &str) -> Vec<serde_json::Value> {
    keys.into_iter()
        .map(|k| {
            serde_json::json!({
                "context": k,
                "rule": rule,
                "source": source,
            })
        })
        .collect()
}

fn build_planner_trace(
    scope: &str,
    mode: CliContexts,
    axes: &std::collections::BTreeMap<String, Vec<String>>,
    relevant_axes: Option<&std::collections::BTreeSet<String>>,
    contract_tokens: Option<&std::collections::BTreeSet<String>>,
    partial_universe_inputs: &[Input],
    analysis_inputs: &[Input],
    resolver_inputs: &[Input],
) -> serde_json::Value {
    const TRACE_MAX_ENTRIES: usize = 200;

    let partial_universe_keys: std::collections::BTreeSet<String> =
        partial_universe_inputs.iter().map(context_key).collect();
    let analysis_keys: std::collections::BTreeSet<String> =
        analysis_inputs.iter().map(context_key).collect();
    let resolver_keys: std::collections::BTreeSet<String> =
        resolver_inputs.iter().map(context_key).collect();

    let included_rule = match mode {
        CliContexts::FullOnly => "mode:full-only",
        CliContexts::Partial => "mode:partial",
        CliContexts::FromContracts => "mode:from-contracts",
    };

    let mut included: Vec<String> = analysis_keys.iter().cloned().collect();
    let mut resolver_extra: Vec<String> =
        resolver_keys.difference(&analysis_keys).cloned().collect();
    let mut excluded: Vec<String> = partial_universe_keys
        .difference(&analysis_keys)
        .cloned()
        .collect();

    included.sort();
    resolver_extra.sort();
    excluded.sort();

    let inc_truncated = included.len().saturating_sub(TRACE_MAX_ENTRIES);
    let res_truncated = resolver_extra.len().saturating_sub(TRACE_MAX_ENTRIES);
    let exc_truncated = excluded.len().saturating_sub(TRACE_MAX_ENTRIES);

    included.truncate(TRACE_MAX_ENTRIES);
    resolver_extra.truncate(TRACE_MAX_ENTRIES);
    excluded.truncate(TRACE_MAX_ENTRIES);

    serde_json::json!({
        "version": 1,
        "scope": scope,
        "mode": trace_mode_name(mode),
        "axisUniverse": axes.keys().cloned().collect::<Vec<_>>(),
        "relevantAxes": relevant_axes.map(|s| s.iter().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "contractTokens": contract_tokens.map(|s| s.iter().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "counts": {
            "universe": partial_universe_keys.len(),
            "analysisIncluded": analysis_keys.len(),
            "resolverIncluded": resolver_keys.len(),
            "excluded": partial_universe_keys.len().saturating_sub(analysis_keys.len())
        },
        "truncated": {
            "included": inc_truncated,
            "resolverIncluded": res_truncated,
            "excluded": exc_truncated
        },
        "included": make_trace_entries(included, included_rule, "analysis"),
        "resolverIncluded": make_trace_entries(resolver_extra, "required-for-supporting-ops", "resolver"),
        "excluded": make_trace_entries(excluded, "not-selected-by-mode", "analysis")
    })
}

fn parse_anchor_root_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    let hex_part = if let Some(rest) = trimmed.strip_prefix("sha256:") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("0x") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        rest
    } else {
        trimmed
    };
    hex::decode(hex_part).map_err(|e| format!("invalid anchor root commitment {raw:?}: {e}"))
}

fn anchor_root_matches(lhs: &str, rhs: &str) -> bool {
    match (parse_anchor_root_bytes(lhs), parse_anchor_root_bytes(rhs)) {
        (Ok(a), Ok(b)) => a == b,
        _ => lhs.trim() == rhs.trim(),
    }
}

fn expected_profile_anchors_from_policy_and_cli(
    policy: Option<&Policy>,
    cli_root: Option<&String>,
    cli_epoch: Option<u64>,
) -> Result<Option<ProfileAnchors>, String> {
    let policy_root = policy
        .and_then(|p| p.kcir.as_ref())
        .and_then(|k| k.anchor_root_commitment.as_ref());
    let policy_epoch = policy
        .and_then(|p| p.kcir.as_ref())
        .and_then(|k| k.anchor_tree_epoch);

    if let (Some(pol), Some(cli)) = (policy_root, cli_root.as_ref()) {
        if !anchor_root_matches(pol, cli) {
            return Err(format!(
                "anchor root commitment mismatch between policy ({}) and CLI ({})",
                pol, cli
            ));
        }
    }
    if let (Some(pol), Some(cli)) = (policy_epoch, cli_epoch) {
        if pol != cli {
            return Err(format!(
                "anchor tree epoch mismatch between policy ({}) and CLI ({})",
                pol, cli
            ));
        }
    }

    let root_raw = cli_root
        .cloned()
        .or_else(|| policy_root.map(|s| s.to_string()));
    let tree_epoch = cli_epoch.or(policy_epoch);
    if root_raw.is_none() && tree_epoch.is_none() {
        return Ok(None);
    }

    let root_commitment = root_raw
        .as_deref()
        .map(parse_anchor_root_bytes)
        .transpose()?;
    Ok(Some(ProfileAnchors {
        root_commitment,
        tree_epoch,
        metadata: std::collections::BTreeMap::new(),
    }))
}

fn validate_semantics(
    policy: Option<&Policy>,
    expected_mode: Option<CliConflictMode>,
    manifest_policy_digest: Option<&String>,
    manifest_mode: ConflictMode,
    manifest_normalizer_version: Option<&String>,
    manifest_profile: Option<&KcirProfileBinding>,
) -> Vec<String> {
    let mut errors = Vec::new();

    if let Some(policy) = policy {
        let expected_digest = paintgun::policy::policy_digest(policy);
        if manifest_policy_digest != Some(&expected_digest) {
            errors.push(format!(
                "policyDigest mismatch: manifest has {:?}, expected {}",
                manifest_policy_digest, expected_digest
            ));
        }

        if let Some(kcir) = policy.kcir.as_ref() {
            let Some(profile) = manifest_profile else {
                errors.push("manifest profile missing while policy.kcir is set".to_string());
                return errors;
            };
            if let Some(exp_scheme) = kcir.scheme_id.as_ref() {
                if profile.scheme_id != *exp_scheme {
                    errors.push(format!(
                        "profile.schemeId mismatch: manifest has {}, expected {}",
                        profile.scheme_id, exp_scheme
                    ));
                }
            }
            if let Some(exp_params) = kcir.params_hash.as_ref() {
                if profile.params_hash != *exp_params {
                    errors.push(format!(
                        "profile.paramsHash mismatch: manifest has {}, expected {}",
                        profile.params_hash, exp_params
                    ));
                }
            }
            if let Some(exp_wire) = kcir.wire_format_id.as_ref() {
                if profile.wire_format_id != *exp_wire {
                    errors.push(format!(
                        "profile.wireFormatId mismatch: manifest has {}, expected {}",
                        profile.wire_format_id, exp_wire
                    ));
                }
            }

            if let Some(exp_root) = kcir.anchor_root_commitment.as_ref() {
                let got_root = profile
                    .anchor
                    .as_ref()
                    .and_then(|a| a.root_commitment.as_ref());
                match got_root {
                    Some(got) if anchor_root_matches(got, exp_root) => {}
                    Some(got) => errors.push(format!(
                        "profile.anchor.rootCommitment mismatch: manifest has {}, expected {}",
                        got, exp_root
                    )),
                    None => errors.push(
                        "profile.anchor.rootCommitment missing while policy expects it".to_string(),
                    ),
                }
            }
            if let Some(exp_epoch) = kcir.anchor_tree_epoch {
                let got_epoch = profile.anchor.as_ref().and_then(|a| a.tree_epoch);
                if got_epoch != Some(exp_epoch) {
                    errors.push(format!(
                        "profile.anchor.treeEpoch mismatch: manifest has {:?}, expected {}",
                        got_epoch, exp_epoch
                    ));
                }
            }
        }
    }

    if let Some(mode) = expected_mode {
        let expected_mode: ConflictMode = mode.into();
        if manifest_mode != expected_mode {
            errors.push(format!(
                "conflictMode mismatch: manifest has {}, expected {}",
                manifest_mode, expected_mode
            ));
        }
    }

    if manifest_mode == ConflictMode::Normalized {
        match manifest_normalizer_version {
            Some(v) if v == NORMALIZER_VERSION => {}
            Some(v) => errors.push(format!(
                "normalizerVersion mismatch: manifest has {}, expected {}",
                v, NORMALIZER_VERSION
            )),
            None => {
                errors.push("normalizerVersion missing for normalized conflict mode".to_string())
            }
        }
    }

    errors
}

fn load_ctc_manifest_and_witnesses(
    manifest_path: &Path,
    explicit_witnesses: Option<&Path>,
) -> CliResult<(CtcManifest, paintgun::cert::CtcWitnesses)> {
    let manifest: CtcManifest = read_json_arg(manifest_path, "ctc manifest JSON")?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let witnesses_path = explicit_witnesses
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            manifest
                .required_artifacts
                .iter()
                .find(|artifact| artifact.kind == RequiredArtifactKind::CtcWitnesses)
                .map(|artifact| base.join(&artifact.entry.file))
                .unwrap_or_else(|| base.join("ctc.witnesses.json"))
        });
    let witnesses: paintgun::cert::CtcWitnesses =
        read_json_arg(&witnesses_path, "ctc witnesses JSON")?;
    witnesses.validate_schema_version().map_err(|e| {
        CliError::new(format!(
            "invalid ctc witnesses JSON {}: {e}",
            witnesses_path.display()
        ))
    })?;
    Ok((manifest, witnesses))
}

#[allow(clippy::too_many_arguments)]
fn run_build(
    resolver: PathBuf,
    contracts: Option<PathBuf>,
    out: PathBuf,
    target: String,
    policy: Option<PathBuf>,
    conflict_mode: CliConflictMode,
    format: CliFormat,
    contexts: CliContexts,
    planner_trace: bool,
    profile: CliProfile,
    kcir_wire_format_id: String,
) -> CliResult<()> {
    let backend = resolve_backend(&target)?;
    let doc: ResolverDoc = read_json_arg(&resolver, "resolver JSON")?;
    let contracts_loaded = contracts.as_ref().map(|p| load_contracts(p)).transpose()?;
    let policy_loaded: Policy = match &policy {
        None => Policy::default(),
        Some(p) => read_json_arg(p, "policy JSON")?,
    };
    if matches!(contexts, CliContexts::FromContracts) && contracts_loaded.is_none() {
        return Err(CliError::new(
            "--contexts from-contracts requires --contracts",
        ));
    }
    if backend.spec().capabilities.requires_contracts && contracts_loaded.is_none() {
        return Err(CliError::new(format!(
            "--contracts is required for --target {}",
            backend.spec().id
        )));
    }
    let contract_tokens = contracts_loaded
        .as_ref()
        .map(|cs| contract_token_set(cs.as_slice()));
    let stage_fingerprint = build_stage_fingerprint(
        backend,
        &resolver,
        &doc,
        contracts.as_deref(),
        policy.as_deref(),
        conflict_mode,
        format,
        contexts,
        planner_trace,
        profile,
        &kcir_wire_format_id,
    )?;
    let expected_outputs =
        build_expected_outputs(backend, &doc, &resolver, format, profile).map_err(CliError::new)?;
    if let StageCacheStatus::Hit =
        check_stage_cache(&out, "build", &stage_fingerprint, &expected_outputs)
            .map_err(CliError::new)?
    {
        eprintln!("note: reused cached build outputs from {}", out.display());
        println!("✓ Built pack: {}", out.display());
        return Ok(());
    }
    let kcir_profile =
        kcir_profile_binding_for_scheme_and_wire(HASH_SCHEME_ID, &kcir_wire_format_id).map_err(
            |e| {
                CliError::new(format!(
                    "invalid --kcir-wire-format-id {}: {}",
                    kcir_wire_format_id, e
                ))
            },
        )?;
    let axes = axes_from_doc(&doc);
    let relevant_axes = match (contexts, contract_tokens.as_ref()) {
        (CliContexts::FromContracts, Some(tokens)) => Some(
            axes_relevant_to_tokens(&doc, &resolver, tokens).map_err(|e| {
                CliError::new(format!("failed to compute contract-relevant axes: {e}"))
            })?,
        ),
        _ => None,
    };
    let partial_universe_inputs = paintgun::contexts::partial_inputs(&axes);
    let planned_inputs =
        paintgun::contexts::plan_inputs(contexts.into(), &axes, relevant_axes.as_ref());
    let analysis_inputs = planned_inputs.clone();
    let required_inputs = backend.required_inputs(&axes);
    let store_inputs = supporting_inputs_for_selection(
        &doc,
        &merge_planned_inputs(planned_inputs, required_inputs),
    );
    let planner_trace_payload = if planner_trace {
        Some(build_planner_trace(
            "build",
            contexts,
            &axes,
            relevant_axes.as_ref(),
            contract_tokens.as_ref(),
            &partial_universe_inputs,
            &analysis_inputs,
            &store_inputs,
        ))
    } else {
        None
    };
    let store = build_token_store_for_inputs(&doc, &resolver, &store_inputs)
        .map_err(|e| CliError::new(format!("failed to build token store: {e}")))?;

    create_dir(&out, "output directory")?;
    let staged_resolver = stage_portable_inputs(&doc, &resolver, &out)
        .map_err(|e| CliError::new(format!("failed to stage portable input bundle: {e}")))?;

    let resolved_path = out.join("resolved.json");
    write_resolved_json(&resolved_path, &store)
        .map_err(|e| CliError::new(format!("failed to write resolved.json: {e}")))?;

    let manifest = build_manifest_rel(&doc, &staged_resolver, &out);
    write_json(&out.join("manifest.json"), "manifest.json", &manifest)?;

    let mut tokens_css_path: Option<PathBuf> = None;
    let mut tokens_swift_path: Option<PathBuf> = None;
    let mut tokens_kotlin_path: Option<PathBuf> = None;

    let emission = backend
        .emit(&BackendRequest {
            source: BackendSource::Build { doc: &doc },
            store: &store,
            policy: &policy_loaded,
            contracts: contracts_loaded.as_deref(),
            out_dir: &out,
        })
        .map_err(|e| CliError::new(format!("failed to emit {} backend: {e}", backend.spec().id)))?;
    let backend_artifacts = build_backend_artifact_descriptors(&emission, &out)?;

    match backend.spec().legacy_slot {
        Some(LegacyTargetSlot::Css) => {
            tokens_css_path = Some(primary_emission_path(&out, &emission)?);
        }
        Some(LegacyTargetSlot::Swift) => {
            tokens_swift_path = Some(primary_emission_path(&out, &emission)?);
        }
        Some(LegacyTargetSlot::AndroidCompose) => {
            tokens_kotlin_path = Some(primary_emission_path(&out, &emission)?);
        }
        None => {}
    }
    let tokens_dts_path = emission_path(&out, &emission, BackendArtifactKind::TypeDeclarations);

    let contract_token_ids = contract_tokens.as_ref().map(|tokens| {
        tokens
            .iter()
            .map(|t| TokenPathId::from(t.as_str()))
            .collect::<std::collections::BTreeSet<_>>()
    });
    let full_profile_pipeline = if matches!(profile, CliProfile::Full) {
        Some(
            run_full_profile_pipeline(FullProfilePipelineRequest {
                doc: &doc,
                store: &store,
                resolver_path: &resolver,
                conflict_mode: conflict_mode.into(),
                policy: &policy_loaded,
                context_mode: contexts.into(),
                contract_tokens: contract_token_ids.as_ref(),
            })
            .map_err(|e| CliError::new(format!("failed to run full-profile pipeline: {e}")))?,
        )
    } else {
        None
    };

    let analysis = if let Some(pipeline) = &full_profile_pipeline {
        pipeline.admissibility.analysis.clone()
    } else {
        analyze_composability_with_mode_and_contexts(
            &doc,
            &store,
            &resolver,
            conflict_mode.into(),
            &policy_loaded,
            contexts.into(),
            contract_tokens.as_ref(),
        )
        .map_err(|e| CliError::new(format!("failed to analyze composability: {e}")))?
    };
    let validation_txt = render_validation_report(&store, &analysis);
    let validation_path = out.join("validation.txt");
    write_bytes(
        &validation_path,
        "validation.txt",
        validation_txt.as_bytes(),
    )?;
    let mut validation_json = paintgun::cert::build_validation_report_json(&analysis);
    insert_backend_artifacts_field(&mut validation_json, &backend_artifacts)?;
    if matches!(format, CliFormat::Json) {
        if let Some(trace) = planner_trace_payload.clone() {
            let obj = validation_json.as_object_mut().ok_or_else(|| {
                CliError::new("internal error: validation report JSON must be an object")
            })?;
            obj.insert("plannerTrace".to_string(), trace);
        }
        let validation_json_path = out.join("validation.json");
        write_json(&validation_json_path, "validation.json", &validation_json)?;
    }
    let diagnostics_json =
        build_editor_diagnostics_projection_json(&validation_json, "validation.json")
            .map_err(|e| CliError::new(format!("failed to build diagnostics.pack.json: {e}")))?;
    write_json(
        &out.join("diagnostics.pack.json"),
        "diagnostics.pack.json",
        &diagnostics_json,
    )?;

    let explicit = if let Some(pipeline) = &full_profile_pipeline {
        pipeline.resolve.explicit.clone()
    } else {
        build_explicit_index(&doc, &store, &resolver)
            .map_err(|e| CliError::new(format!("failed to build explicit index: {e}")))?
    };
    let assignments = if let Some(pipeline) = &full_profile_pipeline {
        pipeline.bidir.assignments.clone()
    } else {
        build_assignments(&store, &explicit)
    };
    let authored_export = build_authored_export(&doc, &store, &assignments);
    let authored_path = out.join("authored.json");
    write_json(&authored_path, "authored.json", &authored_export)?;

    let witnesses_path = out.join("ctc.witnesses.json");
    let witnesses_bytes = json_bytes(&analysis.witnesses, "ctc.witnesses.json")?;
    write_bytes(&witnesses_path, "ctc.witnesses.json", &witnesses_bytes)?;
    let witnesses_sha256 = format!("sha256:{}", paintgun::util::sha256_hex(&witnesses_bytes));

    let mut admissibility_path: Option<PathBuf> = None;
    let mut admissibility_sha256: Option<String> = None;
    if let Some(pipeline) = full_profile_pipeline {
        let admissibility = pipeline.admissibility.witnesses;
        let path = out.join("admissibility.witnesses.json");
        let admissibility_bytes = json_bytes(&admissibility, "admissibility.witnesses.json")?;
        write_bytes(&path, "admissibility.witnesses.json", &admissibility_bytes)?;
        admissibility_sha256 = Some(format!(
            "sha256:{}",
            paintgun::util::sha256_hex(&admissibility_bytes)
        ));
        admissibility_path = Some(path);
        if admissibility.result == GateResult::Rejected {
            println!(
                "note: full-profile admissibility produced {} failure(s); verify --profile full will reject",
                admissibility.failures.len()
            );
        }
    }

    let mut ctc_manifest = build_ctc_manifest(
        &doc,
        &staged_resolver,
        &store,
        Some(&policy_loaded),
        conflict_mode.into(),
        &resolved_path,
        tokens_css_path.as_deref(),
        tokens_swift_path.as_deref(),
        tokens_kotlin_path.as_deref(),
        tokens_dts_path.as_deref(),
        Some(&authored_path),
        Some(&validation_path),
        backend_artifacts,
        analysis.summary.clone(),
        witnesses_sha256,
    );
    ctc_manifest.profile = Some(kcir_profile);
    ctc_manifest.admissibility_witnesses_sha256 = admissibility_sha256;
    ctc_manifest
        .required_artifacts
        .push(required_artifact_binding(
            RequiredArtifactKind::CtcWitnesses,
            &witnesses_path,
            &out,
        ));
    if let Some(path) = admissibility_path.as_deref() {
        ctc_manifest
            .required_artifacts
            .push(required_artifact_binding(
                RequiredArtifactKind::AdmissibilityWitnesses,
                path,
                &out,
            ));
    }
    ctc_manifest
        .required_artifacts
        .sort_by_key(|binding| binding.kind.as_str());
    write_json(
        &out.join("ctc.manifest.json"),
        "ctc.manifest.json",
        &ctc_manifest,
    )?;
    write_stage_cache(&out, "build", &stage_fingerprint, &expected_outputs)
        .map_err(|e| CliError::new(format!("failed to write build stage cache: {e}")))?;

    println!("✓ Built pack: {}", out.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_compose(
    packs: Vec<PathBuf>,
    out: PathBuf,
    target: String,
    contracts: Option<PathBuf>,
    policy: Option<PathBuf>,
    conflict_mode: CliConflictMode,
    format: CliFormat,
    contexts: CliContexts,
    planner_trace: bool,
    verify_packs: bool,
    require_packs_composable: bool,
    require_composable: bool,
) -> CliResult<()> {
    let backend = resolve_backend(&target)?;
    let stage_fingerprint = compose_stage_fingerprint(
        backend,
        &packs,
        contracts.as_deref(),
        policy.as_deref(),
        conflict_mode,
        format,
        contexts,
        planner_trace,
        verify_packs,
        require_packs_composable,
        require_composable,
    )?;
    let expected_outputs = compose_expected_outputs(backend, format);
    if let StageCacheStatus::Hit =
        check_stage_cache(&out, "compose", &stage_fingerprint, &expected_outputs)
            .map_err(CliError::new)?
    {
        eprintln!("note: reused cached compose outputs from {}", out.display());
        if matches!(format, CliFormat::Json) {
            let cached = fs::read_to_string(out.join("compose.report.json")).map_err(|e| {
                CliError::new(format!(
                    "failed to read cached compose.report.json {}: {e}",
                    out.join("compose.report.json").display()
                ))
            })?;
            println!("{cached}");
        } else {
            let cached = fs::read_to_string(out.join("compose.report.txt")).map_err(|e| {
                CliError::new(format!(
                    "failed to read cached compose.report.txt {}: {e}",
                    out.join("compose.report.txt").display()
                ))
            })?;
            println!("{cached}");
        }
        return Ok(());
    }
    let policy_loaded: Policy = match &policy {
        None => Policy::default(),
        Some(p) => read_json_arg(p, "policy JSON")?,
    };
    let contracts_loaded = contracts.as_ref().map(|p| load_contracts(p)).transpose()?;
    if matches!(contexts, CliContexts::FromContracts) && contracts_loaded.is_none() {
        return Err(CliError::new(
            "--contexts from-contracts requires --contracts",
        ));
    }
    if backend.spec().capabilities.requires_contracts && contracts_loaded.is_none() {
        return Err(CliError::new(format!(
            "--contracts is required for --target {}",
            backend.spec().id
        )));
    }
    let contract_tokens = contracts_loaded
        .as_ref()
        .map(|cs| contract_token_set(cs.as_slice()));

    let mut loaded = Vec::new();
    for p in packs {
        let pack = load_pack(&p, verify_packs, require_packs_composable)
            .map_err(|e| CliError::new(e.to_string()))?;
        loaded.push(pack);
    }

    if loaded.len() < 2 {
        return Err(CliError::new("compose requires at least 2 packs"));
    }

    let compose_axes = union_axes(&loaded);
    let relevant_axes = match (contexts, contract_tokens.as_ref()) {
        (CliContexts::FromContracts, Some(tokens)) => {
            relevant_axes_for_contract_tokens(&loaded, tokens)
        }
        _ => None,
    };
    let planned_inputs =
        paintgun::contexts::plan_inputs(contexts.into(), &compose_axes, relevant_axes.as_ref());
    let partial_universe_inputs = paintgun::contexts::partial_inputs(&compose_axes);
    let planner_trace_payload = if planner_trace {
        Some(build_planner_trace(
            "compose",
            contexts,
            &compose_axes,
            relevant_axes.as_ref(),
            contract_tokens.as_ref(),
            &partial_universe_inputs,
            &planned_inputs,
            &planned_inputs,
        ))
    } else {
        None
    };

    create_dir(&out, "output directory")?;

    let composed =
        compose_store_with_context_mode(&loaded, contexts.into(), contract_tokens.as_ref());
    let resolved_path = out.join("resolved.json");
    write_resolved_json(&resolved_path, &composed)
        .map_err(|e| CliError::new(format!("failed to write resolved.json: {e}")))?;

    let emission = backend
        .emit(&BackendRequest {
            source: BackendSource::Compose {
                axes: &composed.axes,
            },
            store: &composed,
            policy: &policy_loaded,
            contracts: contracts_loaded.as_deref(),
            out_dir: &out,
        })
        .map_err(|e| CliError::new(format!("failed to emit {} backend: {e}", backend.spec().id)))?;
    let _ = primary_emission_path(&out, &emission)?;
    let backend_artifacts = build_backend_artifact_descriptors(&emission, &out)?;

    let witnesses = analyze_cross_pack_conflicts_with_mode_and_contexts(
        &loaded,
        &composed.axes,
        conflict_mode.into(),
        &policy_loaded,
        contexts.into(),
        contract_tokens.as_ref(),
    );
    let witnesses_path = out.join("compose.witnesses.json");
    let witnesses_bytes = json_bytes(&witnesses, "compose.witnesses.json")?;
    write_bytes(&witnesses_path, "compose.witnesses.json", &witnesses_bytes)?;
    let witnesses_sha256 = format!("sha256:{}", paintgun::util::sha256_hex(&witnesses_bytes));
    let native_api_versions = native_versions_for_backend(backend);

    let manifest = build_compose_manifest_with_context_count(
        &loaded,
        &out,
        &composed.axes,
        &policy_loaded,
        conflict_mode.into(),
        backend_artifacts,
        native_api_versions,
        witnesses_sha256,
        composed.resolved_by_ctx.len(),
        &witnesses,
    )
    .map_err(|e| CliError::new(format!("failed to build compose manifest: {e}")))?;
    write_json(
        &out.join("compose.manifest.json"),
        "compose.manifest.json",
        &manifest,
    )?;

    let report = render_compose_report(&manifest, &witnesses);
    write_bytes(
        &out.join("compose.report.txt"),
        "compose.report.txt",
        report.as_bytes(),
    )?;
    let mut report_json = paintgun::compose::build_compose_report_json(&manifest, &witnesses);
    if let Some(trace) = planner_trace_payload {
        let obj = report_json.as_object_mut().ok_or_else(|| {
            CliError::new("internal error: compose report JSON must be an object")
        })?;
        obj.insert("plannerTrace".to_string(), trace);
        paintgun::compose::refresh_compose_report_scale_metadata(
            &mut report_json,
            &manifest,
            &witnesses,
        );
    }
    let diagnostics_json =
        build_editor_diagnostics_projection_json(&report_json, "compose.report.json")
            .map_err(|e| CliError::new(format!("failed to build diagnostics.compose.json: {e}")))?;
    write_json(
        &out.join("diagnostics.compose.json"),
        "diagnostics.compose.json",
        &diagnostics_json,
    )?;
    if matches!(format, CliFormat::Json) {
        let report_json_bytes = json_bytes(&report_json, "compose.report.json")?;
        write_bytes(
            &out.join("compose.report.json"),
            "compose.report.json",
            &report_json_bytes,
        )?;
        println!("{}", String::from_utf8_lossy(&report_json_bytes));
    } else {
        println!("{report}");
    }

    if require_composable && !witnesses.conflicts.is_empty() {
        std::process::exit(1);
    }

    write_stage_cache(&out, "compose", &stage_fingerprint, &expected_outputs)
        .map_err(|e| CliError::new(format!("failed to write compose stage cache: {e}")))?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("✗ {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> CliResult<()> {
    match cli.cmd {
        Command::SpecPack { manifest, out } => {
            let summary = build_spec_pack(&manifest, &out, env!("CARGO_PKG_VERSION"))
                .map_err(CliError::new)?;
            println!(
                "✓ Spec pack written: {} (index: {}, documents={})",
                summary.pack_manifest, summary.index, summary.documents
            );
            return Ok(());
        }

        Command::VerifySpecPack { manifest, format } => {
            let report = verify_spec_pack(&manifest);
            if matches!(format, CliFormat::Json) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("serialize spec-pack verify report")
                );
                if !report.ok {
                    std::process::exit(1);
                }
                return Ok(());
            }

            if !report.ok {
                eprintln!("✗ Spec pack verification failed:");
                for error in &report.errors {
                    eprintln!("  - {error}");
                }
                std::process::exit(1);
            }
            println!(
                "✓ Spec pack verified: {} (documents={})",
                manifest.display(),
                report.checked_documents
            );
            return Ok(());
        }

        Command::Verify {
            manifest,
            format,
            witnesses,
            require_composable,
            allowlist,
            policy,
            conflict_mode,
            require_signed,
            profile,
            admissibility_witnesses,
            anchor_root_commitment,
            anchor_tree_epoch,
        } => {
            let allowlist_data: Option<Allowlist> = match &allowlist {
                None => None,
                Some(path) => match read_json_file(path) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        eprintln!("✗ failed to parse allowlist {}: {e}", path.display());
                        std::process::exit(1);
                    }
                },
            };
            let policy_data: Option<Policy> = match &policy {
                None => None,
                Some(path) => match read_json_file(path) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        eprintln!("✗ failed to parse policy {}: {e}", path.display());
                        std::process::exit(1);
                    }
                },
            };
            let expected_profile_anchors = match expected_profile_anchors_from_policy_and_cli(
                policy_data.as_ref(),
                anchor_root_commitment.as_ref(),
                anchor_tree_epoch,
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("✗ invalid anchor expectations: {e}");
                    std::process::exit(1);
                }
            };
            let report = verify_ctc_with_options(
                &manifest,
                CtcVerifyOptions {
                    witnesses_path: witnesses.as_deref(),
                    require_composable,
                    allowlist: allowlist_data.as_ref(),
                    require_signed,
                    profile: profile.into(),
                    admissibility_witnesses_path: admissibility_witnesses.as_deref(),
                    expected_profile_anchors,
                },
            );
            let semantic_errors = if report.ok {
                match read_json_file::<CtcManifest>(&manifest) {
                    Ok(ctc_manifest) => validate_semantics(
                        policy_data.as_ref(),
                        conflict_mode,
                        ctc_manifest.semantics.policy_digest.as_ref(),
                        ctc_manifest.semantics.conflict_mode,
                        ctc_manifest.semantics.normalizer_version.as_ref(),
                        ctc_manifest.profile.as_ref(),
                    ),
                    Err(e) => vec![format!(
                        "failed to parse manifest {}: {e}",
                        manifest.display()
                    )],
                }
            } else {
                Vec::new()
            };
            let overall_ok = report.ok && semantic_errors.is_empty();

            if matches!(format, CliFormat::Json) {
                let out = serde_json::json!({
                    "kind": "verify",
                    "manifest": manifest.to_string_lossy(),
                    "ok": overall_ok,
                    "verify": {
                        "ok": report.ok,
                        "errors": report.errors,
                        "errorDetails": report.error_details
                            .iter()
                            .map(|e| serde_json::json!({"code": e.code, "message": e.message}))
                            .collect::<Vec<_>>(),
                        "notes": report.notes,
                    },
                    "semantics": {
                        "ok": semantic_errors.is_empty(),
                        "errors": semantic_errors,
                    },
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).expect("serialize verify json output")
                );
                if !overall_ok {
                    std::process::exit(1);
                }
                return Ok(());
            }

            if !report.ok {
                eprintln!("✗ CTC verification failed:");
                for e in report.errors {
                    eprintln!("  - {e}");
                }
                for n in report.notes {
                    eprintln!("  - note: {n}");
                }
                std::process::exit(1);
            }
            for n in report.notes {
                println!("note: {n}");
            }

            if !semantic_errors.is_empty() {
                eprintln!("✗ CTC semantic verification failed:");
                for e in semantic_errors {
                    eprintln!("  - {e}");
                }
                std::process::exit(1);
            }

            println!("✓ CTC verified: {}", manifest.display());
            return Ok(());
        }

        Command::VerifyCompose {
            manifest,
            format,
            witnesses,
            verify_packs,
            require_packs_composable,
            policy,
            conflict_mode,
            require_signed,
            require_packs_signed,
            pack_profile,
        } => {
            let policy_data: Option<Policy> = match &policy {
                None => None,
                Some(path) => match read_json_file(path) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        eprintln!("✗ failed to parse policy {}: {e}", path.display());
                        std::process::exit(1);
                    }
                },
            };
            let rep = verify_compose_with_signing(
                &manifest,
                witnesses.as_deref(),
                verify_packs,
                require_packs_composable,
                require_signed,
                require_packs_signed,
                pack_profile.into(),
            );
            let semantic_errors = if rep.ok {
                match read_json_file::<ComposeManifest>(&manifest) {
                    Ok(compose_manifest) => validate_semantics(
                        policy_data.as_ref(),
                        conflict_mode,
                        compose_manifest.semantics.policy_digest.as_ref(),
                        compose_manifest.semantics.conflict_mode,
                        compose_manifest.semantics.normalizer_version.as_ref(),
                        None,
                    ),
                    Err(e) => vec![format!(
                        "failed to parse compose manifest {}: {e}",
                        manifest.display()
                    )],
                }
            } else {
                Vec::new()
            };
            let overall_ok = rep.ok && semantic_errors.is_empty();

            if matches!(format, CliFormat::Json) {
                let out = serde_json::json!({
                    "kind": "verify-compose",
                    "manifest": manifest.to_string_lossy(),
                    "ok": overall_ok,
                    "verify": {
                        "ok": rep.ok,
                        "errors": rep.errors,
                        "errorDetails": rep.error_details
                            .iter()
                            .map(|e| serde_json::json!({"code": e.code, "message": e.message}))
                            .collect::<Vec<_>>(),
                    },
                    "semantics": {
                        "ok": semantic_errors.is_empty(),
                        "errors": semantic_errors,
                    },
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out)
                        .expect("serialize verify-compose json output")
                );
                if !overall_ok {
                    std::process::exit(1);
                }
                return Ok(());
            }

            if !rep.ok {
                eprintln!("✗ Compose meta-cert verification failed:");
                if rep.error_details.is_empty() {
                    for e in &rep.errors {
                        eprintln!("  - {e}");
                    }
                } else {
                    for e in &rep.error_details {
                        eprintln!("  - [{}] {}", e.code, e.message);
                    }
                }
                std::process::exit(1);
            }

            if !semantic_errors.is_empty() {
                eprintln!("✗ Compose semantic verification failed:");
                for e in &semantic_errors {
                    eprintln!("  - {e}");
                }
                std::process::exit(1);
            }

            println!("✓ Compose meta-cert verified: {}", manifest.display());
            return Ok(());
        }

        Command::Sign {
            manifest,
            out,
            signer,
        } => {
            match sign_manifest_file(&manifest, out.as_deref(), signer.as_deref()) {
                Ok(sig_path) => {
                    println!(
                        "✓ Signed manifest: {} (signature: {})",
                        manifest.display(),
                        sig_path.display()
                    );
                }
                Err(e) => {
                    eprintln!("✗ failed to sign manifest: {e}");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }

        Command::FixAllowlist {
            manifest,
            witnesses,
            matcher,
            witness_ids,
            reason_template,
            out,
        } => {
            let (_manifest, ctc_witnesses) =
                match load_ctc_manifest_and_witnesses(&manifest, witnesses.as_deref()) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!("✗ {err}");
                        std::process::exit(1);
                    }
                };
            let witness_ids = witness_ids
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            let allowlist = match generate_allowlist(
                &ctc_witnesses,
                matcher.into(),
                &witness_ids,
                &reason_template,
            ) {
                Ok(value) => value,
                Err(errors) => {
                    eprintln!("✗ failed to generate allowlist:");
                    for error in errors {
                        eprintln!("  - {error}");
                    }
                    std::process::exit(1);
                }
            };

            if let Some(path) = out {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        create_dir(parent, "allowlist output directory")?;
                    }
                }
                write_json(&path, "allowlist JSON", &allowlist)?;
                println!(
                    "✓ Wrote allowlist stub: {} (conflicts={}, bcViolations={}). Review and replace placeholder reasons before use.",
                    path.display(),
                    allowlist.conflicts.len(),
                    allowlist.bc_violations.len()
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&allowlist)
                        .expect("serialize generated allowlist")
                );
            }
            return Ok(());
        }

        Command::Explain {
            witness_id,
            witnesses,
        } => {
            let witness_id = WitnessId::from(witness_id.as_str());
            let witness_files: Vec<PathBuf> = if witnesses.is_empty() {
                let defaults = vec![
                    PathBuf::from("dist/ctc.witnesses.json"),
                    PathBuf::from("dist-compose/compose.witnesses.json"),
                ];
                defaults.into_iter().filter(|p| p.exists()).collect()
            } else {
                witnesses
            };

            if witness_files.is_empty() {
                eprintln!("✗ no witness files found; pass one or more --witnesses <path>");
                std::process::exit(1);
            }

            let mut matches: Vec<(String, String)> = Vec::new();
            let mut parse_errors: Vec<String> = Vec::new();

            for wf in &witness_files {
                let wb = match fs::read(wf) {
                    Ok(v) => v,
                    Err(e) => {
                        parse_errors.push(format!("failed to read {}: {e}", wf.display()));
                        continue;
                    }
                };

                if let Ok(ctc) = serde_json::from_slice::<paintgun::cert::CtcWitnesses>(&wb) {
                    if let Some(expl) =
                        explain_ctc_witness(&ctc, &witness_id, &wf.display().to_string())
                    {
                        matches.push((wf.display().to_string(), expl));
                    }
                    continue;
                }

                if let Ok(compose) =
                    serde_json::from_slice::<paintgun::compose::ComposeWitnesses>(&wb)
                {
                    if let Some(expl) =
                        explain_compose_witness(&compose, &witness_id, &wf.display().to_string())
                    {
                        matches.push((wf.display().to_string(), expl));
                    }
                    continue;
                }

                parse_errors.push(format!("unsupported witness file format: {}", wf.display()));
            }

            if matches.len() > 1 {
                eprintln!("✗ witness `{}` matched multiple files:", witness_id);
                for (path, _) in &matches {
                    eprintln!("  - {path}");
                }
                eprintln!("  pass a single --witnesses <path> to disambiguate");
                std::process::exit(1);
            }

            if let Some((_path, expl)) = matches.pop() {
                println!("{expl}");
                return Ok(());
            }

            eprintln!(
                "✗ witness `{}` not found in searched files: {}",
                witness_id,
                witness_files
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for e in parse_errors {
                eprintln!("  - {e}");
            }
            std::process::exit(1);
        }

        Command::AnnotateReport {
            report,
            file_root,
            max,
        } => {
            let parsed = match read_report(&report) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("✗ {e}");
                    std::process::exit(1);
                }
            };
            let out = build_github_annotations(&parsed, &file_root, max);
            for line in &out.lines {
                println!("{line}");
            }
            println!(
                "::notice title=paintgun/report::reportKind={} conflictMode={} findings={} emitted={} truncated={}",
                parsed.report_kind,
                parsed.conflict_mode,
                parsed.counts.total,
                out.emitted,
                out.truncated
            );
            return Ok(());
        }

        Command::Build {
            resolver,
            contracts,
            out,
            target,
            policy,
            conflict_mode,
            format,
            contexts,
            planner_trace,
            profile,
            kcir_wire_format_id,
        } => {
            return run_build(
                resolver,
                contracts,
                out,
                target,
                policy,
                conflict_mode,
                format,
                contexts,
                planner_trace,
                profile,
                kcir_wire_format_id,
            )
        }

        Command::Compose {
            packs,
            out,
            target,
            contracts,
            policy,
            conflict_mode,
            format,
            contexts,
            planner_trace,
            verify_packs,
            require_packs_composable,
            require_composable,
        } => {
            return run_compose(
                packs,
                out,
                target,
                contracts,
                policy,
                conflict_mode,
                format,
                contexts,
                planner_trace,
                verify_packs,
                require_packs_composable,
                require_composable,
            )
        }
    }
}

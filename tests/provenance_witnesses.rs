use std::path::PathBuf;

use paintgun::cert::analyze_composability;
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};

#[test]
fn conflict_witnesses_carry_file_blame_metadata() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    let witness = analysis
        .witnesses
        .conflicts
        .first()
        .expect("expected at least one conflict witness");
    let candidate = witness
        .candidates
        .first()
        .expect("expected at least one conflict candidate");

    let file_path = candidate.file_path.as_str();
    assert!(
        !file_path.starts_with('/'),
        "filePath should be stable relative, got absolute path: {file_path}"
    );

    let file_hash = candidate.file_hash.as_str();
    assert!(
        file_hash.starts_with("sha256:"),
        "fileHash should be sha256-prefixed, got: {file_hash}"
    );

    let ptr = candidate.json_pointer.as_str();
    assert!(
        ptr.starts_with('/'),
        "jsonPointer should be a JSON Pointer, got: {ptr}"
    );

    let layer = candidate.resolution_layer_id.as_str();
    assert!(
        layer.starts_with("modifier:") || layer.starts_with("set:"),
        "unexpected resolutionLayerId: {layer}"
    );

    let rank = candidate.resolution_rank;
    assert!(
        rank < 100,
        "resolutionRank should be bounded for sample fixture, got: {rank}"
    );
    assert!(
        !candidate.pack_id.is_empty(),
        "candidate should include packId"
    );
    assert!(
        candidate.pack_hash.starts_with("sha256:"),
        "candidate should include sha256 packHash"
    );

    let inherited = analysis
        .witnesses
        .inherited
        .first()
        .expect("expected at least one inherited witness");
    assert!(
        !inherited.sources.is_empty(),
        "inherited witness should include rich source provenance"
    );
    let inherited_source = &inherited.sources[0];
    assert!(
        !inherited_source.file_path.is_empty(),
        "inherited source should include filePath"
    );
    assert!(
        inherited_source.file_hash.starts_with("sha256:"),
        "inherited source should include sha256 fileHash"
    );
    assert!(
        inherited_source.json_pointer.starts_with('/'),
        "inherited source should include jsonPointer"
    );
    assert!(
        !inherited_source.resolution_layer_id.is_empty(),
        "inherited source should include resolutionLayerId"
    );
    assert!(
        inherited_source.resolution_rank < 100,
        "inherited source should include resolutionRank"
    );
    assert!(
        !inherited.resolved_value_json.is_empty(),
        "inherited witness should include resolved_value_json"
    );
    assert!(
        inherited.resolved_value_digest.starts_with("sha256:"),
        "inherited witness should include resolved_value_digest"
    );

    let gap = analysis
        .witnesses
        .gaps
        .first()
        .expect("expected at least one gap witness");
    assert!(
        !gap.authored_sources.is_empty(),
        "gap witness should include authored sources for remediation"
    );
}

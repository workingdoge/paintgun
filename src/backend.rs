use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::emit::{
    build_layer_defs_from_axes, compile_component_css, compile_component_css_with_layers,
    emit_kotlin_module_scaffold, emit_store_kotlin, emit_store_swift, emit_swift_package_scaffold,
    emit_tokens_d_ts, Contract, CssEmitter, KOTLIN_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION,
};
use crate::policy::Policy;
use crate::resolver::{Input, ResolverDoc, TokenStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendScope {
    TokenBackend,
    SystemPackage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub requires_contracts: bool,
    pub emits_package_scaffold: bool,
    pub scope: BackendScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyTargetSlot {
    Css,
    Swift,
    Kotlin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendArtifactKind {
    PrimaryTokenOutput,
    TypeDeclarations,
    PackageManifest,
    PackageSettings,
    PackageBuildScript,
    PackageSource,
    PackageTest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendArtifact {
    pub kind: BackendArtifactKind,
    pub relative_path: PathBuf,
    pub api_version: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendEmission {
    pub backend_id: &'static str,
    pub artifacts: Vec<BackendArtifact>,
}

impl BackendEmission {
    pub fn artifact(&self, kind: BackendArtifactKind) -> Option<&BackendArtifact> {
        self.artifacts.iter().find(|artifact| artifact.kind == kind)
    }

    pub fn primary_output(&self) -> Option<&BackendArtifact> {
        self.artifact(BackendArtifactKind::PrimaryTokenOutput)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendSpec {
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub api_version: Option<&'static str>,
    pub capabilities: BackendCapabilities,
    pub legacy_slot: LegacyTargetSlot,
}

pub enum BackendSource<'a> {
    Build {
        doc: &'a ResolverDoc,
    },
    Compose {
        axes: &'a BTreeMap<String, Vec<String>>,
    },
}

pub struct BackendRequest<'a> {
    pub source: BackendSource<'a>,
    pub store: &'a TokenStore,
    pub policy: &'a Policy,
    pub contracts: Option<&'a [Contract]>,
    pub out_dir: &'a Path,
}

#[derive(Debug)]
pub struct BackendError(String);

impl BackendError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

pub trait TargetBackend {
    fn spec(&self) -> BackendSpec;
    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input>;
    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError>;
}

struct CssBackend;
struct SwiftBackend;
struct KotlinBackend;

static CSS_BACKEND: CssBackend = CssBackend;
static SWIFT_BACKEND: SwiftBackend = SwiftBackend;
static KOTLIN_BACKEND: KotlinBackend = KotlinBackend;

fn builtin_backends() -> [&'static dyn TargetBackend; 3] {
    [&CSS_BACKEND, &SWIFT_BACKEND, &KOTLIN_BACKEND]
}

pub fn resolve_target_backend(target: &str) -> Option<&'static dyn TargetBackend> {
    builtin_backends().into_iter().find(|backend| {
        let spec = backend.spec();
        spec.id == target || spec.aliases.iter().any(|alias| *alias == target)
    })
}

pub fn supported_target_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = builtin_backends()
        .into_iter()
        .flat_map(|backend| {
            let spec = backend.spec();
            std::iter::once(spec.id).chain(spec.aliases.iter().copied())
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn write_bytes(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(), BackendError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            BackendError::new(format!("failed to create {}: {e}", parent.display()))
        })?;
    }
    fs::write(path, bytes)
        .map_err(|e| BackendError::new(format!("failed to write {}: {e}", path.display())))
}

fn layer_order_from_axes(axes: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut out = Vec::new();
    out.push("base".to_string());
    let mut mods: Vec<String> = axes.keys().cloned().collect();
    mods.sort();
    out.extend(mods.clone());
    for i in 0..mods.len() {
        for j in (i + 1)..mods.len() {
            out.push(format!("{}-{}", mods[i], mods[j]));
        }
    }
    out
}

fn layer_order_from_doc(doc: &ResolverDoc) -> Vec<String> {
    let mut names = Vec::new();
    names.push("base".to_string());

    let mut mods: Vec<String> = Vec::new();
    for entry in &doc.resolution_order {
        if let Some(name) = entry.modifier_name() {
            if !mods.iter().any(|m| m == &name) {
                mods.push(name);
            }
        }
    }
    if mods.is_empty() {
        mods.extend(
            doc.all_modifiers()
                .into_iter()
                .map(|(name, _)| name.to_string()),
        );
        mods.sort();
    }
    names.extend(mods.clone());

    for i in 0..mods.len() {
        for j in (i + 1)..mods.len() {
            names.push(format!("{}-{}", mods[i], mods[j]));
        }
    }

    names
}

impl TargetBackend for CssBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "css",
            aliases: &[],
            api_version: None,
            capabilities: BackendCapabilities {
                requires_contracts: true,
                emits_package_scaffold: false,
                scope: BackendScope::TokenBackend,
            },
            legacy_slot: LegacyTargetSlot::Css,
        }
    }

    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        crate::contexts::layered_inputs(axes, None)
    }

    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError> {
        let contracts = request
            .contracts
            .ok_or_else(|| BackendError::new("backend css requires contracts"))?;
        let emitter = CssEmitter {
            color_policy: request.policy.css_color.clone(),
        };
        let preamble = match request.source {
            BackendSource::Build { doc } => {
                format!("@layer {};\n\n", layer_order_from_doc(doc).join(", "))
            }
            BackendSource::Compose { axes } => {
                format!("@layer {};\n\n", layer_order_from_axes(axes).join(", "))
            }
        };

        let mut css = String::new();
        css.push_str(&preamble);
        match request.source {
            BackendSource::Build { doc } => {
                for contract in contracts {
                    css.push_str(&format!("/* ═ {} ═ */\n\n", contract.component));
                    css.push_str(&compile_component_css(
                        contract,
                        doc,
                        request.store,
                        request.policy,
                        &emitter,
                    ));
                    css.push('\n');
                }
            }
            BackendSource::Compose { axes } => {
                let layer_defs = build_layer_defs_from_axes(axes);
                for contract in contracts {
                    css.push_str(&format!("/* ═ {} ═ */\n\n", contract.component));
                    css.push_str(&compile_component_css_with_layers(
                        contract,
                        request.store,
                        request.policy,
                        &emitter,
                        &layer_defs,
                    ));
                    css.push('\n');
                }
            }
        }

        let css_path = request.out_dir.join("tokens.css");
        write_bytes(&css_path, css.as_bytes())?;
        let dts = emit_tokens_d_ts(contracts);
        let dts_path = request.out_dir.join("tokens.d.ts");
        write_bytes(&dts_path, dts.as_bytes())?;

        Ok(BackendEmission {
            backend_id: self.spec().id,
            artifacts: vec![
                BackendArtifact {
                    kind: BackendArtifactKind::PrimaryTokenOutput,
                    relative_path: PathBuf::from("tokens.css"),
                    api_version: None,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::TypeDeclarations,
                    relative_path: PathBuf::from("tokens.d.ts"),
                    api_version: None,
                },
            ],
        })
    }
}

impl TargetBackend for SwiftBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "swift",
            aliases: &[],
            api_version: Some(SWIFT_EMITTER_API_VERSION),
            capabilities: BackendCapabilities {
                requires_contracts: false,
                emits_package_scaffold: true,
                scope: BackendScope::TokenBackend,
            },
            legacy_slot: LegacyTargetSlot::Swift,
        }
    }

    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        crate::contexts::layered_inputs(axes, None)
            .into_iter()
            .filter(|input| input.len() <= 1)
            .collect()
    }

    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError> {
        let swift = emit_store_swift(request.store, request.policy);
        let source_path = request.out_dir.join("tokens.swift");
        write_bytes(&source_path, swift.as_bytes())?;
        emit_swift_package_scaffold(request.out_dir, &swift).map_err(|e| {
            BackendError::new(format!("failed to write swift package scaffold: {e}"))
        })?;

        Ok(BackendEmission {
            backend_id: self.spec().id,
            artifacts: vec![
                BackendArtifact {
                    kind: BackendArtifactKind::PrimaryTokenOutput,
                    relative_path: PathBuf::from("tokens.swift"),
                    api_version: self.spec().api_version,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageManifest,
                    relative_path: PathBuf::from("swift/Package.swift"),
                    api_version: None,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageSource,
                    relative_path: PathBuf::from(
                        "swift/Sources/PaintgunTokens/PaintgunTokens.swift",
                    ),
                    api_version: self.spec().api_version,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageTest,
                    relative_path: PathBuf::from(
                        "swift/Tests/PaintgunTokensTests/PaintgunTokensTests.swift",
                    ),
                    api_version: None,
                },
            ],
        })
    }
}

impl TargetBackend for KotlinBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "kotlin",
            aliases: &[],
            api_version: Some(KOTLIN_EMITTER_API_VERSION),
            capabilities: BackendCapabilities {
                requires_contracts: false,
                emits_package_scaffold: true,
                scope: BackendScope::TokenBackend,
            },
            legacy_slot: LegacyTargetSlot::Kotlin,
        }
    }

    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        crate::contexts::layered_inputs(axes, None)
            .into_iter()
            .filter(|input| input.len() <= 1)
            .collect()
    }

    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError> {
        let kotlin = emit_store_kotlin(request.store, request.policy);
        let source_path = request.out_dir.join("tokens.kt");
        write_bytes(&source_path, kotlin.as_bytes())?;
        emit_kotlin_module_scaffold(request.out_dir, &kotlin).map_err(|e| {
            BackendError::new(format!("failed to write kotlin module scaffold: {e}"))
        })?;

        Ok(BackendEmission {
            backend_id: self.spec().id,
            artifacts: vec![
                BackendArtifact {
                    kind: BackendArtifactKind::PrimaryTokenOutput,
                    relative_path: PathBuf::from("tokens.kt"),
                    api_version: self.spec().api_version,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageSettings,
                    relative_path: PathBuf::from("kotlin/settings.gradle.kts"),
                    api_version: None,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageBuildScript,
                    relative_path: PathBuf::from("kotlin/build.gradle.kts"),
                    api_version: None,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageSource,
                    relative_path: PathBuf::from(
                        "kotlin/src/main/kotlin/paintgun/PaintgunTokens.kt",
                    ),
                    api_version: self.spec().api_version,
                },
                BackendArtifact {
                    kind: BackendArtifactKind::PackageTest,
                    relative_path: PathBuf::from(
                        "kotlin/src/test/kotlin/paintgun/PaintgunTokensSmokeTest.kt",
                    ),
                    api_version: None,
                },
            ],
        })
    }
}

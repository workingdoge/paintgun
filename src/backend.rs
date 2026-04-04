use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::emit::{
    emit_kotlin_module_scaffold, emit_store_kotlin, emit_store_swift, emit_store_web_tokens_ts,
    emit_swift_package_scaffold, emit_web_tokens_package_scaffold, Contract,
    ANDROID_COMPOSE_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION, WEB_TOKENS_TS_API_VERSION,
};
use crate::policy::Policy;
use crate::resolver::{Input, ResolverDoc, TokenStore};
use crate::web_css::{
    assemble_css_compat_stylesheet, emit_component_package_stylesheet,
    emit_component_package_types, emit_css_token_stylesheet_for_build,
    emit_css_token_stylesheet_for_compose,
};

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
    AndroidCompose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendArtifactKind {
    PrimaryTokenOutput,
    TokenStylesheet,
    SystemStylesheet,
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
    pub legacy_slot: Option<LegacyTargetSlot>,
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
    fn planned_artifacts(&self) -> Vec<BackendArtifact>;
    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError>;
}

struct CssBackend;
struct SwiftBackend;
struct AndroidComposeBackend;
struct WebTokensTsBackend;

static CSS_BACKEND: CssBackend = CssBackend;
static SWIFT_BACKEND: SwiftBackend = SwiftBackend;
static ANDROID_COMPOSE_BACKEND: AndroidComposeBackend = AndroidComposeBackend;
static WEB_TOKENS_TS_BACKEND: WebTokensTsBackend = WebTokensTsBackend;

fn builtin_backends() -> [&'static dyn TargetBackend; 4] {
    [
        &CSS_BACKEND,
        &SWIFT_BACKEND,
        &ANDROID_COMPOSE_BACKEND,
        &WEB_TOKENS_TS_BACKEND,
    ]
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

impl TargetBackend for CssBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "web-css-vars",
            aliases: &["css"],
            api_version: None,
            capabilities: BackendCapabilities {
                requires_contracts: true,
                emits_package_scaffold: false,
                scope: BackendScope::SystemPackage,
            },
            legacy_slot: Some(LegacyTargetSlot::Css),
        }
    }

    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        crate::contexts::layered_inputs(axes, None)
    }

    fn planned_artifacts(&self) -> Vec<BackendArtifact> {
        vec![
            BackendArtifact {
                kind: BackendArtifactKind::PrimaryTokenOutput,
                relative_path: PathBuf::from("tokens.css"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::TokenStylesheet,
                relative_path: PathBuf::from("tokens.vars.css"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::SystemStylesheet,
                relative_path: PathBuf::from("components.css"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::TypeDeclarations,
                relative_path: PathBuf::from("tokens.d.ts"),
                api_version: None,
            },
        ]
    }

    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError> {
        let contracts = request
            .contracts
            .ok_or_else(|| BackendError::new("backend web-css-vars requires contracts"))?;
        let token_css = match request.source {
            BackendSource::Build { doc } => {
                emit_css_token_stylesheet_for_build(doc, request.store, request.policy)
            }
            BackendSource::Compose { axes } => {
                emit_css_token_stylesheet_for_compose(axes, request.store, request.policy)
            }
        };
        let component_css = emit_component_package_stylesheet(contracts);
        let compatibility_css = assemble_css_compat_stylesheet(&token_css, &component_css);
        let css_path = request.out_dir.join("tokens.css");
        write_bytes(&css_path, compatibility_css.as_bytes())?;
        let token_css_path = request.out_dir.join("tokens.vars.css");
        write_bytes(&token_css_path, token_css.as_bytes())?;
        let component_css_path = request.out_dir.join("components.css");
        write_bytes(&component_css_path, component_css.as_bytes())?;
        let dts = emit_component_package_types(contracts);
        let dts_path = request.out_dir.join("tokens.d.ts");
        write_bytes(&dts_path, dts.as_bytes())?;

        Ok(BackendEmission {
            backend_id: self.spec().id,
            artifacts: self.planned_artifacts(),
        })
    }
}

impl TargetBackend for SwiftBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "swift-tokens",
            aliases: &["swift"],
            api_version: Some(SWIFT_EMITTER_API_VERSION),
            capabilities: BackendCapabilities {
                requires_contracts: false,
                emits_package_scaffold: true,
                scope: BackendScope::TokenBackend,
            },
            legacy_slot: Some(LegacyTargetSlot::Swift),
        }
    }

    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        crate::contexts::layered_inputs(axes, None)
            .into_iter()
            .filter(|input| input.len() <= 1)
            .collect()
    }

    fn planned_artifacts(&self) -> Vec<BackendArtifact> {
        vec![
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
                relative_path: PathBuf::from("swift/Sources/PaintgunTokens/PaintgunTokens.swift"),
                api_version: self.spec().api_version,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageTest,
                relative_path: PathBuf::from(
                    "swift/Tests/PaintgunTokensTests/PaintgunTokensTests.swift",
                ),
                api_version: None,
            },
        ]
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
            artifacts: self.planned_artifacts(),
        })
    }
}

impl TargetBackend for AndroidComposeBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "android-compose-tokens",
            aliases: &["kotlin"],
            api_version: Some(ANDROID_COMPOSE_EMITTER_API_VERSION),
            capabilities: BackendCapabilities {
                requires_contracts: false,
                emits_package_scaffold: true,
                scope: BackendScope::TokenBackend,
            },
            legacy_slot: Some(LegacyTargetSlot::AndroidCompose),
        }
    }

    fn required_inputs(&self, axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        crate::contexts::layered_inputs(axes, None)
            .into_iter()
            .filter(|input| input.len() <= 1)
            .collect()
    }

    fn planned_artifacts(&self) -> Vec<BackendArtifact> {
        vec![
            BackendArtifact {
                kind: BackendArtifactKind::PrimaryTokenOutput,
                relative_path: PathBuf::from("tokens.kt"),
                api_version: self.spec().api_version,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageSettings,
                relative_path: PathBuf::from("android/settings.gradle.kts"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageBuildScript,
                relative_path: PathBuf::from("android/build.gradle.kts"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageSource,
                relative_path: PathBuf::from("android/src/main/kotlin/paintgun/PaintgunTokens.kt"),
                api_version: self.spec().api_version,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageTest,
                relative_path: PathBuf::from(
                    "android/src/test/kotlin/paintgun/PaintgunTokensSmokeTest.kt",
                ),
                api_version: None,
            },
        ]
    }

    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError> {
        let kotlin = emit_store_kotlin(request.store, request.policy);
        let source_path = request.out_dir.join("tokens.kt");
        write_bytes(&source_path, kotlin.as_bytes())?;
        emit_kotlin_module_scaffold(request.out_dir, &kotlin).map_err(|e| {
            BackendError::new(format!("failed to write android module scaffold: {e}"))
        })?;

        Ok(BackendEmission {
            backend_id: self.spec().id,
            artifacts: self.planned_artifacts(),
        })
    }
}

impl TargetBackend for WebTokensTsBackend {
    fn spec(&self) -> BackendSpec {
        BackendSpec {
            id: "web-tokens-ts",
            aliases: &[],
            api_version: Some(WEB_TOKENS_TS_API_VERSION),
            capabilities: BackendCapabilities {
                requires_contracts: false,
                emits_package_scaffold: true,
                scope: BackendScope::TokenBackend,
            },
            legacy_slot: None,
        }
    }

    fn required_inputs(&self, _axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
        Vec::new()
    }

    fn planned_artifacts(&self) -> Vec<BackendArtifact> {
        vec![
            BackendArtifact {
                kind: BackendArtifactKind::PrimaryTokenOutput,
                relative_path: PathBuf::from("tokens.ts"),
                api_version: self.spec().api_version,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageManifest,
                relative_path: PathBuf::from("web/package.json"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageSettings,
                relative_path: PathBuf::from("web/tsconfig.json"),
                api_version: None,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageSource,
                relative_path: PathBuf::from("web/src/index.ts"),
                api_version: self.spec().api_version,
            },
            BackendArtifact {
                kind: BackendArtifactKind::PackageTest,
                relative_path: PathBuf::from("web/src/index.test.ts"),
                api_version: None,
            },
        ]
    }

    fn emit(&self, request: &BackendRequest<'_>) -> Result<BackendEmission, BackendError> {
        let web_tokens = emit_store_web_tokens_ts(request.store, request.policy);
        let source_path = request.out_dir.join("tokens.ts");
        write_bytes(&source_path, web_tokens.as_bytes())?;
        emit_web_tokens_package_scaffold(request.out_dir, &web_tokens).map_err(|e| {
            BackendError::new(format!("failed to write web token package scaffold: {e}"))
        })?;

        Ok(BackendEmission {
            backend_id: self.spec().id,
            artifacts: self.planned_artifacts(),
        })
    }
}

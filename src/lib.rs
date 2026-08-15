//! `dev.mcpg.credential.gcp-impersonation` — `credential_issuer` plugin.
//!
//! Mints short-lived GCP credentials per caller request via the IAM
//! Credentials REST API. The gateway authenticates with its own base
//! identity (GKE Workload Identity / GCE metadata server, or an
//! operator-supplied token) and **impersonates** a target service
//! account chosen by mapping the caller's `PluginIdentity`, returning
//! either an OAuth2 access token (`generateAccessToken`) or an OIDC ID
//! token (`generateIdToken`).
//!
//! Mirrors `libs/plugins/credential/vault-dynamic-db` (reqwest + bundled
//! runtime) and reuses the identity-mapping + Verified-trust-gate +
//! allowlist pattern from `libs/plugins/credential/aws-sts`.
//!
//! # Scope
//!
//! - **Impersonation**: `generateAccessToken` (scopes + lifetime) and
//!   `generateIdToken` (audience + includeEmail), with an operator-fixed
//!   delegate chain.
//! - **Base auth**: metadata server (Workload Identity / GCE) or a
//!   static operator token. Service-account-key (RS256 JWT-bearer) is a
//!   deferred follow-up.
//! - **Identity mapping**: static / subject_id / from_role / template —
//!   identity-derived target SA emails require Verified trust + pass an
//!   SA-email shape check + an optional per-target allowlist.
//! - **No revocation**: GCP short-lived tokens auto-expire; `revoke` is
//!   a no-op.

mod client;
mod config;
mod identity_mapping;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{
    BaseAuth, ConfigError, GcpImpersonationConfig, IdentityMapping, TargetConfig, TokenKind,
};

const PLUGIN_ID: &str = "dev.mcpg.credential.gcp-impersonation";

pub struct GcpImpersonationPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: GcpImpersonationConfig,
    client: client::GcpClient,
    /// Built lazily on first sync (FFI) call so async-only consumers /
    /// tests never build (and never drop in an async context) a runtime.
    sync_runtime: OnceLock<Runtime>,
}

impl GcpImpersonationPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = GcpImpersonationConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "gcp-impersonation: config parse failed; refusing to register"
            );
            panic!(
                "gcp-impersonation config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: GcpImpersonationConfig) -> Self {
        let client = client::GcpClient::new(&cfg)
            .unwrap_or_else(|err| panic!("gcp-impersonation: HTTP client init failed: {err}"));
        tracing::info!(
            plugin_id = PLUGIN_ID,
            iam_endpoint = %cfg.iam_credentials_endpoint,
            target_count = cfg.targets.len(),
            "gcp-impersonation: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "GCP Service-Account Impersonation".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                client,
                sync_runtime: OnceLock::new(),
            }),
        }
    }
}

async fn issue_inner(
    inner: &Inner,
    identity: &PluginIdentity,
    target_name: &str,
) -> Result<IssuedCredential, CredentialError> {
    let target =
        inner
            .config
            .targets
            .get(target_name)
            .ok_or_else(|| CredentialError::Misconfigured {
                reason: format!("unknown target: {target_name}"),
            })?;

    let sa = match identity_mapping::resolve_target(identity, target) {
        identity_mapping::Resolution::Target {
            email,
            identity_derived,
        } => {
            // A target SA driven by caller-controlled identity must come
            // from a Verified principal. Spoofable header-asserted /
            // anonymous callers must not steer which GCP identity — and
            // thus which cloud permissions — is impersonated.
            if identity_derived && identity.trust_level != "verified" {
                metric_issue(target_name, "untrusted_identity");
                return Err(CredentialError::NotAuthorized {
                    reason: format!(
                        "identity-derived service account requires Verified trust; caller trust is `{}`",
                        identity.trust_level
                    ),
                });
            }
            // The SA email is interpolated into the IAM Credentials URL
            // path; reject anything that isn't a valid SA email so a
            // crafted identity can't steer the call elsewhere.
            if !identity_mapping::is_valid_sa_email(&email) {
                metric_issue(target_name, "invalid_service_account");
                return Err(CredentialError::NotAuthorized {
                    reason: "resolved value is not a valid service-account email".into(),
                });
            }
            if let Some(allow) = &target.allowed_service_accounts
                && !allow.iter().any(|a| a == &email)
            {
                metric_issue(target_name, "sa_not_allowed");
                return Err(CredentialError::NotAuthorized {
                    reason:
                        "resolved service account is not in this target's allowed_service_accounts"
                            .into(),
                });
            }
            email
        }
        identity_mapping::Resolution::EmptyDerived { reason } => {
            metric_issue(target_name, "empty_identity");
            return Err(CredentialError::NotAuthorized { reason });
        }
        identity_mapping::Resolution::SubstitutionFailed { field } => {
            metric_issue(target_name, "substitution_failed");
            return Err(CredentialError::NotAuthorized {
                reason: format!(
                    "identity template substitution failed: field `{field}` is None or out-of-bounds"
                ),
            });
        }
    };

    let started = std::time::Instant::now();
    let (issued, part_key, kind_label) = match target.token_kind {
        TokenKind::AccessToken => (
            inner
                .client
                .generate_access_token(
                    &sa,
                    &target.scopes,
                    target.lifetime_seconds,
                    &target.delegates,
                )
                .await?,
            "access_token",
            "access_token",
        ),
        TokenKind::IdToken => {
            // Validated non-empty at config load.
            let audience = target.audience.as_deref().unwrap_or_default();
            (
                inner
                    .client
                    .generate_id_token(
                        &sa,
                        audience,
                        target.include_email,
                        target.id_token_assumed_ttl_seconds,
                        &target.delegates,
                    )
                    .await?,
                "id_token",
                "id_token",
            )
        }
    };
    metrics::histogram!(
        "mcpg_gcp_impersonation_issue_latency_ms",
        "target" => target_name.to_owned(),
    )
    .record(started.elapsed().as_millis() as f64);
    metric_issue(target_name, "ok");

    let ttl = cap_ttl_seconds(issued.ttl_seconds, target.max_cache_ttl_ms);
    let mut metadata = BTreeMap::new();
    metadata.insert("gcp.service_account".to_string(), sa);
    metadata.insert("gcp.token_kind".to_string(), kind_label.to_string());
    if !target.scopes.is_empty() {
        metadata.insert("gcp.scopes".to_string(), target.scopes.join(" "));
    }
    if let Some(subject) = identity.subject_id.as_deref() {
        metadata.insert("gcp.caller_subject".to_string(), sanitize_subject(subject));
    }
    let mut parts = BTreeMap::new();
    parts.insert(part_key.to_string(), issued.token.clone());

    Ok(IssuedCredential {
        value: Some(issued.token),
        parts,
        ttl_seconds: ttl,
        // GCP short-lived tokens have no per-token revocation API.
        lease_id: None,
        issued_at: now_rfc3339(),
        metadata,
    })
}

fn metric_issue(target: &str, result: &str) {
    metrics::counter!(
        "mcpg_gcp_impersonation_issue_total",
        "target" => target.to_owned(),
        "result" => result.to_owned(),
    )
    .increment(1);
}

/// Attribution-only label for the audit ledger; not an authorization
/// boundary. Strip control chars + clamp length so a junk subject can't
/// pollute logs.
fn sanitize_subject(subject: &str) -> String {
    subject
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Cap the cached credential TTL (seconds) at the operator's
/// millisecond limit, with a 1-second floor.
fn cap_ttl_seconds(token_ttl_secs: u64, max_cache_ttl_ms: u64) -> u64 {
    (max_cache_ttl_ms / 1000).max(1).min(token_ttl_secs)
}

#[async_trait]
impl CredentialIssuer for GcpImpersonationPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, identity, target).await
    }

    // GCP short-lived tokens auto-expire; no revocation primitive.
}

impl SyncCredentialIssuer for GcpImpersonationPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let runtime = self.inner.sync_runtime.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("gcp-impersonation: failed to build tokio runtime")
        });
        let inner = Arc::clone(&self.inner);
        let identity = identity.clone();
        let target = target.to_owned();
        runtime.block_on(async move { issue_inner(&inner, &identity, &target).await })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: GcpImpersonationPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> GcpImpersonationPlugin {
                GcpImpersonationPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SA: &str = "svc@my-proj.iam.gserviceaccount.com";

    fn cap_ttl(secs: u64, ms: u64) -> u64 {
        cap_ttl_seconds(secs, ms)
    }

    #[test]
    fn cap_ttl_clamps_and_floors() {
        assert_eq!(cap_ttl(3600, 60_000), 60);
        assert_eq!(cap_ttl(45, 3_600_000), 45);
        assert_eq!(cap_ttl(3600, 500), 1);
    }

    fn identity(trust: &str, subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: trust.into(),
            trust_level: trust.into(),
            subject_id: Some(subject.into()),
            auth_provider: Some("okta".into()),
            issuer: Some("https://okta.example.com".into()),
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    fn static_subject_plugin(allowed: Option<Vec<&str>>) -> GcpImpersonationPlugin {
        let mut target = json!({
            "service_account": SA,
            "identity_mapping": "subject_id",
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
        });
        if let Some(a) = allowed {
            target["allowed_service_accounts"] = json!(a);
        }
        let cfg = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "ya29.base" },
            "targets": { "t": target }
        });
        GcpImpersonationPlugin::from_config_json(&cfg.to_string())
    }

    // ---- construction ----

    #[test]
    fn from_config_json_succeeds() {
        let p = static_subject_plugin(None);
        assert_eq!(p.inner.manifest.id, PLUGIN_ID);
        assert_eq!(p.inner.manifest.plugin_class, PluginClass::CredentialIssuer);
    }

    #[test]
    #[should_panic(expected = "gcp-impersonation config parse failed")]
    fn malformed_config_panics() {
        GcpImpersonationPlugin::from_config_json("{ not json");
    }

    #[test]
    #[should_panic(expected = "gcp-impersonation config parse failed")]
    fn empty_targets_panics() {
        let cfg = json!({ "base_auth": { "kind": "static_access_token", "access_token": "t" }, "targets": {} });
        GcpImpersonationPlugin::from_config_json(&cfg.to_string());
    }

    // ---- identity guards (sync path; return before any HTTP) ----

    #[test]
    fn issue_rejects_identity_derived_sa_from_unverified_caller() {
        let p = static_subject_plugin(None);
        let err = SyncCredentialIssuer::issue(
            &p,
            &identity("header_asserted", "other@my-proj.iam.gserviceaccount.com"),
            "t",
            &Value::Null,
        )
        .expect_err("unverified identity-derived SA must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("Verified trust")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_non_sa_subject() {
        let p = static_subject_plugin(None);
        let err = SyncCredentialIssuer::issue(
            &p,
            &identity("verified", "not-an-email"),
            "t",
            &Value::Null,
        )
        .expect_err("a non-SA subject must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("service-account email")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_sa_outside_allowlist() {
        let p = static_subject_plugin(Some(vec!["only@my-proj.iam.gserviceaccount.com"]));
        let err = SyncCredentialIssuer::issue(
            &p,
            &identity("verified", "other@my-proj.iam.gserviceaccount.com"),
            "t",
            &Value::Null,
        )
        .expect_err("SA outside allowlist must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("allowed_service_accounts")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_unknown_target() {
        let p = static_subject_plugin(None);
        let err = SyncCredentialIssuer::issue(&p, &identity("verified", SA), "nope", &Value::Null)
            .expect_err("unknown target must be refused");
        assert!(
            matches!(err, CredentialError::Misconfigured { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn revoke_is_noop_ok() {
        let p = static_subject_plugin(None);
        assert!(SyncCredentialIssuer::revoke(&p, "any").is_ok());
    }

    // ---- wiremock: real IAM Credentials request/response ----

    fn static_access_plugin(iam_endpoint: &str) -> GcpImpersonationPlugin {
        let cfg = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "ya29.base" },
            "iam_credentials_endpoint": iam_endpoint,
            "targets": {
                "t": { "service_account": SA, "scopes": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime_seconds": 3600 }
            }
        });
        GcpImpersonationPlugin::from_config_json(&cfg.to_string())
    }

    #[tokio::test]
    async fn generate_access_token_happy_path() {
        let server = MockServer::start().await;
        let expire = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
        Mock::given(method("POST"))
            .and(path_regex(r":generateAccessToken$"))
            .and(header("authorization", "Bearer ya29.base"))
            .and(body_string_contains("\"lifetime\":\"3600s\""))
            .and(body_string_contains("cloud-platform"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ya29.impersonated",
                "expireTime": expire,
            })))
            .expect(1)
            .mount(&server)
            .await;
        let p = static_access_plugin(&server.uri());
        let cred = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("ya29.impersonated"));
        assert_eq!(
            cred.parts.get("access_token").map(String::as_str),
            Some("ya29.impersonated")
        );
        assert!(cred.lease_id.is_none());
        assert!(
            (3590..=3600).contains(&cred.ttl_seconds),
            "{}",
            cred.ttl_seconds
        );
        assert_eq!(
            cred.metadata.get("gcp.service_account").map(String::as_str),
            Some(SA)
        );
        assert_eq!(
            cred.metadata.get("gcp.token_kind").map(String::as_str),
            Some("access_token")
        );
    }

    #[tokio::test]
    async fn generate_id_token_happy_path() {
        let server = MockServer::start().await;
        let exp = chrono::Utc::now().timestamp() + 3000;
        let payload = base64_url(&format!("{{\"exp\":{exp}}}"));
        let jwt = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig");
        Mock::given(method("POST"))
            .and(path_regex(r":generateIdToken$"))
            .and(body_string_contains(
                "\"audience\":\"https://svc.example.com\"",
            ))
            .and(body_string_contains("\"includeEmail\":true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": jwt })))
            .expect(1)
            .mount(&server)
            .await;
        let cfg = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "ya29.base" },
            "iam_credentials_endpoint": server.uri(),
            "targets": { "idt": { "service_account": SA, "token_kind": "id_token", "audience": "https://svc.example.com" } }
        });
        let p = GcpImpersonationPlugin::from_config_json(&cfg.to_string());
        let cred = CredentialIssuer::issue(&p, &identity("verified", "alice"), "idt", &json!({}))
            .await
            .unwrap();
        assert!(cred.value.as_deref().unwrap().starts_with("eyJ"));
        assert_eq!(
            cred.metadata.get("gcp.token_kind").map(String::as_str),
            Some("id_token")
        );
        assert!(
            (2990..=3000).contains(&cred.ttl_seconds),
            "{}",
            cred.ttl_seconds
        );
    }

    #[tokio::test]
    async fn permission_denied_maps_not_authorized_and_redacts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r":generateAccessToken$"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": { "code": 403, "status": "PERMISSION_DENIED", "message": "LEAKED_TOKEN_abc denied" }
            })))
            .mount(&server)
            .await;
        let p = static_access_plugin(&server.uri());
        let err = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap_err();
        let CredentialError::NotAuthorized { reason } = err else {
            panic!("expected NotAuthorized, got {err:?}");
        };
        assert!(reason.contains("PERMISSION_DENIED"));
        assert!(
            !reason.contains("LEAKED_TOKEN_abc"),
            "message leaked: {reason}"
        );
    }

    #[tokio::test]
    async fn resource_exhausted_maps_throttled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r":generateAccessToken$"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "error": { "status": "RESOURCE_EXHAUSTED" }
            })))
            .mount(&server)
            .await;
        let p = static_access_plugin(&server.uri());
        let err = CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialError::Throttled { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn delegates_serialized_when_present() {
        let server = MockServer::start().await;
        let expire = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
        Mock::given(method("POST"))
            .and(path_regex(r":generateAccessToken$"))
            .and(body_string_contains(
                "projects/-/serviceAccounts/mid@my-proj.iam.gserviceaccount.com",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ya29.x", "expireTime": expire
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cfg = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "ya29.base" },
            "iam_credentials_endpoint": server.uri(),
            "targets": { "t": { "service_account": SA, "scopes": ["s"], "delegates": ["mid@my-proj.iam.gserviceaccount.com"] } }
        });
        let p = GcpImpersonationPlugin::from_config_json(&cfg.to_string());
        CredentialIssuer::issue(&p, &identity("verified", "alice"), "t", &json!({}))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn metadata_server_base_auth_fetches_then_impersonates() {
        let server = MockServer::start().await;
        let expire = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
        // Base token from the (mocked) metadata server — must carry the
        // Metadata-Flavor header. expect(1) proves the base token is
        // cached across both issue calls.
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .and(header("metadata-flavor", "Google"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "ya29.from-metadata", "expires_in": 3599, "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r":generateAccessToken$"))
            .and(header("authorization", "Bearer ya29.from-metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": "ya29.impersonated", "expireTime": expire
            })))
            .expect(2)
            .mount(&server)
            .await;
        let cfg = json!({
            "base_auth": { "kind": "metadata_server", "endpoint": server.uri() },
            "iam_credentials_endpoint": server.uri(),
            "targets": { "t": { "service_account": SA, "scopes": ["s"] } }
        });
        let p = GcpImpersonationPlugin::from_config_json(&cfg.to_string());
        let id = identity("verified", "alice");
        for _ in 0..2 {
            let cred = CredentialIssuer::issue(&p, &id, "t", &json!({}))
                .await
                .unwrap();
            assert_eq!(cred.value.as_deref(), Some("ya29.impersonated"));
        }
    }

    fn base64_url(s: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
    }
}

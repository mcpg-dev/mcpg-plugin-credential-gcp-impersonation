//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.gcp-impersonation`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpImpersonationConfig {
    /// Base auth used to CALL the IAM Credentials API. Default
    /// `metadata_server` (the GKE Workload Identity / GCE path).
    #[serde(default)]
    pub base_auth: BaseAuth,

    /// IAM Credentials API host. Default
    /// `https://iamcredentials.googleapis.com`. Override only for
    /// tests (wiremock) / a private Google API endpoint. Must be
    /// `https://` (or `http://localhost` for tests).
    #[serde(default = "default_iam_endpoint")]
    pub iam_credentials_endpoint: String,

    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
    /// Refresh the cached base token this many ms before its expiry.
    #[serde(default = "default_refresh_buffer_ms")]
    pub refresh_buffer_ms: u64,

    /// Per-target mapping. At least one target required.
    pub targets: BTreeMap<String, TargetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BaseAuth {
    /// GKE Workload Identity / GCE metadata server. Default.
    MetadataServer {
        /// Metadata host override (tests). Default
        /// `http://metadata.google.internal`.
        #[serde(default = "default_metadata_endpoint")]
        endpoint: String,
        /// SA name on the metadata server. Default `default`.
        #[serde(default = "default_metadata_sa")]
        service_account: String,
    },
    /// Operator-supplied Bearer token (tests / simple setups). The
    /// gateway calls AssumeRole-equivalent with this token directly.
    StaticAccessToken { access_token: String },
}

impl Default for BaseAuth {
    fn default() -> Self {
        Self::MetadataServer {
            endpoint: default_metadata_endpoint(),
            service_account: default_metadata_sa(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    #[default]
    AccessToken,
    IdToken,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMapping {
    /// Always impersonate `target.service_account`. Default.
    #[default]
    Static,
    /// Use `identity.subject_id` as the SA email.
    SubjectId,
    /// Substitute identity fields into `service_account_template`.
    Template,
    /// Use `identity.roles[0]` as the SA email.
    FromRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// `access_token` (default) | `id_token`.
    #[serde(default)]
    pub token_kind: TokenKind,

    /// Target service-account email. Required (+validated) for
    /// `identity_mapping = static`; the operator fallback otherwise.
    #[serde(default)]
    pub service_account: String,

    #[serde(default)]
    pub identity_mapping: IdentityMapping,

    /// Required for `identity_mapping = template`. `${identity.<field>}`
    /// substitution; the result MUST be a valid SA email.
    #[serde(default)]
    pub service_account_template: Option<String>,

    /// Optional allowlist of SA emails this target may impersonate.
    /// An identity-derived email MUST appear here when set.
    #[serde(default)]
    pub allowed_service_accounts: Option<Vec<String>>,

    /// `access_token` only. OAuth scopes; non-empty when
    /// `token_kind = access_token`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// `access_token` only. Requested lifetime (seconds), `1..=3600`
    /// (or `..=43200` with `allow_extended_lifetime`). `None` → GCP
    /// default (3600).
    #[serde(default)]
    pub lifetime_seconds: Option<u32>,
    /// Permit a >3600s lifetime (needs the org-policy lifetime
    /// extension on the SA).
    #[serde(default)]
    pub allow_extended_lifetime: bool,

    /// `id_token` only. Required when `token_kind = id_token`.
    #[serde(default)]
    pub audience: Option<String>,
    /// `id_token` only. Embed `email`/`email_verified`. Default true.
    #[serde(default = "default_true")]
    pub include_email: bool,
    /// Fallback TTL (seconds) for an ID token whose `exp` can't be
    /// decoded. Default 3300 (5 min under the 3600 ceiling).
    #[serde(default = "default_id_token_ttl")]
    pub id_token_assumed_ttl_seconds: u64,

    /// Optional operator-fixed delegation chain — bare SA emails or
    /// full `projects/-/serviceAccounts/<email>` resource names.
    /// Never identity-derived.
    #[serde(default)]
    pub delegates: Vec<String>,

    /// Cache TTL cap (ms). Issued ttl = `min(token_expiry,
    /// max_cache_ttl_ms/1000)`. `1..=86_400_000`. Default 3_600_000.
    #[serde(default = "default_max_cache_ttl_ms")]
    pub max_cache_ttl_ms: u64,
}

const MAX_LIFETIME: u32 = 3600;
const MAX_EXTENDED_LIFETIME: u32 = 43_200;
const MIN_LIFETIME: u32 = 1;

fn default_iam_endpoint() -> String {
    "https://iamcredentials.googleapis.com".into()
}
fn default_metadata_endpoint() -> String {
    "http://metadata.google.internal".into()
}
fn default_metadata_sa() -> String {
    "default".into()
}
fn default_connect_timeout_ms() -> u64 {
    5000
}
fn default_operation_timeout_ms() -> u64 {
    15_000
}
fn default_refresh_buffer_ms() -> u64 {
    60_000
}
fn default_true() -> bool {
    true
}
fn default_id_token_ttl() -> u64 {
    3300
}
fn default_max_cache_ttl_ms() -> u64 {
    3_600_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.gcp-impersonation config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error(
        "credential.gcp-impersonation: {field} must be https:// (or http://localhost for tests)"
    )]
    InvalidEndpointScheme { field: &'static str },
    #[error("credential.gcp-impersonation: targets must be non-empty")]
    EmptyTargets,
    #[error("credential.gcp-impersonation: base_auth.static_access_token.access_token is empty")]
    EmptyStaticToken,
    #[error(
        "credential.gcp-impersonation: base_auth.metadata_server.service_account `{sa}` is not a valid SA alias or email"
    )]
    InvalidMetadataServiceAccount { sa: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` has identity_mapping=static but service_account is empty"
    )]
    StaticTargetMissingSa { name: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` service_account `{sa}` is not a valid service-account email"
    )]
    InvalidServiceAccount { name: String, sa: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` has identity_mapping=template but service_account_template is missing"
    )]
    TemplateTargetMissingTemplate { name: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` allowed_service_accounts entry `{sa}` is not a valid service-account email"
    )]
    InvalidAllowedServiceAccount { name: String, sa: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` token_kind=access_token requires non-empty scopes"
    )]
    AccessTokenMissingScopes { name: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` lifetime_seconds={secs} out of range (1..={max})"
    )]
    InvalidLifetime { name: String, secs: u32, max: u32 },
    #[error(
        "credential.gcp-impersonation: target `{name}` token_kind=id_token requires a non-empty audience"
    )]
    IdTokenMissingAudience { name: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` token_kind=id_token must not set scopes/lifetime_seconds"
    )]
    IdTokenUnexpectedField { name: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` delegate `{d}` is not a valid SA email or resource name"
    )]
    InvalidDelegate { name: String, d: String },
    #[error(
        "credential.gcp-impersonation: target `{name}` max_cache_ttl_ms={ttl}; must be 1..=86_400_000"
    )]
    InvalidMaxCacheTtl { name: String, ttl: u64 },
}

/// An endpoint override is config-origin, but constrain it: `https://`
/// anywhere, or `http://` only to an exact localhost host (the
/// test/emulator carve-out). Plain `http://` to any other host is an
/// operator footgun (cleartext bearer) — reject it.
pub(crate) fn is_allowed_endpoint(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty();
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return matches!(
            host,
            "localhost" | "127.0.0.1" | "[::1]" | "metadata.google.internal"
        );
    }
    false
}

impl GcpImpersonationConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !is_allowed_endpoint(&self.iam_credentials_endpoint) {
            return Err(ConfigError::InvalidEndpointScheme {
                field: "iam_credentials_endpoint",
            });
        }
        match &self.base_auth {
            BaseAuth::MetadataServer {
                endpoint,
                service_account,
            } => {
                if !is_allowed_endpoint(endpoint) {
                    return Err(ConfigError::InvalidEndpointScheme {
                        field: "base_auth.metadata_server.endpoint",
                    });
                }
                // The SA alias is interpolated into the metadata token
                // URL path (`.../service-accounts/{sa}/token`); even
                // though it is operator-fixed, reject anything that
                // isn't a GCE SA alias (`default`, `[a-z0-9-]+`) or a
                // full SA email so it can't alter the metadata path.
                let alias_ok = !service_account.is_empty()
                    && service_account
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
                if !alias_ok && !crate::identity_mapping::is_valid_sa_email(service_account) {
                    return Err(ConfigError::InvalidMetadataServiceAccount {
                        sa: service_account.clone(),
                    });
                }
            }
            BaseAuth::StaticAccessToken { access_token } => {
                if access_token.is_empty() {
                    return Err(ConfigError::EmptyStaticToken);
                }
            }
        }
        if self.targets.is_empty() {
            return Err(ConfigError::EmptyTargets);
        }
        for (name, target) in &self.targets {
            self.validate_target(name, target)?;
        }
        Ok(())
    }

    fn validate_target(&self, name: &str, target: &TargetConfig) -> Result<(), ConfigError> {
        use crate::identity_mapping::{is_valid_delegate, is_valid_sa_email};

        match target.identity_mapping {
            IdentityMapping::Static => {
                if target.service_account.is_empty() {
                    return Err(ConfigError::StaticTargetMissingSa { name: name.into() });
                }
                if !is_valid_sa_email(&target.service_account) {
                    return Err(ConfigError::InvalidServiceAccount {
                        name: name.into(),
                        sa: target.service_account.clone(),
                    });
                }
            }
            IdentityMapping::Template => {
                if target
                    .service_account_template
                    .as_deref()
                    .map(str::is_empty)
                    .unwrap_or(true)
                {
                    return Err(ConfigError::TemplateTargetMissingTemplate { name: name.into() });
                }
            }
            IdentityMapping::SubjectId | IdentityMapping::FromRole => {
                // A non-empty operator fallback must itself be valid.
                if !target.service_account.is_empty() && !is_valid_sa_email(&target.service_account)
                {
                    return Err(ConfigError::InvalidServiceAccount {
                        name: name.into(),
                        sa: target.service_account.clone(),
                    });
                }
            }
        }

        if let Some(allow) = &target.allowed_service_accounts {
            for sa in allow {
                if !is_valid_sa_email(sa) {
                    return Err(ConfigError::InvalidAllowedServiceAccount {
                        name: name.into(),
                        sa: sa.clone(),
                    });
                }
            }
        }

        match target.token_kind {
            TokenKind::AccessToken => {
                if target.scopes.is_empty() {
                    return Err(ConfigError::AccessTokenMissingScopes { name: name.into() });
                }
                if let Some(secs) = target.lifetime_seconds {
                    let max = if target.allow_extended_lifetime {
                        MAX_EXTENDED_LIFETIME
                    } else {
                        MAX_LIFETIME
                    };
                    if !(MIN_LIFETIME..=max).contains(&secs) {
                        return Err(ConfigError::InvalidLifetime {
                            name: name.into(),
                            secs,
                            max,
                        });
                    }
                }
            }
            TokenKind::IdToken => {
                if target
                    .audience
                    .as_deref()
                    .map(str::is_empty)
                    .unwrap_or(true)
                {
                    return Err(ConfigError::IdTokenMissingAudience { name: name.into() });
                }
                if !target.scopes.is_empty() || target.lifetime_seconds.is_some() {
                    return Err(ConfigError::IdTokenUnexpectedField { name: name.into() });
                }
            }
        }

        for d in &target.delegates {
            if !is_valid_delegate(d) {
                return Err(ConfigError::InvalidDelegate {
                    name: name.into(),
                    d: d.clone(),
                });
            }
        }

        if target.max_cache_ttl_ms == 0 || target.max_cache_ttl_ms > 86_400_000 {
            return Err(ConfigError::InvalidMaxCacheTtl {
                name: name.into(),
                ttl: target.max_cache_ttl_ms,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SA: &str = "svc@my-proj.iam.gserviceaccount.com";

    fn minimal() -> serde_json::Value {
        json!({
            "base_auth": { "kind": "static_access_token", "access_token": "ya29.test" },
            "targets": {
                "ro": { "service_account": SA, "scopes": ["https://www.googleapis.com/auth/cloud-platform"] }
            }
        })
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let cfg = GcpImpersonationConfig::parse(&minimal().to_string()).unwrap();
        assert_eq!(
            cfg.iam_credentials_endpoint,
            "https://iamcredentials.googleapis.com"
        );
        let t = &cfg.targets["ro"];
        assert_eq!(t.token_kind, TokenKind::AccessToken);
        assert_eq!(t.identity_mapping, IdentityMapping::Static);
        assert_eq!(t.max_cache_ttl_ms, 3_600_000);
    }

    #[test]
    fn default_base_auth_is_metadata_server() {
        let cfg = GcpImpersonationConfig::parse(
            &json!({ "targets": { "ro": { "service_account": SA, "scopes": ["s"] } } }).to_string(),
        )
        .unwrap();
        assert!(matches!(cfg.base_auth, BaseAuth::MetadataServer { .. }));
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = minimal();
        v["bogus"] = json!(1);
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidJson(_)
        ));
    }

    #[test]
    fn rejects_empty_targets() {
        let v = json!({ "base_auth": { "kind": "static_access_token", "access_token": "t" }, "targets": {} });
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyTargets
        ));
    }

    #[test]
    fn rejects_bad_iam_endpoint_scheme() {
        let mut v = minimal();
        v["iam_credentials_endpoint"] = json!("ftp://iam");
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidEndpointScheme { .. }
        ));
    }

    #[test]
    fn rejects_plain_http_nonlocal_endpoint() {
        let mut v = minimal();
        v["iam_credentials_endpoint"] = json!("http://evil.example.com");
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidEndpointScheme { .. }
        ));
    }

    #[test]
    fn accepts_http_localhost_endpoint() {
        let mut v = minimal();
        v["iam_credentials_endpoint"] = json!("http://localhost:4599");
        assert!(GcpImpersonationConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_static_without_sa() {
        let mut v = minimal();
        v["targets"]["ro"]["service_account"] = json!("");
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::StaticTargetMissingSa { .. }
        ));
    }

    #[test]
    fn rejects_static_with_malformed_sa() {
        let mut v = minimal();
        v["targets"]["ro"]["service_account"] = json!("not-an-email");
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidServiceAccount { .. }
        ));
    }

    #[test]
    fn rejects_template_without_template() {
        let mut v = minimal();
        v["targets"]["ro"] = json!({ "identity_mapping": "template", "scopes": ["s"] });
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::TemplateTargetMissingTemplate { .. }
        ));
    }

    #[test]
    fn rejects_access_token_without_scopes() {
        let mut v = minimal();
        v["targets"]["ro"]["scopes"] = json!([]);
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::AccessTokenMissingScopes { .. }
        ));
    }

    #[test]
    fn rejects_id_token_without_audience() {
        let v = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "t" },
            "targets": { "idt": { "service_account": SA, "token_kind": "id_token" } }
        });
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::IdTokenMissingAudience { .. }
        ));
    }

    #[test]
    fn rejects_id_token_with_scopes() {
        let v = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "t" },
            "targets": { "idt": { "service_account": SA, "token_kind": "id_token", "audience": "https://x", "scopes": ["s"] } }
        });
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::IdTokenUnexpectedField { .. }
        ));
    }

    #[test]
    fn rejects_out_of_range_lifetime() {
        let mut v = minimal();
        v["targets"]["ro"]["lifetime_seconds"] = json!(7200);
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidLifetime { .. }
        ));
    }

    #[test]
    fn accepts_extended_lifetime_when_opted_in() {
        let mut v = minimal();
        v["targets"]["ro"]["lifetime_seconds"] = json!(7200);
        v["targets"]["ro"]["allow_extended_lifetime"] = json!(true);
        assert!(GcpImpersonationConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_bad_allowlist_entry() {
        let mut v = minimal();
        v["targets"]["ro"]["identity_mapping"] = json!("subject_id");
        v["targets"]["ro"]["allowed_service_accounts"] = json!([SA, "garbage"]);
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidAllowedServiceAccount { .. }
        ));
    }

    #[test]
    fn rejects_zero_ttl() {
        let mut v = minimal();
        v["targets"]["ro"]["max_cache_ttl_ms"] = json!(0);
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidMaxCacheTtl { .. }
        ));
    }

    #[test]
    fn rejects_empty_static_token() {
        let v = json!({
            "base_auth": { "kind": "static_access_token", "access_token": "" },
            "targets": { "ro": { "service_account": SA, "scopes": ["s"] } }
        });
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyStaticToken
        ));
    }

    #[test]
    fn rejects_metadata_sa_with_path_breakout() {
        let v = json!({
            "base_auth": { "kind": "metadata_server", "service_account": "default/../token" },
            "targets": { "ro": { "service_account": SA, "scopes": ["s"] } }
        });
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidMetadataServiceAccount { .. }
        ));
    }

    #[test]
    fn accepts_default_metadata_sa_alias() {
        let v = json!({
            "base_auth": { "kind": "metadata_server", "service_account": "default" },
            "targets": { "ro": { "service_account": SA, "scopes": ["s"] } }
        });
        assert!(GcpImpersonationConfig::parse(&v.to_string()).is_ok());
    }

    #[test]
    fn rejects_bad_delegate() {
        let mut v = minimal();
        v["targets"]["ro"]["delegates"] = json!(["not valid"]);
        assert!(matches!(
            GcpImpersonationConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidDelegate { .. }
        ));
    }
}

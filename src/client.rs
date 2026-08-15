//! GCP IAM Credentials REST client: base-token acquisition (metadata
//! server / static) + service-account impersonation
//! (`generateAccessToken` / `generateIdToken`).

use std::time::{Duration, Instant};

use base64::Engine as _;
use mcpg_plugin_protocol::credential::CredentialError;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex as TokioMutex;

use crate::config::{BaseAuth, GcpImpersonationConfig};
use crate::identity_mapping::delegate_resource_name;

pub(crate) struct GcpClient {
    http: reqwest::Client,
    /// IAM Credentials host, no trailing slash.
    iam_endpoint: String,
    refresh_buffer: Duration,
    base: BaseAuth,
    cached_base: TokioMutex<Option<CachedBaseToken>>,
}

struct CachedBaseToken {
    token: String,
    /// `None` = never expires (static token).
    expires_at: Option<Instant>,
}

pub(crate) struct IssuedToken {
    pub token: String,
    pub ttl_seconds: u64,
}

#[derive(Deserialize)]
struct MetadataTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct GenerateAccessTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireTime")]
    expire_time: String,
}

#[derive(Deserialize)]
struct GenerateIdTokenResponse {
    token: String,
}

impl GcpClient {
    pub(crate) fn new(cfg: &GcpImpersonationConfig) -> Result<Self, CredentialError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(cfg.connect_timeout_ms))
            .timeout(Duration::from_millis(cfg.operation_timeout_ms))
            .build()
            .map_err(|e| CredentialError::Backend {
                reason: format!("reqwest client init: {e}"),
            })?;
        Ok(Self {
            http,
            iam_endpoint: cfg
                .iam_credentials_endpoint
                .trim_end_matches('/')
                .to_owned(),
            refresh_buffer: Duration::from_millis(cfg.refresh_buffer_ms),
            base: cfg.base_auth.clone(),
            cached_base: TokioMutex::new(None),
        })
    }

    async fn invalidate_base(&self) {
        *self.cached_base.lock().await = None;
    }

    async fn base_bearer(&self, force_refresh: bool) -> Result<String, CredentialError> {
        let mut guard = self.cached_base.lock().await;
        if !force_refresh && let Some(c) = guard.as_ref() {
            let fresh = match c.expires_at {
                None => true,
                Some(exp) => Instant::now() + self.refresh_buffer < exp,
            };
            if fresh {
                return Ok(c.token.clone());
            }
        }
        let fetched = self.fetch_base_token().await?;
        let token = fetched.token.clone();
        *guard = Some(fetched);
        Ok(token)
    }

    async fn fetch_base_token(&self) -> Result<CachedBaseToken, CredentialError> {
        match &self.base {
            BaseAuth::StaticAccessToken { access_token } => Ok(CachedBaseToken {
                token: access_token.clone(),
                expires_at: None,
            }),
            BaseAuth::MetadataServer {
                endpoint,
                service_account,
            } => {
                let url = format!(
                    "{}/computeMetadata/v1/instance/service-accounts/{}/token",
                    endpoint.trim_end_matches('/'),
                    service_account
                );
                let resp = self
                    .http
                    .get(&url)
                    .header("Metadata-Flavor", "Google")
                    .send()
                    .await
                    .map_err(|e| CredentialError::Backend {
                        reason: format!("metadata server unreachable: {e}"),
                    })?;
                if !resp.status().is_success() {
                    return Err(CredentialError::Backend {
                        reason: format!("metadata server returned HTTP {}", resp.status().as_u16()),
                    });
                }
                let mt: MetadataTokenResponse =
                    resp.json().await.map_err(|e| CredentialError::Backend {
                        reason: format!("parse metadata token response: {e}"),
                    })?;
                let expires_at = (mt.expires_in > 0)
                    .then(|| Instant::now() + Duration::from_secs(mt.expires_in));
                Ok(CachedBaseToken {
                    token: mt.access_token,
                    expires_at,
                })
            }
        }
    }

    /// POST a JSON body to an IAM Credentials action URL, carrying the
    /// base bearer. On a 401 (stale base token), invalidate + retry
    /// once with a freshly-fetched base token.
    async fn post_iam(
        &self,
        url: &str,
        body: serde_json::Value,
    ) -> Result<String, CredentialError> {
        for attempt in 0..2 {
            let bearer = self.base_bearer(attempt == 1).await?;
            let resp = self
                .http
                .post(url)
                .bearer_auth(&bearer)
                .json(&body)
                .send()
                .await
                .map_err(|e| CredentialError::Backend {
                    reason: format!("IAM Credentials endpoint unreachable: {e}"),
                })?;
            let status = resp.status();
            if status.as_u16() == 401 && attempt == 0 {
                self.invalidate_base().await;
                continue;
            }
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(map_gcp_error(status, &text));
            }
            return resp.text().await.map_err(|e| CredentialError::Backend {
                reason: format!("read IAM Credentials response: {e}"),
            });
        }
        // Unreachable: attempt 1 always returns. Defensive fallback.
        Err(CredentialError::NotAuthorized {
            reason: "IAM Credentials returned HTTP 401 after base-token refresh".into(),
        })
    }

    pub(crate) async fn generate_access_token(
        &self,
        sa: &str,
        scopes: &[String],
        lifetime_seconds: Option<u32>,
        delegates: &[String],
    ) -> Result<IssuedToken, CredentialError> {
        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            self.iam_endpoint,
            encode_sa(sa)
        );
        let mut body = json!({ "scope": scopes });
        if let Some(l) = lifetime_seconds {
            body["lifetime"] = json!(format!("{l}s"));
        }
        if !delegates.is_empty() {
            body["delegates"] = json!(
                delegates
                    .iter()
                    .map(|d| delegate_resource_name(d))
                    .collect::<Vec<_>>()
            );
        }
        let text = self.post_iam(&url, body).await?;
        let parsed: GenerateAccessTokenResponse =
            serde_json::from_str(&text).map_err(|e| CredentialError::Backend {
                reason: format!("parse generateAccessToken response: {e}"),
            })?;
        Ok(IssuedToken {
            token: parsed.access_token,
            ttl_seconds: expire_time_to_ttl(&parsed.expire_time)?,
        })
    }

    pub(crate) async fn generate_id_token(
        &self,
        sa: &str,
        audience: &str,
        include_email: bool,
        assumed_ttl: u64,
        delegates: &[String],
    ) -> Result<IssuedToken, CredentialError> {
        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:generateIdToken",
            self.iam_endpoint,
            encode_sa(sa)
        );
        let mut body = json!({ "audience": audience, "includeEmail": include_email });
        if !delegates.is_empty() {
            body["delegates"] = json!(
                delegates
                    .iter()
                    .map(|d| delegate_resource_name(d))
                    .collect::<Vec<_>>()
            );
        }
        let text = self.post_iam(&url, body).await?;
        let parsed: GenerateIdTokenResponse =
            serde_json::from_str(&text).map_err(|e| CredentialError::Backend {
                reason: format!("parse generateIdToken response: {e}"),
            })?;
        let ttl = id_token_ttl(&parsed.token, assumed_ttl);
        Ok(IssuedToken {
            token: parsed.token,
            ttl_seconds: ttl,
        })
    }
}

/// Percent-encode the SA-email path segment. `is_valid_sa_email`
/// already restricts the charset; this encodes the one reserved byte
/// (`@`) and is defence-in-depth for anything else.
fn encode_sa(sa: &str) -> String {
    let mut out = String::with_capacity(sa.len() + 2);
    for b in sa.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// `generateAccessToken` returns an absolute RFC3339 `expireTime`; the
/// host cache wants a relative TTL. Clamp at 1s.
fn expire_time_to_ttl(expire_time: &str) -> Result<u64, CredentialError> {
    let dt = chrono::DateTime::parse_from_rfc3339(expire_time).map_err(|e| {
        CredentialError::Backend {
            reason: format!("parse expireTime `{expire_time}`: {e}"),
        }
    })?;
    Ok((dt.timestamp() - chrono::Utc::now().timestamp()).max(1) as u64)
}

/// `generateIdToken` returns no expiry; decode the JWT payload's `exp`
/// (read-only, no signature verification) to derive a TTL, falling back
/// to the operator's assumed TTL when it can't be decoded.
fn id_token_ttl(token: &str, fallback: u64) -> u64 {
    token
        .split('.')
        .nth(1)
        .and_then(|p| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("exp").and_then(serde_json::Value::as_i64))
        .map(|exp| (exp - chrono::Utc::now().timestamp()).max(1) as u64)
        .unwrap_or(fallback)
}

/// Map an IAM Credentials error onto the credential-issuer taxonomy.
/// Reads only the Google error `status` enum + HTTP code — never the
/// `message` (which can echo back submitted material).
pub(crate) fn map_gcp_error(status: reqwest::StatusCode, body: &str) -> CredentialError {
    let gstatus = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("status"))
                .and_then(|s| s.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let code = status.as_u16();
    let reason = if gstatus.is_empty() {
        format!("IAM Credentials returned HTTP {code}")
    } else {
        format!("IAM Credentials returned HTTP {code} ({gstatus})")
    };
    match gstatus.as_str() {
        "UNAUTHENTICATED" | "PERMISSION_DENIED" => CredentialError::NotAuthorized { reason },
        "RESOURCE_EXHAUSTED" => CredentialError::Throttled { reason },
        "INVALID_ARGUMENT" | "FAILED_PRECONDITION" | "NOT_FOUND" => {
            CredentialError::Misconfigured { reason }
        }
        "UNAVAILABLE" | "INTERNAL" | "DEADLINE_EXCEEDED" => CredentialError::Backend { reason },
        _ => match code {
            401 | 403 => CredentialError::NotAuthorized { reason },
            429 => CredentialError::Throttled { reason },
            400 | 404 => CredentialError::Misconfigured { reason },
            500..=599 => CredentialError::Backend { reason },
            400..=499 => CredentialError::Misconfigured { reason },
            _ => CredentialError::Backend { reason },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn encode_sa_encodes_at_sign_only() {
        assert_eq!(
            encode_sa("svc@proj.iam.gserviceaccount.com"),
            "svc%40proj.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn expire_time_parses_future() {
        let future = chrono::Utc::now() + chrono::Duration::seconds(3600);
        let ttl = expire_time_to_ttl(&future.to_rfc3339()).unwrap();
        assert!((3590..=3600).contains(&ttl), "{ttl}");
    }

    #[test]
    fn expire_time_past_clamps_to_one() {
        let past = chrono::Utc::now() - chrono::Duration::seconds(60);
        assert_eq!(expire_time_to_ttl(&past.to_rfc3339()).unwrap(), 1);
    }

    #[test]
    fn expire_time_malformed_is_backend_error() {
        assert!(matches!(
            expire_time_to_ttl("not-a-time"),
            Err(CredentialError::Backend { .. })
        ));
    }

    #[test]
    fn id_token_ttl_from_jwt_exp() {
        let exp = chrono::Utc::now().timestamp() + 3000;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"exp\":{exp}}}").as_bytes());
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig");
        let ttl = id_token_ttl(&token, 3300);
        assert!((2990..=3000).contains(&ttl), "{ttl}");
    }

    #[test]
    fn id_token_ttl_undecodable_uses_fallback() {
        assert_eq!(id_token_ttl("not.a.jwt", 1234), 1234);
        assert_eq!(id_token_ttl("only-one-segment", 999), 999);
    }

    #[test]
    fn error_mapping_by_status_enum() {
        let perm = map_gcp_error(
            StatusCode::FORBIDDEN,
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"x"}}"#,
        );
        assert!(matches!(perm, CredentialError::NotAuthorized { .. }));

        let exhausted = map_gcp_error(
            StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#,
        );
        assert!(matches!(exhausted, CredentialError::Throttled { .. }));

        let bad = map_gcp_error(
            StatusCode::BAD_REQUEST,
            r#"{"error":{"status":"INVALID_ARGUMENT"}}"#,
        );
        assert!(matches!(bad, CredentialError::Misconfigured { .. }));

        let nf = map_gcp_error(StatusCode::NOT_FOUND, r#"{"error":{"status":"NOT_FOUND"}}"#);
        assert!(matches!(nf, CredentialError::Misconfigured { .. }));

        let internal = map_gcp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":{"status":"INTERNAL"}}"#,
        );
        assert!(matches!(internal, CredentialError::Backend { .. }));
    }

    #[test]
    fn error_mapping_falls_back_to_http_code() {
        // No parseable body → classify on HTTP status only.
        assert!(matches!(
            map_gcp_error(StatusCode::UNAUTHORIZED, "<html>"),
            CredentialError::NotAuthorized { .. }
        ));
        assert!(matches!(
            map_gcp_error(StatusCode::SERVICE_UNAVAILABLE, ""),
            CredentialError::Backend { .. }
        ));
    }

    #[test]
    fn error_mapping_never_leaks_message() {
        let err = map_gcp_error(
            StatusCode::FORBIDDEN,
            r#"{"error":{"status":"PERMISSION_DENIED","message":"LEAKED_TOKEN_xyz789"}}"#,
        );
        let CredentialError::NotAuthorized { reason } = err else {
            panic!("expected NotAuthorized");
        };
        assert!(!reason.contains("LEAKED_TOKEN_xyz789"), "{reason}");
        assert!(reason.contains("PERMISSION_DENIED"));
    }
}

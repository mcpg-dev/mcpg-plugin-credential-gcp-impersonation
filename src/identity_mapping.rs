//! Identity → target service-account-email resolution for
//! `dev.mcpg.credential.gcp-impersonation`.

use mcpg_plugin_protocol::types::PluginIdentity;

use crate::config::{IdentityMapping, TargetConfig};

/// Resolution outcome. The error variants surface as
/// `CredentialError::NotAuthorized`.
#[derive(Debug)]
pub(crate) enum Resolution {
    /// Impersonate this SA email. `identity_derived` is true when the
    /// value came from caller-controlled identity (subject_id /
    /// first-role / template) rather than the operator's static
    /// `service_account`.
    Target {
        email: String,
        identity_derived: bool,
    },
    EmptyDerived {
        reason: String,
    },
    SubstitutionFailed {
        field: String,
    },
}

/// A service-account email is valid only if it is a non-empty lowercase
/// local-part `@` a host in the `*.gserviceaccount.com` family with no
/// path-breakout bytes. The email is interpolated into the IAM
/// Credentials `:generateAccessToken` URL path, so a `/`, `:`, `%`,
/// `?`, `#`, whitespace, or `..` would let a crafted identity steer the
/// call to a different endpoint or forge a second action. Stricter than
/// GCP but rejects nothing a real SA email contains.
pub(crate) fn is_valid_sa_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 320 {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // local-part: lowercase alnum + '-' (GCP SA name charset).
    if !local
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    // domain: lowercase alnum + '-' + '.', must be in the
    // gserviceaccount.com family, no path-breakout bytes.
    if !domain
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return false;
    }
    if domain.contains("..") {
        return false;
    }
    domain == "gserviceaccount.com" || domain.ends_with(".gserviceaccount.com")
}

/// A delegate is a bare SA email or a full
/// `projects/-/serviceAccounts/<email>` resource name.
pub(crate) fn is_valid_delegate(d: &str) -> bool {
    if let Some(email) = d.strip_prefix("projects/-/serviceAccounts/") {
        is_valid_sa_email(email)
    } else {
        is_valid_sa_email(d)
    }
}

/// Wrap a delegate (bare email or resource name) into the
/// `projects/-/serviceAccounts/<email>` resource form the API expects.
pub(crate) fn delegate_resource_name(d: &str) -> String {
    if d.starts_with("projects/-/serviceAccounts/") {
        d.to_owned()
    } else {
        format!("projects/-/serviceAccounts/{d}")
    }
}

pub(crate) fn resolve_target(identity: &PluginIdentity, target: &TargetConfig) -> Resolution {
    match target.identity_mapping {
        IdentityMapping::Static => Resolution::Target {
            email: target.service_account.clone(),
            identity_derived: false,
        },
        IdentityMapping::SubjectId => match identity.subject_id.as_deref() {
            Some(s) if !s.is_empty() => Resolution::Target {
                email: s.to_owned(),
                identity_derived: true,
            },
            _ if !target.service_account.is_empty() => Resolution::Target {
                email: target.service_account.clone(),
                identity_derived: false,
            },
            _ => Resolution::EmptyDerived {
                reason: "identity has no subject_id and no static fallback service_account".into(),
            },
        },
        IdentityMapping::FromRole => match identity.roles.first() {
            Some(r) if !r.is_empty() => Resolution::Target {
                email: r.clone(),
                identity_derived: true,
            },
            _ if !target.service_account.is_empty() => Resolution::Target {
                email: target.service_account.clone(),
                identity_derived: false,
            },
            _ => Resolution::EmptyDerived {
                reason: "identity has no roles and no static fallback service_account".into(),
            },
        },
        IdentityMapping::Template => {
            let template = target.service_account_template.as_deref().unwrap_or("");
            substitute(template, identity)
        }
    }
}

/// Substitute `${identity.<field>}` placeholders. Supported fields:
/// `subject_id`, `kind`, `trust_level`, `auth_provider`,
/// `roles[N]`, `groups[N]`, `scopes[N]`, `attributes.<key>`.
fn substitute(template: &str, identity: &PluginIdentity) -> Resolution {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut placeholder = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                placeholder.push(ch);
            }
            if !closed {
                return Resolution::SubstitutionFailed {
                    field: format!("unterminated placeholder `${{{placeholder}`"),
                };
            }
            let field = placeholder
                .strip_prefix("identity.")
                .unwrap_or(placeholder.as_str());
            match resolve_field(field, identity) {
                Some(s) if !s.is_empty() => out.push_str(&s),
                _ => {
                    return Resolution::SubstitutionFailed {
                        field: field.to_owned(),
                    };
                }
            }
        } else {
            out.push(c);
        }
    }
    if out.is_empty() {
        Resolution::EmptyDerived {
            reason: "template substitution produced an empty service-account email".into(),
        }
    } else {
        Resolution::Target {
            email: out,
            identity_derived: true,
        }
    }
}

fn resolve_field(field: &str, identity: &PluginIdentity) -> Option<String> {
    match field {
        "subject_id" => identity.subject_id.clone(),
        "kind" => Some(identity.kind.clone()),
        "trust_level" => Some(identity.trust_level.clone()),
        "auth_provider" => identity.auth_provider.clone(),
        f if f.starts_with("attributes.") => {
            let key = &f["attributes.".len()..];
            identity.attributes.get(key).cloned()
        }
        f if let Some(idx) = parse_indexed(f, "roles") => identity.roles.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "groups") => identity.groups.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "scopes") => identity.scopes.get(idx).cloned(),
        _ => None,
    }
}

fn parse_indexed(field: &str, name: &str) -> Option<usize> {
    let prefix = format!("{name}[");
    let rest = field.strip_prefix(&prefix)?;
    let inner = rest.strip_suffix(']')?;
    inner.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SA_A: &str = "team-a@my-proj.iam.gserviceaccount.com";
    const SA_B: &str = "team-b@my-proj.iam.gserviceaccount.com";

    fn ident(subject: Option<&str>) -> PluginIdentity {
        let mut attrs = BTreeMap::new();
        attrs.insert("team".into(), "team-a".into());
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: subject.map(str::to_owned),
            auth_provider: Some("okta".into()),
            issuer: Some("https://okta.example.com".into()),
            roles: vec![SA_A.into(), SA_B.into()],
            groups: vec!["sec".into()],
            scopes: vec![],
            attributes: attrs,
        }
    }

    fn target(mapping: IdentityMapping, sa: &str, template: Option<&str>) -> TargetConfig {
        TargetConfig {
            token_kind: crate::config::TokenKind::AccessToken,
            service_account: sa.into(),
            identity_mapping: mapping,
            service_account_template: template.map(str::to_owned),
            allowed_service_accounts: None,
            scopes: vec!["https://www.googleapis.com/auth/cloud-platform".into()],
            lifetime_seconds: None,
            allow_extended_lifetime: false,
            audience: None,
            include_email: true,
            id_token_assumed_ttl_seconds: 3300,
            delegates: vec![],
            max_cache_ttl_ms: 3_600_000,
        }
    }

    fn assert_target(r: &Resolution, want: &str, derived: bool) {
        match r {
            Resolution::Target {
                email,
                identity_derived,
            } => {
                assert_eq!(email, want);
                assert_eq!(*identity_derived, derived);
            }
            other => panic!("expected Target, got {other:?}"),
        }
    }

    #[test]
    fn sa_email_validation_accepts_real() {
        assert!(is_valid_sa_email(SA_A));
        assert!(is_valid_sa_email(
            "123456-compute@developer.gserviceaccount.com"
        ));
        assert!(is_valid_sa_email("my-proj@appspot.gserviceaccount.com"));
    }

    #[test]
    fn sa_email_validation_rejects_garbage_and_injection() {
        assert!(!is_valid_sa_email(""));
        assert!(!is_valid_sa_email("no-at"));
        assert!(!is_valid_sa_email("evil@example.com"));
        assert!(!is_valid_sa_email("@my-proj.iam.gserviceaccount.com"));
        assert!(!is_valid_sa_email("a@b@my-proj.iam.gserviceaccount.com"));
        assert!(!is_valid_sa_email("UPPER@my-proj.iam.gserviceaccount.com"));
        assert!(!is_valid_sa_email("a b@my-proj.iam.gserviceaccount.com"));
        // path-breakout attempts
        assert!(!is_valid_sa_email("svc/x@my-proj.iam.gserviceaccount.com"));
        assert!(!is_valid_sa_email(
            "svc@my-proj.iam.gserviceaccount.com:generateIdToken"
        ));
        assert!(!is_valid_sa_email(
            "../../x@my-proj.iam.gserviceaccount.com"
        ));
    }

    #[test]
    fn delegate_validation_and_wrapping() {
        assert!(is_valid_delegate(SA_A));
        assert!(is_valid_delegate(&format!(
            "projects/-/serviceAccounts/{SA_A}"
        )));
        assert!(!is_valid_delegate("bogus"));
        assert_eq!(
            delegate_resource_name(SA_A),
            format!("projects/-/serviceAccounts/{SA_A}")
        );
        assert_eq!(
            delegate_resource_name(&format!("projects/-/serviceAccounts/{SA_A}")),
            format!("projects/-/serviceAccounts/{SA_A}")
        );
    }

    #[test]
    fn static_returns_configured_not_derived() {
        let r = resolve_target(
            &ident(Some("x")),
            &target(IdentityMapping::Static, SA_A, None),
        );
        assert_target(&r, SA_A, false);
    }

    #[test]
    fn subject_id_returns_caller_derived() {
        let r = resolve_target(
            &ident(Some(SA_B)),
            &target(IdentityMapping::SubjectId, SA_A, None),
        );
        assert_target(&r, SA_B, true);
    }

    #[test]
    fn subject_id_falls_back_when_anonymous_not_derived() {
        let r = resolve_target(
            &ident(None),
            &target(IdentityMapping::SubjectId, SA_A, None),
        );
        assert_target(&r, SA_A, false);
    }

    #[test]
    fn subject_id_empty_derived_without_fallback() {
        let r = resolve_target(&ident(None), &target(IdentityMapping::SubjectId, "", None));
        assert!(matches!(r, Resolution::EmptyDerived { .. }));
    }

    #[test]
    fn from_role_returns_first_role_derived() {
        let r = resolve_target(
            &ident(Some("x")),
            &target(IdentityMapping::FromRole, SA_A, None),
        );
        assert_target(&r, SA_A, true);
    }

    #[test]
    fn template_substitutes_attribute_derived() {
        let r = resolve_target(
            &ident(Some("x")),
            &target(
                IdentityMapping::Template,
                "",
                Some("${identity.attributes.team}@my-proj.iam.gserviceaccount.com"),
            ),
        );
        assert_target(&r, SA_A, true);
    }

    #[test]
    fn template_substitution_failure_surfaces_field() {
        let r = resolve_target(
            &ident(None),
            &target(
                IdentityMapping::Template,
                "",
                Some("${identity.subject_id}@my-proj.iam.gserviceaccount.com"),
            ),
        );
        match r {
            Resolution::SubstitutionFailed { field } => assert_eq!(field, "subject_id"),
            other => panic!("{other:?}"),
        }
    }
}

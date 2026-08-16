# GCP Service-Account Impersonation (`dev.mcpg.credential.gcp-impersonation`)

A **credential_issuer** plugin that mints **short-lived GCP
credentials per caller request** via the [IAM Credentials REST API].
The gateway authenticates with its own base identity (GKE Workload
Identity / GCE metadata server, or an operator-supplied token) and
**impersonates** a target service account chosen by mapping the
caller's `PluginIdentity` — returning an OAuth2 access token
(`generateAccessToken`) or an OIDC ID token (`generateIdToken`).

Bindings consume the issued token through the `cred://` scheme,
authenticating to Google APIs as the per-caller-scoped service account
rather than as one shared identity.

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `base_auth` | object | `metadata_server` | How the gateway gets the Bearer token to *call* the IAM Credentials API (see below). |
| `iam_credentials_endpoint` | string | `https://iamcredentials.googleapis.com` | API host. `https://` (or `http://localhost` for tests). |
| `connect_timeout_ms` / `operation_timeout_ms` | int | `5000` / `15000` | HTTP timeouts. |
| `refresh_buffer_ms` | int | `60000` | Refresh the cached base token this long before its expiry. |
| `targets` | map | *(required, ≥1)* | Per-target mapping (below). |

### `base_auth`

- `{ "kind": "metadata_server", "endpoint"?, "service_account"? }` — GKE
  Workload Identity / GCE. Default; `endpoint` defaults to
  `http://metadata.google.internal`, `service_account` to `default`.
- `{ "kind": "static_access_token", "access_token": "ya29...." }` — an
  operator-supplied base Bearer (tests / simple setups).

(Service-account-key RS256 JWT-bearer auth is a planned follow-up.)

### Target

| Field | Type | Default | Description |
|---|---|---|---|
| `token_kind` | `access_token` \| `id_token` | `access_token` | What to mint. |
| `service_account` | string | `""` | Target SA email. Required + validated for `static`; the operator fallback otherwise. |
| `identity_mapping` | `static` \| `subject_id` \| `from_role` \| `template` | `static` | How the target SA is chosen. |
| `service_account_template` | string | *(none)* | Required for `template`; `${identity.<field>}` → an SA email. |
| `allowed_service_accounts` | array | *(none)* | Allowlist bounding identity-derived SAs. |
| `scopes` | array | `[]` | `access_token` only; required. |
| `lifetime_seconds` | int | *(GCP default 3600)* | `access_token` only; `1..=3600` (or `..=43200` with `allow_extended_lifetime`). |
| `audience` | string | *(none)* | `id_token` only; required. |
| `include_email` | bool | `true` | `id_token` only. |
| `delegates` | array | `[]` | Operator-fixed impersonation chain (SA emails / resource names). |
| `max_cache_ttl_ms` | int | `3600000` | Caps the host cache TTL; effective TTL is `min(token_expiry, this)`. |

### Identity mapping & security floor

`static` uses the operator-fixed SA. `subject_id` / `from_role` /
`template` derive the SA from the caller. **Any identity-derived target
SA is honoured only for a Verified principal** — header-asserted /
unauthenticated callers are refused (`NotAuthorized`). The resolved
value must be a well-formed `*.gserviceaccount.com` email (it is
interpolated into the API URL path) and, if `allowed_service_accounts`
is set, appear in it. Static / fallback SAs are operator-fixed and
exempt. `delegates` are operator-fixed and never identity-derived.

## Example

```yaml
# Top-level `plugins:` is a flat list of plugin entries.
plugins:
  - id: dev.mcpg.credential.gcp-impersonation
    class: credential_issuer
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/credential-gcp-impersonation:protocol-1" }
    config:
      # base_auth defaults to the GKE Workload Identity metadata server
      targets:
        bq-reader:
          service_account: "bq-reader@my-proj.iam.gserviceaccount.com"
          scopes: ["https://www.googleapis.com/auth/bigquery.readonly"]
        per-team:
          identity_mapping: template
          service_account_template: "mcpg-${identity.attributes.team}@my-proj.iam.gserviceaccount.com"
          allowed_service_accounts:
            - "mcpg-data@my-proj.iam.gserviceaccount.com"
          scopes: ["https://www.googleapis.com/auth/cloud-platform"]
```

Bindings consume the issued credential via
`cred://<plugin-alias>/<target>` in any config-origin position — the
first segment is the `plugins[].id` alias, so the entry above is reached
as:

```yaml
Authorization: "Bearer ${cred://dev.mcpg.credential.gcp-impersonation/bq-reader}"
```

Give the entry a shorter `id` and set `ref` to the manifest id when a
terser reference is wanted, or when one artifact runs under several
aliases.

## Issued credential

`value` + `parts.access_token` (or `parts.id_token`) hold the token;
`ttl_seconds` is the token's remaining lifetime capped at
`max_cache_ttl_ms`. `lease_id` is absent — GCP short-lived tokens
auto-expire; `revoke` is a no-op.

## Testing

Unit tests (`cargo test -p mcpg-plugin-credential-gcp-impersonation
--lib`) cover config validation, identity→SA mapping, the Verified /
SA-shape / allowlist guards, `expireTime`/JWT-`exp` → TTL, and error
mapping — all offline. The HTTP request/response contract (against the
IAM Credentials + metadata endpoints) is exercised offline with
[`wiremock`] in the same `--lib` run (no Docker). A **live GCP
integration** run against a real project is deferred to a later
orchestrated test pass.

## Notes

- Pure-Rust, rustls-only (`reqwest` `rustls-tls`, no SDK).
- `network_outbound` capability.
- The IAM Credentials / metadata hosts are config-origin (operator-
  fixed); only the *target* SA is identity-derived. Errors surface the
  Google error `status` enum only — never the `message` (which can echo
  submitted material).

[IAM Credentials REST API]: https://cloud.google.com/iam/docs/reference/credentials/rest
[`wiremock`]: https://docs.rs/wiremock

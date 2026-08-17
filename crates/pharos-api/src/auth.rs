//! Validator-namespace Bearer-token auth middleware.
//!
//! `validator_auth_layer(token)` returns a `tower::Layer` that, when a token is
//! configured (`Some`), requires `Authorization: Bearer <token>` on every request.
//! Missing header → 401; wrong token → 403.  When `None`, the layer is a no-op
//! pass-through.
//!
//! Applied ONLY on the `/eth/v1/validator/*` sub-router so it never blocks
//! non-validator reads (per `D-validator-auth-layer`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, header};
use axum::response::IntoResponse;
use subtle::ConstantTimeEq;
use tower::{Layer, Service};

use crate::error::ApiError;

// ── ValidatorAuthLayer ────────────────────────────────────────────────────────

/// Tower layer that optionally enforces Bearer-token authentication.
#[derive(Clone)]
pub struct ValidatorAuthLayer {
    token: Option<Arc<String>>,
}

impl<S> Layer<S> for ValidatorAuthLayer {
    type Service = ValidatorAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ValidatorAuthService {
            inner,
            token: self.token.clone(),
        }
    }
}

/// Build a `ValidatorAuthLayer`.
///
/// - `None`  → pass-through (default, no auth required).
/// - `Some(t)` → `Authorization: Bearer <t>` required; missing → 401, wrong → 403.
pub fn validator_auth_layer(token: Option<String>) -> ValidatorAuthLayer {
    ValidatorAuthLayer {
        token: token.map(Arc::new),
    }
}

// ── ValidatorAuthService ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ValidatorAuthService<S> {
    inner: S,
    token: Option<Arc<String>>,
}

impl<S> Service<Request<Body>> for ValidatorAuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let Some(ref expected) = self.token else {
            // No token configured → unconditional pass-through.
            return Box::pin(self.inner.call(req));
        };

        let auth_value = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let expected = Arc::clone(expected);
        match auth_value {
            None => {
                let resp = ApiError::Unauthorized("missing Authorization header".to_string())
                    .into_response();
                Box::pin(async move { Ok(resp) })
            }
            Some(hdr) => {
                let provided = hdr.strip_prefix("Bearer ").unwrap_or("").trim().to_string();
                // Constant-time compare so a LAN/localhost attacker cannot recover
                // the token byte-by-byte via response-timing (the `==` short-circuits
                // on first differing byte). Length still differs in timing, which is
                // acceptable for a fixed-length token.
                if provided.as_bytes().ct_eq(expected.as_bytes()).into() {
                    Box::pin(self.inner.call(req))
                } else {
                    let resp = ApiError::Forbidden("invalid token".to_string()).into_response();
                    Box::pin(async move { Ok(resp) })
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::{Router, routing::get};
    use tower::ServiceExt as _;

    use super::*;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn router_with_auth(token: Option<String>) -> Router {
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(validator_auth_layer(token))
    }

    #[tokio::test]
    async fn no_token_passes_without_header() {
        let app = router_with_auth(None);
        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_token_passes() {
        let app = router_with_auth(Some("secret123".to_string()));
        let req = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, "Bearer secret123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let app = router_with_auth(Some("secret123".to_string()));
        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_returns_403() {
        let app = router_with_auth(Some("secret123".to_string()));
        let req = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, "Bearer wrongtoken")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn non_bearer_scheme_returns_403() {
        let app = router_with_auth(Some("secret123".to_string()));
        let req = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
